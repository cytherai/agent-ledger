// Agent-neutral write observer. Records every change to a regular file under each ROOT: its SHA-256, its macOS
// provenance stamp (which app's processes wrote it, when that app is tracked) and an APFS clone of the version, kept
// as HOME/versions/<sha256>. At start it compares every file with the last version recorded in
// HOME/observations.jsonl, so changes made while it was stopped are recorded too ("startup").
// Git's reflogs (.git/logs/HEAD and .git/logs/refs/stash) are versioned as "vcs" records and .git/index changes are
// recorded as "vcs" markers (no content), so the reconciler can recognise git operations; nothing else under .git is
// tracked. When FSEvents reports dropped events (MustScanSubDirs), the subtree
// is rescanned ("rescan") and the gap is recorded ("gap").
// Files over 64 MB, and anything under .build, node_modules or __pycache__, are not tracked. HOME is owner-only (0700).
// One watcher per HOME: it holds an exclusive lock on HOME/watch.lock, and a second one exits at once. It watches the
// projects listed in HOME/roots (ROOT arguments are added there), and a project appended later joins without a gap:
// the stream restarts from the last event it saw. It exits after 30 minutes without agent claims (HOME/claims.jsonl);
// the agent's next hook starts it again, and the startup comparison covers the time in between.
// Usage: watch HOME [ROOT...]     Needs no root and no entitlement: FSEvents and clones are ordinary user APIs.
import Foundation
import CoreServices
import CryptoKit

/// The path as FSEvents reports it: symlinks resolved, /private kept (Foundation's standardizing would strip it).
func real(_ path: String) -> String { String(cString: realpath(path, nil)) }
let ownerOnly: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
try FileManager.default.createDirectory(atPath: CommandLine.arguments[1], withIntermediateDirectories: true, attributes: ownerOnly)
let home = URL(fileURLWithPath: real(CommandLine.arguments[1]))
try FileManager.default.setAttributes(ownerOnly, ofItemAtPath: home.path)
let lock = open(home.appendingPathComponent("watch.lock").path, O_CREAT | O_RDWR, 0o600)
guard lock >= 0, flock(lock, LOCK_EX | LOCK_NB) == 0 else { print("another watcher holds the lock"); exit(0) }
let rootsFile = home.appendingPathComponent("roots"), idleSeconds: TimeInterval = 30 * 60
func readRoots() -> [String] {  // registered projects that still exist, as FSEvents names them
    let listed = (try? String(contentsOf: rootsFile, encoding: .utf8))?.split(separator: "\n").map(String.init) ?? []
    return Array(Set(listed.filter { FileManager.default.fileExists(atPath: $0) }.map(real))).sorted()
}
let added = CommandLine.arguments.dropFirst(2).filter { FileManager.default.fileExists(atPath: $0) }.map(real).filter { !readRoots().contains($0) }
if !FileManager.default.fileExists(atPath: rootsFile.path) { FileManager.default.createFile(atPath: rootsFile.path, contents: nil) }
if !added.isEmpty { let f = try FileHandle(forWritingTo: rootsFile); f.seekToEndOfFile(); f.write(Data(added.map { $0 + "\n" }.joined().utf8)) }
var roots = readRoots()
guard !roots.isEmpty else { print("no projects registered in", rootsFile.path); exit(0) }
let versions = home.appendingPathComponent("versions"), log = home.appendingPathComponent("observations.jsonl")
let skipped: Set<String> = [".git", ".build", "node_modules", "__pycache__", ".DS_Store"]
let reflogs = ["logs/HEAD", "logs/refs/stash"]
let maxBytes: off_t = 64 << 20

try FileManager.default.createDirectory(at: versions, withIntermediateDirectories: true, attributes: ownerOnly)
if !FileManager.default.fileExists(atPath: log.path) { FileManager.default.createFile(atPath: log.path, contents: nil) }
var last: [String: String] = [:]  // path -> sha256 of its last recorded version ("" when deleted)
for line in (try String(contentsOf: log, encoding: .utf8)).split(separator: "\n") {
    let o = try JSONSerialization.jsonObject(with: Data(line.utf8)) as! [String: Any]
    if !["vcs", "gap"].contains(o["kind"] as! String) { last[o["path"] as! String] = o["sha256"] as? String ?? "" }
}
let out = try FileHandle(forWritingTo: log)
out.seekToEndOfFile()

func write(_ o: [String: Any]) {
    let stamped = o.merging(["schema": 1, "t_ms": Int(Date().timeIntervalSince1970 * 1000)]) { current, _ in current }
    out.write(try! JSONSerialization.data(withJSONObject: stamped, options: [.sortedKeys]) + Data("\n".utf8))
}

func provenance(_ path: String) -> String? {
    var buffer = [UInt8](repeating: 0, count: 64)
    let n = getxattr(path, "com.apple.provenance", &buffer, buffer.count, 0, 0)
    return n > 0 ? buffer[..<n].map { String(format: "%02x", $0) }.joined() : nil
}

/// Clones the file (an immutable copy-on-write snapshot), hashes the clone rather than the live file, and keeps it
/// under its hash. Nil when the file is gone or is no longer a regular file.
func snapshot(_ path: String) -> (sha: String, size: off_t, inode: UInt64)? {
    var st = stat()
    guard lstat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { return nil }
    let temp = versions.appendingPathComponent(".tmp-\(UUID().uuidString)")
    guard copyfile(path, temp.path, nil, copyfile_flags_t(COPYFILE_CLONE)) == 0, let data = FileManager.default.contents(atPath: temp.path) else {
        try? FileManager.default.removeItem(at: temp)
        return nil
    }
    let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    let kept = versions.appendingPathComponent(sha)
    if FileManager.default.fileExists(atPath: kept.path) { try? FileManager.default.removeItem(at: temp) } else { try! FileManager.default.moveItem(at: temp, to: kept) }
    return (sha, off_t(data.count), UInt64(st.st_ino))
}

func record(_ path: String, kind: String, flags: [String] = []) {
    let parts = path.split(separator: "/").map(String.init)
    var kind = kind
    if let git = parts.firstIndex(of: ".git") {  // inside a repository's .git: only its index and reflogs matter
        let inside = parts[(git + 1)...].joined(separator: "/")
        if inside == "index" { return write(["kind": "vcs", "path": path, "flags": flags]) }
        guard reflogs.contains(inside) else { return }
        kind = "vcs"
    } else if path.hasPrefix(home.path + "/") || parts.contains(where: { skipped.contains($0) }) {
        return
    }
    var st = stat()
    if lstat(path, &st) == 0, st.st_mode & S_IFMT != S_IFREG || st.st_size > maxBytes { return }  // not a tracked file
    let s = snapshot(path), sha = s?.sha ?? ""  // "" once it no longer exists
    guard sha != (last[path] ?? "") else { return }  // unchanged since the last record
    last[path] = sha
    var o: [String: Any] = ["kind": kind, "path": path, "flags": flags]
    if let s { o["sha256"] = s.sha; o["size"] = s.size; o["inode"] = s.inode }
    if let p = provenance(path) { o["provenance"] = p }
    write(o)
}

/// Records every tracked file under `root` that differs from its last recorded version.
func scan(_ root: String, kind: String) {
    guard let walker = FileManager.default.enumerator(atPath: root) else { return }  // gone, or not a directory
    while let relative = walker.nextObject() as? String {
        let name = (relative as NSString).lastPathComponent
        if name == ".git" { reflogs.forEach { record(root + "/" + relative + "/" + $0, kind: kind) } }
        if skipped.contains(name) { walker.skipDescendants(); continue }
        record(root + "/" + relative, kind: kind)
    }
}

for root in roots { scan(root, kind: "startup") }  // anything new or different since the last run
for (path, sha) in last where !sha.isEmpty && roots.contains(where: { path.hasPrefix($0 + "/") }) && !FileManager.default.fileExists(atPath: path) {
    record(path, kind: "startup")  // deleted while stopped
}

let names: [(Int, String)] = [(kFSEventStreamEventFlagItemCreated, "Created"), (kFSEventStreamEventFlagItemRemoved, "Removed"),
    (kFSEventStreamEventFlagItemRenamed, "Renamed"), (kFSEventStreamEventFlagItemModified, "Modified"),
    (kFSEventStreamEventFlagItemInodeMetaMod, "InodeMeta"), (kFSEventStreamEventFlagItemXattrMod, "Xattr"),
    (kFSEventStreamEventFlagItemCloned, "Cloned"), (kFSEventStreamEventFlagMustScanSubDirs, "MustScanSubDirs"),
    (kFSEventStreamEventFlagUserDropped, "UserDropped"), (kFSEventStreamEventFlagKernelDropped, "KernelDropped")]
let callback: FSEventStreamCallback = { _, _, count, paths, flags, _ in
    let items = Unmanaged<CFArray>.fromOpaque(paths).takeUnretainedValue() as! [[String: Any]]
    for i in 0..<count {
        let path = items[i][kFSEventStreamEventExtendedDataPathKey] as! String
        let named = names.filter { flags[i] & UInt32($0.0) != 0 }.map(\.1)
        if flags[i] & UInt32(kFSEventStreamEventFlagMustScanSubDirs) != 0 {  // events were dropped under this path
            write(["kind": "gap", "path": path, "flags": named])
            scan(path, kind: "rescan")
        } else if flags[i] & UInt32(kFSEventStreamEventFlagItemIsFile) != 0 {
            record(path, kind: "change", flags: named)
        }
    }
}
let queue = DispatchQueue(label: "agent-ledger.watch")  // every record is written from here, or from main before it starts
func start(since: FSEventStreamEventId) -> FSEventStreamRef {
    let s = FSEventStreamCreate(nil, callback, nil, roots as CFArray, since, 0.05,
        UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagUseExtendedData | kFSEventStreamCreateFlagNoDefer))!
    FSEventStreamSetDispatchQueue(s, queue)
    FSEventStreamStart(s)
    print("watching", roots.joined(separator: " "))
    fflush(stdout)
    return s
}
var stream = start(since: FSEventStreamEventId(kFSEventStreamEventIdSinceNow))

let rootsChanged = DispatchSource.makeFileSystemObjectSource(fileDescriptor: open(rootsFile.path, O_EVTONLY), eventMask: [.write, .extend], queue: queue)
rootsChanged.setEventHandler {  // a newly registered project: scan it, then restart the stream from the last event seen
    let current = readRoots()
    guard current != roots else { return }
    current.filter { !roots.contains($0) }.forEach { scan($0, kind: "startup") }
    let seen = FSEventStreamGetLatestEventId(stream)
    let since = seen == FSEventStreamEventId(kFSEventStreamEventIdSinceNow) ? FSEventsGetCurrentEventId() : seen
    FSEventStreamStop(stream); FSEventStreamInvalidate(stream); FSEventStreamRelease(stream)
    roots = current
    stream = start(since: since)
}
rootsChanged.resume()

let began = Date(), idle = DispatchSource.makeTimerSource(queue: queue)
idle.schedule(deadline: .now() + 60, repeating: 60)
idle.setEventHandler {
    let claims = home.appendingPathComponent("claims.jsonl").path
    let lastClaim = (try? FileManager.default.attributesOfItem(atPath: claims))?[.modificationDate] as? Date ?? began
    if Date().timeIntervalSince(max(lastClaim, began)) > idleSeconds { exit(0) }
}
idle.resume()
dispatchMain()
