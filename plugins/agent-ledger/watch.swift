// Agent-neutral write observer. Records every change to a regular file under each ROOT: its SHA-256, its macOS
// provenance stamp (which app's processes wrote it, when that app is tracked) and an APFS clone of the version, kept
// as HOME/versions/<sha256>. At start it compares every file with the last version recorded in
// HOME/observations.jsonl, so changes made while it was stopped are recorded too ("startup").
// Git's reflogs (.git/logs/HEAD and .git/logs/refs/stash) are versioned as "vcs" records and .git/index changes are
// recorded as "vcs" markers (no content), so the reconciler can recognise git operations; nothing else under .git is
// tracked. When FSEvents reports dropped events (MustScanSubDirs), the subtree
// is rescanned ("rescan") and the gap is recorded ("gap").
// Once a minute, and after the startup comparison, it sweeps each project: it compares every file whose ctime moved
// since it was last hashed with its last recorded version, and records what the event stream missed ("checkpoint").
// Then it records a "heartbeat" for the project saying whether the folder could be read. An unreadable folder is
// not swept, so a folder the watcher cannot see never looks like files were deleted. A sweep leaves a change younger
// than the event stream's delay to the stream. A check asks for a sweep of one project through HOME/requests and gets
// a "sweep" record once it is complete (see answer()).
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
var hashedAt: [String: timespec] = [:]  // path -> its ctime when last hashed
var unreadable = Set<String>()  // tracked files that exist but could not be read
let grace: TimeInterval = 2  // longer than the event stream takes to report a change (0.6 s at most, measured under load)
for line in (try String(contentsOf: log, encoding: .utf8)).split(separator: "\n") {
    let o = try JSONSerialization.jsonObject(with: Data(line.utf8)) as! [String: Any]
    if !["vcs", "gap", "heartbeat", "sweep"].contains(o["kind"] as! String) { last[o["path"] as! String] = o["sha256"] as? String ?? "" }
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
    if lstat(path, &st) == 0 {
        if st.st_mode & S_IFMT != S_IFREG || st.st_size > maxBytes { return }  // not a tracked file
        if kind == "checkpoint" {  // a sweep records only what the event stream missed
            // it hashes only what changed since it was last hashed: every write moves ctime, and nothing sets it back
            if let t = hashedAt[path], t.tv_sec == st.st_ctimespec.tv_sec, t.tv_nsec == st.st_ctimespec.tv_nsec { return }
            // and leaves a change too recent for the stream to have reported yet, or an agent's write reads as unseen
            if Date().timeIntervalSince1970 - (Double(st.st_ctimespec.tv_sec) + Double(st.st_ctimespec.tv_nsec) / 1e9) < grace { return }
        }
        hashedAt[path] = st.st_ctimespec
    } else if errno != ENOENT {
        return  // it can't be looked at, which is not evidence that it is gone
    }
    let s = snapshot(path)
    if s == nil, lstat(path, &st) == 0 { unreadable.insert(path); return }  // there but unreadable: neither a deletion nor a change
    unreadable.remove(path)
    let sha = s?.sha ?? ""  // "" once it no longer exists
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

/// Compares every tracked file under `dir` with its last record, deletions included. A sweep leaves a deletion whose
/// folder changed within `grace` to the event stream, as it does a recent change; `stable` then says it is pending.
func compare(_ dir: String, kind: String) {
    scan(dir, kind: kind)
    for (path, sha) in last where !sha.isEmpty && path.hasPrefix(dir + "/") && !FileManager.default.fileExists(atPath: path) {
        var st = stat()
        if kind == "checkpoint", lstat((path as NSString).deletingLastPathComponent, &st) == 0,
           Date().timeIntervalSince1970 - Double(st.st_mtimespec.tv_sec) < grace { continue }
        record(path, kind: kind)  // deleted unseen
    }
}

/// Whether every tracked file under `dir` still has the ctime it had when last hashed, with none added or gone: then
/// nothing changed after the sweep read it.
func stable(_ dir: String) -> Bool {
    guard let walker = FileManager.default.enumerator(atPath: dir) else { return false }
    var present = Set<String>()
    while let relative = walker.nextObject() as? String {
        if skipped.contains((relative as NSString).lastPathComponent) { walker.skipDescendants(); continue }
        let path = dir + "/" + relative
        var st = stat()
        guard !path.hasPrefix(home.path + "/"), lstat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_size <= maxBytes else { continue }
        guard let t = hashedAt[path], t.tv_sec == st.st_ctimespec.tv_sec, t.tv_nsec == st.st_ctimespec.tv_nsec else { return false }
        present.insert(path)
    }
    return !last.contains { path, sha in !sha.isEmpty && path.hasPrefix(dir + "/") && !path.contains("/.git/") && !present.contains(path) }
}

/// Compares each readable project with its last records, deletions included, then records a heartbeat per project.
func sweep(kind: String) {
    for root in roots {
        let readable = (try? FileManager.default.contentsOfDirectory(atPath: root)) != nil
        if readable { compare(root, kind: kind) }
        write(["kind": "heartbeat", "path": root, "readable": readable])
    }
}
sweep(kind: "startup")  // anything new, different or gone since the last run

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
    sweep(kind: "checkpoint")
    let claims = home.appendingPathComponent("claims.jsonl").path
    let lastClaim = (try? FileManager.default.attributesOfItem(atPath: claims))?[.modificationDate] as? Date ?? began
    if Date().timeIntervalSince(max(lastClaim, began)) > idleSeconds { exit(0) }
}

let requests = home.appendingPathComponent("requests")
try FileManager.default.createDirectory(at: requests, withIntermediateDirectories: true, attributes: ownerOnly)
var answered = 0  // the checkpoint sequence
/// Runs `work` once on the watcher's queue after `delay`, through a dispatch source like every other handler here.
func later(_ delay: TimeInterval, _ work: @escaping () -> Void) {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + delay)
    timer.setEventHandler { timer.cancel(); work() }
    timer.resume()
}
/// Answers each pending request, HOME/requests/<id>.json holding {"id", "path"}, with a "sweep" record written only
/// once its sweep is complete. "settled": every tracked file under the path matched its last record, and none changed
/// while it was compared. Otherwise "unwatched" (not a canonical path inside a watched project), "unreadable",
/// "unreadable-files", or "unsettled" (changes still pending after three tries).
func answer() {
    for name in ((try? FileManager.default.contentsOfDirectory(atPath: requests.path)) ?? []) where name.hasSuffix(".json") {
        let file = requests.appendingPathComponent(name)
        let request = (try? Data(contentsOf: file)).flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
        try? FileManager.default.removeItem(at: file)
        guard let id = request?["id"] as? String, let path = request?["path"] as? String else { continue }
        answered += 1
        check(id, path, sequence: answered, attempt: 1)
    }
}
func check(_ id: String, _ path: String, sequence: Int, attempt: Int) {
    let canonical = realpath(path, nil).map { p -> String in defer { free(p) }; return String(cString: p) }
    var status = "settled"
    if canonical != path || !roots.contains(where: { path == $0 || path.hasPrefix($0 + "/") }) {
        status = "unwatched"
    } else if (try? FileManager.default.contentsOfDirectory(atPath: path)) == nil {
        status = "unreadable"
    } else {
        compare(path, kind: "checkpoint")
        if !stable(path) {  // a change it left to the stream, or one during the sweep: sweep again once the stream has caught up
            if attempt < 3 { return later(grace) { check(id, path, sequence: sequence, attempt: attempt + 1) } }
            status = "unsettled"
        } else if unreadable.contains(where: { $0.hasPrefix(path + "/") }) {
            status = "unreadable-files"
        }
    }
    write(["kind": "sweep", "path": path, "request": id, "sequence": sequence, "status": status])
}
let requested = DispatchSource.makeFileSystemObjectSource(fileDescriptor: open(requests.path, O_EVTONLY), eventMask: .write, queue: queue)
requested.setEventHandler(handler: answer)
requested.resume()
later(0, answer)  // requests made before this watcher started
idle.resume()
dispatchMain()
