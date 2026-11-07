import Foundation
import Darwin

@_silgen_name("proc_pidpath") private func desktopProcPath(_ pid: Int32, _ buffer: UnsafeMutableRawPointer, _ size: UInt32) -> Int32
@_silgen_name("proc_pidinfo") private func desktopProcInfo(_ pid: Int32, _ flavor: Int32, _ arg: UInt64, _ buffer: UnsafeMutableRawPointer, _ size: Int32) -> Int32

struct DesktopConsolePin: Codable, Equatable {
    let pid: Int32, uid: UInt32, seconds: UInt64, micros: UInt64
    let argv: [String]
    let sha: String
    let managed: Bool
    static func observe(_ pid: Int32, sha: String, managed: Bool) -> DesktopConsolePin? {
        guard pid>1 else { return nil }
        var b=[UInt8](repeating:0,count:136)
        guard desktopProcInfo(pid,3,0,&b,136)==136 else { return nil }
        func word<T: FixedWidthInteger>(_ offset: Int, _: T.Type)->T { b.withUnsafeBytes { $0.loadUnaligned(fromByteOffset:offset,as:T.self) } }
        guard word(12,UInt32.self)==UInt32(pid) else { return nil }
        var mib:[Int32]=[CTL_KERN,KERN_PROCARGS2,pid], size=0
        guard sysctl(&mib,3,nil,&size,nil,0)==0, size>4, size<1048576 else { return nil }
        var args=[UInt8](repeating:0,count:size)
        guard sysctl(&mib,3,&args,&size,nil,0)==0 else { return nil }
        let count=args.withUnsafeBytes { $0.loadUnaligned(as:Int32.self) }
        guard count>0, count<128 else { return nil }
        var i=4
        while i<size && args[i] != 0 { i += 1 }
        while i<size && args[i]==0 { i += 1 }
        var argv=[String]()
        for _ in 0..<count {
            let start=i
            while i<size && args[i] != 0 { i += 1 }
            guard i<size, let value=String(bytes:args[start..<i],encoding:.utf8) else { return nil }
            argv.append(value); i += 1
        }
        var executable=[UInt8](repeating:0,count:4096)
        guard desktopProcPath(pid,&executable,4096)>0, String(cString:executable)==argv.first else { return nil }
        return DesktopConsolePin(pid:pid,uid:word(20,UInt32.self),seconds:word(120,UInt64.self),micros:word(128,UInt64.self),argv:argv,sha:sha,managed:managed)
    }
    func stillMatches()->Bool { Self.observe(pid,sha:sha,managed:managed)==self }
    func terminateIfMatching()->Bool { stillMatches() && kill(pid,SIGTERM)==0 }
}

struct DesktopAuthorizationIntent: Codable {
    var schema=1
    var operation: String, stage: String, sha: String, state: String
    var resume: Bool
    var console: DesktopConsolePin?
}

// Separate application-owned journal. Never consume a caller environment path or
// Go journal as authorization authority. UNKNOWN deliberately has no retry path.
final class DesktopIntentStore {
    let root: String, uid: uid_t
    init(home: String, fixtureRoot: String? = nil) {
        root=fixtureRoot ?? home+"/.anytls-desktop-state"; uid=getuid()
    }
    private func secure(_ path: String, directory: Bool, mode: mode_t)->Bool {
        var s=stat()
        return lstat(path,&s)==0 && s.st_uid==uid && s.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG) && s.st_mode & 0o777 == mode && (directory || s.st_nlink==1)
    }
    private func validateRoot(create: Bool) throws -> Bool {
        var path=""
        for part in root.split(separator:"/").dropLast() {
            path += "/"+part; var s=stat()
            guard lstat(path,&s)==0, s.st_mode & S_IFMT == S_IFDIR, s.st_mode & 0o022==0, s.st_uid==0 || s.st_uid==uid else { throw CocoaError(.fileReadNoPermission) }
        }
        var s=stat()
        if lstat(root,&s) != 0 {
            guard errno==ENOENT else { throw CocoaError(.fileReadNoPermission) }
            if !create { return false }
            guard mkdir(root,0o700)==0 || errno==EEXIST else { throw CocoaError(.fileWriteNoPermission) }
        }
        guard URL(fileURLWithPath:root).resolvingSymlinksInPath().path==root, secure(root,directory:true,mode:0o700) else { throw CocoaError(.fileReadNoPermission) }
        let members=try FileManager.default.contentsOfDirectory(atPath:root)
        guard members.allSatisfy({ ["authorization.json","lifecycle.lock"].contains($0) }) else { throw CocoaError(.fileReadCorruptFile) }
        if members.contains("lifecycle.lock"), !secure(root+"/lifecycle.lock",directory:false,mode:0o600) { throw CocoaError(.fileReadNoPermission) }
        return true
    }
    // A lease-only private directory is not an authorization intent. Any error is
    // conservatively present; permission failures never mean absent.
    var present: Bool { do { return try load() != nil } catch { return true } }
    func acquireLease() throws -> Int32 {
        _=try validateRoot(create:true)
        let path=root+"/lifecycle.lock"
        let fd=open(path,O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0o600)
        guard fd>=0 else { throw CocoaError(.fileWriteNoPermission) }
        var held=false
        defer { if !held { close(fd) } }
        var a=stat(), b=stat()
        guard fstat(fd,&a)==0, lstat(path,&b)==0, a.st_dev==b.st_dev, a.st_ino==b.st_ino,
              a.st_uid==uid, a.st_mode & S_IFMT == S_IFREG, a.st_mode & 0o777==0o600, a.st_nlink==1,
              flock(fd,LOCK_EX|LOCK_NB)==0 else { throw CocoaError(.fileLocking) }
        held=true; return fd
    }
    static func releaseLease(_ fd: Int32) { _=flock(fd,LOCK_UN); close(fd) }
    func load() throws -> DesktopAuthorizationIntent? {
        if try !validateRoot(create:false) { return nil }
        var st=stat()
        if lstat(root+"/authorization.json",&st) != 0 {
            guard errno==ENOENT else { throw CocoaError(.fileReadNoPermission) }; return nil
        }
        guard secure(root+"/authorization.json",directory:false,mode:0o600) else { throw CocoaError(.fileReadNoPermission) }
        let d=try Data(contentsOf:URL(fileURLWithPath:root+"/authorization.json"))
        guard d.count<16384 else { throw CocoaError(.fileReadCorruptFile) }
        let value=try JSONDecoder().decode(DesktopAuthorizationIntent.self,from:d)
        guard value.schema==1, ["ARMED","DENIED","UNKNOWN","READY","DONE","ACTIVATION_UNKNOWN","DRAINING"].contains(value.state), DesktopMigration.isToken(value.operation), DesktopMigration.isToken(value.sha) else { throw CocoaError(.fileReadCorruptFile) }
        return value
    }
    func save(_ value: DesktopAuthorizationIntent) throws {
        _=try validateRoot(create:true)
        // Verify home/ancestors are physical and not group/world writable.
        var path=""
        for part in root.split(separator:"/").dropLast() {
            path += "/"+part; var s=stat()
            guard lstat(path,&s)==0, s.st_mode & S_IFMT == S_IFDIR, s.st_mode & 0o022==0, s.st_uid==0 || s.st_uid==uid else { throw CocoaError(.fileWriteNoPermission) }
        }
        if mkdir(root,0o700) != 0 && errno != EEXIST { throw CocoaError(.fileWriteNoPermission) }
        guard secure(root,directory:true,mode:0o700) else { throw CocoaError(.fileWriteNoPermission) }
        let leaf=root+"/authorization.json"
        var st=stat()
        if lstat(leaf,&st)==0 && !secure(leaf,directory:false,mode:0o600) { throw CocoaError(.fileWriteNoPermission) }
        let temp=root+"/.intent-"+UUID().uuidString
        let fd=open(temp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0o600)
        guard fd>=0 else { throw CocoaError(.fileWriteNoPermission) }
        defer { close(fd); unlink(temp) }
        let data=try JSONEncoder().encode(value)
        let wrote=data.withUnsafeBytes { Darwin.write(fd,$0.baseAddress,data.count) }
        guard wrote==data.count, fsync(fd)==0, rename(temp,leaf)==0 else { throw CocoaError(.fileWriteUnknown) }
        let dir=open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW); guard dir>=0 else { throw CocoaError(.fileWriteUnknown) }; defer { close(dir) }
        guard fsync(dir)==0 else { throw CocoaError(.fileWriteUnknown) }
    }
}

struct DesktopMigration: Decodable {
    let schema: Int, phase: String, plan: String, operation: String?
    let binary: String, config: String, config_identity: String, binary_sha256: String, old_binary_sha256: String
    let helper_sha256: String, helper_version: String, stage: String?, uid: Int, home: String, was_running: Bool
    static func isToken(_ s: String)->Bool { s.utf8.count==64 && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    func valid(home: String, uid: Int, sha: String)->Bool {
        guard schema==1, self.home==home, self.uid==uid, binary==home+"/.anytls/anytls-macos", config==home+"/.anytls/config.yaml", config_identity==DesktopRuntime.sum(Data(config.utf8)), binary_sha256==sha, Self.isToken(plan), Self.isToken(old_binary_sha256), Self.isToken(helper_sha256), !helper_version.isEmpty else { return false }
        if phase=="INSPECTED" { return operation==nil && stage==nil }
        guard ["AWAITING_HELPER","COMMITTED"].contains(phase), let op=operation, Self.isToken(op) else { return false }
        return stage==home+"/.anytls/.desktop-candidate-"+op
    }
    static func parse(_ result: DesktopCommandResult)->DesktopMigration? {
        guard !result.timedOut, result.data.count<=65536 else { return nil }
        if result.code==0 { return try? JSONDecoder().decode(Self.self,from:result.data) }
        guard let object=try? JSONSerialization.jsonObject(with:result.data) as? [String:Any], let nested=object["migration"], let data=try? JSONSerialization.data(withJSONObject:nested) else { return nil }
        return try? JSONDecoder().decode(Self.self,from:data)
    }
}
