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

struct DesktopRecoveryIntent: Codable {
    var schema=1
    var state: String
    var consent="EXPLICIT_NEW_STOP"
    let plan: String, recoveryOf: String, recoveryPlanSHA: String, sha: String
    let console: DesktopConsolePin?
    var operation: String?
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
        guard members.allSatisfy({ ["authorization.json","recovery.json","lifecycle.lock"].contains($0) }) else { throw CocoaError(.fileReadCorruptFile) }
        if members.contains("lifecycle.lock"), !secure(root+"/lifecycle.lock",directory:false,mode:0o600) { throw CocoaError(.fileReadNoPermission) }
        return true
    }
    // A lease-only private directory is not an authorization intent. Any error is
    // conservatively present; permission failures never mean absent.
    var present: Bool { do { return try load() != nil } catch { return true } }
    var recoveryPresent: Bool { do { return try loadRecovery() != nil } catch { return true } }
    // Reject duplicate/escaped/case-alias object keys before Foundation folds
    // them into a dictionary. Bound nesting independently of decoder behavior.
    static func uniqueJSONKeys(_ data: Data)->Bool {
        let bytes=Array(data); var i=0, objects=[Set<String>]()
        while i<bytes.count {
            if bytes[i]==123 { objects.append([]); if objects.count>16 { return false }; i += 1; continue }
            if bytes[i]==125 { guard !objects.isEmpty else { return false }; objects.removeLast(); i += 1; continue }
            if bytes[i] != 34 { i += 1; continue }
            let start=i; i += 1
            while i<bytes.count && bytes[i] != 34 { if bytes[i]==92 { i += 1 }; i += 1 }
            guard i<bytes.count else { return false }; i += 1
            var next=i
            while next<bytes.count && [UInt8(32),9,10,13].contains(bytes[next]) { next += 1 }
            if next<bytes.count && bytes[next]==58 {
                guard !objects.isEmpty,
                      let values=try? JSONSerialization.jsonObject(with:Data([91]+bytes[start..<i]+[93])) as? [String], let key=values.first,
                      objects[objects.count-1].insert(key.lowercased()).inserted else { return false }
            }
        }
        return objects.isEmpty
    }
    func loadRecovery() throws -> DesktopRecoveryIntent? {
        if try !validateRoot(create:false) { return nil }
        let path=root+"/recovery.json"
        var s=stat()
        if lstat(path,&s) != 0 { guard errno==ENOENT else { throw CocoaError(.fileReadNoPermission) }; return nil }
        let fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        guard fd>=0 else { throw CocoaError(.fileReadNoPermission) }; defer { close(fd) }
        var opened=stat(), final=stat()
        guard fstat(fd,&opened)==0, secure(path,directory:false,mode:0o600), opened.st_dev==s.st_dev, opened.st_ino==s.st_ino, opened.st_uid==uid, opened.st_mode & S_IFMT==S_IFREG, opened.st_mode & 0o777==0o600, opened.st_nlink==1, opened.st_size>0, opened.st_size<16384 else { throw CocoaError(.fileReadCorruptFile) }
        var bytes=[UInt8](repeating:0,count:Int(opened.st_size)+1)
        let count=Darwin.read(fd,&bytes,bytes.count)
        guard count==Int(opened.st_size), lstat(path,&final)==0, final.st_dev==opened.st_dev, final.st_ino==opened.st_ino else { throw CocoaError(.fileReadCorruptFile) }
        let data=Data(bytes.prefix(count))
        guard Self.uniqueJSONKeys(data) else { throw CocoaError(.fileReadCorruptFile) }
        let value=try JSONDecoder().decode(DesktopRecoveryIntent.self,from:data)
        guard let original=try JSONSerialization.jsonObject(with:data) as? NSDictionary,
              let canonical=try JSONSerialization.jsonObject(with:JSONEncoder().encode(value)) as? NSDictionary,
              original==canonical else { throw CocoaError(.fileReadCorruptFile) }
        guard value.schema==1, value.consent=="EXPLICIT_NEW_STOP", ["RECOVERY_ARMED","RECOVERY_UNKNOWN","AWAITING_HELPER","DONE"].contains(value.state), [value.plan,value.recoveryOf,value.recoveryPlanSHA,value.sha].allSatisfy(DesktopMigration.isToken), value.operation.map(DesktopMigration.isToken) ?? true, value.operation != value.recoveryOf, (["AWAITING_HELPER","DONE"].contains(value.state) ? value.operation != nil : value.operation==nil) else { throw CocoaError(.fileReadCorruptFile) }
        return value
    }
    func saveRecovery(_ value: DesktopRecoveryIntent) throws { try saveData(JSONEncoder().encode(value),leafName:"recovery.json") }
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
        try saveData(JSONEncoder().encode(value),leafName:"authorization.json")
    }
    private func saveData(_ data: Data, leafName: String) throws {
        _=try validateRoot(create:true)
        // Verify home/ancestors are physical and not group/world writable.
        var path=""
        for part in root.split(separator:"/").dropLast() {
            path += "/"+part; var s=stat()
            guard lstat(path,&s)==0, s.st_mode & S_IFMT == S_IFDIR, s.st_mode & 0o022==0, s.st_uid==0 || s.st_uid==uid else { throw CocoaError(.fileWriteNoPermission) }
        }
        if mkdir(root,0o700) != 0 && errno != EEXIST { throw CocoaError(.fileWriteNoPermission) }
        guard secure(root,directory:true,mode:0o700) else { throw CocoaError(.fileWriteNoPermission) }
        let leaf=root+"/"+leafName
        var st=stat()
        if lstat(leaf,&st)==0 && !secure(leaf,directory:false,mode:0o600) { throw CocoaError(.fileWriteNoPermission) }
        let temp=root+"/.intent-"+UUID().uuidString
        let fd=open(temp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0o600)
        guard fd>=0 else { throw CocoaError(.fileWriteNoPermission) }
        defer { close(fd); unlink(temp) }
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
    var recovery_of: String? = nil, recovery_plan_sha256: String? = nil
    static func isToken(_ s: String)->Bool { s.utf8.count==64 && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    func valid(home: String, uid: Int, sha: String)->Bool {
        guard schema==1, self.home==home, self.uid==uid, binary==home+"/.anytls/anytls-macos", config==home+"/.anytls/config.yaml", config_identity==DesktopRuntime.sum(Data(config.utf8)), binary_sha256==sha, Self.isToken(plan), Self.isToken(old_binary_sha256), Self.isToken(helper_sha256), !helper_version.isEmpty else { return false }
        if phase=="INSPECTED" { return operation==nil && stage==nil }
        guard ["AWAITING_HELPER","COMMITTED"].contains(phase), let op=operation, Self.isToken(op) else { return false }
        return stage==home+"/.anytls/.desktop-candidate-"+op
    }
    static func parse(_ result: DesktopCommandResult)->DesktopMigration? {
        guard !result.timedOut, result.data.count<=65536, DesktopIntentStore.uniqueJSONKeys(result.data) else { return nil }
        if result.code==0 { return try? JSONDecoder().decode(Self.self,from:result.data) }
        guard let object=try? JSONSerialization.jsonObject(with:result.data) as? [String:Any], let nested=object["migration"], let data=try? JSONSerialization.data(withJSONObject:nested) else { return nil }
        return try? JSONDecoder().decode(Self.self,from:data)
    }
}

// Distinct flat closed schema: recovery never weakens DesktopMigration.valid.
struct DesktopRecoveryPreview: Decodable {
    let schema: Int, phase: String, plan: String
    let binary: String, config: String, config_identity: String, binary_sha256: String, old_binary_sha256: String
    let helper_sha256: String, helper_version: String, uid: Int, home: String, was_running: Bool
    let recovery_of: String, recovery_plan_sha256: String
    func valid(home: String, uid: Int, sha: String)->Bool {
        schema==1 && phase=="RECOVERY_INSPECTED" && self.home==home && self.uid==uid && uid>0 && binary==home+"/.anytls/anytls-macos" && config==home+"/.anytls/config.yaml" && config_identity==DesktopRuntime.sum(Data(config.utf8)) && binary_sha256==sha && [plan,binary_sha256,old_binary_sha256,helper_sha256,recovery_of,recovery_plan_sha256].allSatisfy(DesktopMigration.isToken) && !helper_version.isEmpty && helper_version.utf8.count<=128
    }
    static func parse(_ result: DesktopCommandResult)->Self? {
        let keys:Set<String>=["schema","phase","plan","binary","config","config_identity","binary_sha256","old_binary_sha256","helper_sha256","helper_version","uid","home","was_running","recovery_of","recovery_plan_sha256"]
        guard result.code==0, !result.timedOut, result.data.count<=16384,
              let object=try? JSONSerialization.jsonObject(with:result.data) as? [String:Any], Set(object.keys)==keys else { return nil }
        guard DesktopIntentStore.uniqueJSONKeys(result.data) else { return nil }
        return try? JSONDecoder().decode(Self.self,from:result.data)
    }
}
