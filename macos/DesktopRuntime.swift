import Foundation
import CryptoKit
import Darwin

struct DesktopCommandResult {
    let code: Int32
    let data: Data
    let timedOut: Bool
    var stderr: Data = Data()
}
// Commands execute off main. Both pipes drain concurrently with hard read caps;
// no Process.waitUntilExit on the UI queue and no wait-before-drain deadlock.
final class DesktopProcessRunner {
    static func run(_ path: String, _ args: [String], _ deadline: Double, _ done: @escaping (DesktopCommandResult) -> Void) {
        DispatchQueue.global(qos:.userInitiated).async {
            let p=Process(), out=Pipe(), err=Pipe()
            p.executableURL=URL(fileURLWithPath:path); p.arguments=args
            p.standardInput=FileHandle.nullDevice; p.standardOutput=out; p.standardError=err
            do { try p.run() } catch {
                DispatchQueue.main.async { done(DesktopCommandResult(code:-1,data:Data(),timedOut:false)) }; return
            }
            // Nonblocking reads avoid immortal reader threads when a descendant
            // retains a pipe after its direct parent exits.
            let handles=[out.fileHandleForReading,err.fileHandleForReading]
            for h in handles { _=fcntl(h.fileDescriptor,F_SETFL,O_NONBLOCK) }
            var captures=[Data(),Data()], eof=[false,false], capped=false
            let end=Date().addingTimeInterval(deadline)
            var timedOut=false, exitedAt: Date?
            while true {
                for i in 0..<2 where !eof[i] {
                    var chunk=[UInt8](repeating:0,count:4096)
                    let n=Darwin.read(handles[i].fileDescriptor,&chunk,chunk.count)
                    if n==0 { eof[i]=true }
                    if n>0 {
                        if captures[i].count+n<=65536 { captures[i].append(contentsOf:chunk.prefix(n)) }
                        else { capped=true }
                    }
                }
                if !p.isRunning && exitedAt==nil { exitedAt=Date() }
                if let exit=exitedAt, eof.allSatisfy({$0}) || Date().timeIntervalSince(exit)>1 { if !eof.allSatisfy({$0}) { timedOut=true }; break }
                if Date()>=end { timedOut=true; break }
                Thread.sleep(forTimeInterval:0.001)
            }
            if p.isRunning { p.terminate(); Thread.sleep(forTimeInterval:0.05); if p.isRunning { kill(p.processIdentifier,SIGKILL) } }
            for h in handles { try? h.close() }
            let code: Int32 = timedOut || capped || p.isRunning ? -1 : p.terminationStatus
            DispatchQueue.main.async { done(DesktopCommandResult(code:code,data:captures[0],timedOut:timedOut,stderr:captures[1])) }
        }
    }
}

struct DesktopMetadata: Decodable {
    let schema: Int, version: String, binary: String, config: String, config_identity: String
    let binary_sha256: String, endpoint: String, listen: String, port: Int, uid: Int, home: String
    let helper_state: String
}

final class DesktopRuntime {
    typealias Runner = (String,[String],Double,@escaping (DesktopCommandResult)->Void)->Void
    let home: String, uid: Int, bundle: String
    let run: Runner
    let exists: (String)->Bool
    let digest: (String)->String?
    let portFree: ()->Bool
    let candidateSafe: (String)->Bool
    private(set) var busy=false
    private(set) var message="尚未初始化；请点「安装／更新组件…」"
    private(set) var console: Process?
    private var expectedSHA="", expectedVersion=""
    private var authAttempted=false
    private var setupUncertain=false
    let intents: DesktopIntentStore
    private var adopted: DesktopConsolePin?
    var consentMigration: ((Bool)->Bool?)?
    var onMigrationResume: (()->Void)?
    var blocksQuit: Bool { busy || setupUncertain || ((try? intents.load()).map { $0.state != "DONE" } ?? intents.present) }
    private var activationArmed=false
    private var lifecycleLease: Int32?
    deinit { endLifecycle() }
    private func beginLifecycle()->Bool {
        guard lifecycleLease==nil else { return false }
        do { lifecycleLease=try intents.acquireLease(); return true }
        catch { status("另一 App 正在处理组件，或私有状态不安全；未执行任何变更"); return false }
    }
    private func endLifecycle() {
        if let fd=lifecycleLease { lifecycleLease=nil; DesktopIntentStore.releaseLease(fd) }
    }
    func reserveQuitLifecycle()->Bool { beginLifecycle() }
    func finishQuitLifecycle() { endLifecycle() }
    func beginMigrationActivation()->Bool {
        guard beginLifecycle() else { return false }
        guard var intent=try? intents.load(), intent.state=="DONE" else { endLifecycle(); return false }
        intent.state="ACTIVATION_UNKNOWN"; intent.resume=false
        do { try intents.save(intent); activationArmed=true; status("组件已更新；恢复 VPN 的结果待确认，不会自动重试"); return true } catch { fail("无法持久保存恢复意图；未启动 VPN"); return false }
    }
    func observeMigrationActivation(running: Bool, pending: Bool, uncertain: Bool) {
        if activationArmed && !pending && uncertain { activationArmed=false; endLifecycle(); return }
        guard activationArmed, running, !pending, !uncertain, var intent=try? intents.load() else { return }
        intent.state="DONE"; do { try intents.save(intent); activationArmed=false; endLifecycle(); status("组件已更新；VPN 已确认恢复") } catch { status("VPN 恢复记录无法同步；保持锁定") }
    }
    var authorizationRetryAllowed: Bool { !busy && (try? intents.load())?.state == "DENIED" }
    var onChange: (()->Void)?
    // Fixture injection returns a real privately owned child, never a fake Process.
    var launchConsole: (() throws -> Process)?
    var drainTimeout: Double = 8
    var binary: String { home+"/.anytls/anytls-macos" }
    var config: String { home+"/.anytls/config.yaml" }
    var source: String { bundle+"/Contents/Resources/runtime/anytls-macos" }
    init(bundle: String = Bundle.main.bundlePath, home: String = String(cString:getpwuid(getuid())!.pointee.pw_dir), uid: Int = Int(getuid()), run: @escaping Runner = DesktopProcessRunner.run, exists: @escaping (String)->Bool = { FileManager.default.fileExists(atPath:$0) }, digest: @escaping (String)->String? = DesktopRuntime.fileSHA, portFree: @escaping ()->Bool = DesktopRuntime.availablePort, fixtureStateRoot: String? = nil, candidateSafe: ((String)->Bool)? = nil) {
        self.bundle=bundle; self.home=home; self.uid=uid; self.run=run; self.exists=exists; self.digest=digest; self.portFree=portFree
        self.intents=DesktopIntentStore(home:home,fixtureRoot:fixtureStateRoot)
        self.candidateSafe=candidateSafe ?? { DesktopRuntime.safeCandidate($0,home:home,uid:uid) }
    }
    static func sum(_ data: Data)->String { SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() }
    static func fileSHA(_ path: String)->String? {
        guard let f=FileHandle(forReadingAtPath:path) else { return nil }; defer { try? f.close() }
        var h=SHA256()
        while let d=try? f.read(upToCount:65536), !d.isEmpty { h.update(data:d) }
        return h.finalize().map { String(format:"%02x",$0) }.joined()
    }
    static func safeCandidate(_ path: String, home: String, uid: Int)->Bool {
        guard path.hasPrefix(home+"/.anytls/"), URL(fileURLWithPath:home).resolvingSymlinksInPath().path==home else { return false }
        var root=stat(), leaf=stat()
        return lstat(home+"/.anytls",&root)==0 && root.st_uid==uid_t(uid) && root.st_mode & S_IFMT == S_IFDIR && root.st_mode & 0o777==0o700 && lstat(path,&leaf)==0 && leaf.st_uid==uid_t(uid) && leaf.st_mode & S_IFMT == S_IFREG && leaf.st_nlink==1 && [mode_t(0o700),mode_t(0o755)].contains(leaf.st_mode & 0o777)
    }
    static func availablePort()->Bool {
        let fd=socket(AF_INET,SOCK_STREAM,0); guard fd>=0 else { return false }; defer { close(fd) }
        var a=sockaddr_in(); a.sin_len=UInt8(MemoryLayout<sockaddr_in>.size); a.sin_family=sa_family_t(AF_INET); a.sin_port=UInt16(18089).bigEndian; a.sin_addr=in_addr(s_addr:INADDR_ANY)
        return withUnsafePointer(to:&a) { $0.withMemoryRebound(to:sockaddr.self,capacity:1) { Darwin.bind(fd,$0,socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 } }
    }
    static func quote(_ s: String)->String { "'"+s.replacingOccurrences(of:"'",with:"'\\''")+"'" }
    static func authorizationScript(binary: String, uid: Int, home: String)->String {
        let command=[binary,"helper-install-root",String(uid),home].map(quote).joined(separator:" ")
        return "do shell script \""+command.replacingOccurrences(of:"\\",with:"\\\\").replacingOccurrences(of:"\"",with:"\\\"")+"\" with administrator privileges"
    }
    private func status(_ text: String) { message=text; onChange?() }
    private func fail(_ text: String) { busy=false; endLifecycle(); status(text) }
    private func verifyBundle()->Bool {
        guard let d=try? Data(contentsOf:URL(fileURLWithPath:bundle+"/Contents/Resources/runtime/manifest.json")), d.count<4096,
              let o=try? JSONSerialization.jsonObject(with:d) as? [String:Any], o["schema"] as? Int == 1,
              o["binary"] as? String == "anytls-macos", o["arch"] as? String == "arm64",
              let sha=o["sha256"] as? String, sha.count==64, sha.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
              let version=o["version"] as? String, !version.isEmpty, digest(source)==sha else { return false }
        expectedSHA=sha; expectedVersion=version; return true
    }
    func validConsoleMetadata(_ body: [String:Any])->Bool {
        body["version"] as? String == expectedVersion && body["listenHost"] as? String == "0.0.0.0" && (console?.isRunning == true || adopted?.stillMatches() == true)
    }
    func valid(_ m: DesktopMetadata, prepare: Bool=false)->Bool {
        m.schema==1 && m.uid==uid && uid>0 && m.home==home && m.binary==binary && m.config==config && m.config_identity==Self.sum(Data(config.utf8)) && m.binary_sha256==expectedSHA && m.version==expectedVersion && m.endpoint=="http://127.0.0.1:18089" && m.listen=="0.0.0.0" && m.port==18089 && (prepare ? m.helper_state=="not_checked" : ["missing","ready","mismatch","unavailable"].contains(m.helper_state)) && digest(binary)==expectedSHA
    }
    private func decode(_ r: DesktopCommandResult, prepare: Bool=false)->DesktopMetadata? {
        guard !r.timedOut, r.code==0, let m=try? JSONDecoder().decode(DesktopMetadata.self,from:r.data), valid(m,prepare:prepare) else { return nil }; return m
    }
    // Explicit action only. Timeouts never replay prepare/install; next action is inspect.
    func initialize(login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        guard !busy, beginLifecycle() else { return }; busy=true
        guard verifyBundle() else { fail("内嵌核心清单或 SHA 校验失败；拒绝安装"); return }
        if intents.present && (try? intents.load())?.state != "DONE" { reconcileMigration(login:login); return }
        if setupUncertain { inspect(allowAuthorization:false,login:login); return }
        if !exists(binary) {
            do { try intents.save(DesktopAuthorizationIntent(operation:String(repeating:"0",count:64),stage:binary,sha:expectedSHA,state:"UNKNOWN",resume:false,console:nil)) }
            catch { fail("首次准备意图无法持久保存；未执行准备"); return }
        }
        status("正在准备组件；不会启动 VPN…")
        run(source,["desktop","prepare"],25) { [weak self] r in
            guard let self=self else { return }
            if r.timedOut { self.setupUncertain=true }
            guard self.decode(r,prepare:true) != nil else {
                let code=(try? JSONSerialization.jsonObject(with:r.data) as? [String:Any])?["error"] as? String
                if ["UPDATE_REQUIRED","LEGACY_LAYOUT_REQUIRES_REVIEW","EXISTING_HELPER_REQUIRES_REVIEW"].contains(code ?? "") { self.inspectMigration(login:login); return }
                if self.exists(self.binary) && self.digest(self.binary) != self.expectedSHA { self.inspectMigration(login:login); return }
                self.inspectMigration(login:login); return
            }
            self.inspect(allowAuthorization:!self.authAttempted,login:login)
        }
    }
    func attach(login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        guard !busy, !blocksQuit, exists(binary), verifyBundle(), digest(binary)==expectedSHA, beginLifecycle() else { return }
        busy=true; inspect(allowAuthorization:false,login:login)
    }
    private func inspect(allowAuthorization: Bool, login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        run(binary,["desktop","inspect"],10) { [weak self] r in
            guard let self=self else { return }
            guard let m=self.decode(r) else { self.fail("组件检查失败／安装结果未知；不会重试授权，请核实后重试初始化"); return }
            switch m.helper_state {
            case "missing":
                guard allowAuthorization, self.verifyBundle(), self.digest(self.binary)==self.expectedSHA else { self.fail("助手未安装／授权未完成；不会自动重复提示。请重新打开 App 后主动初始化"); return }
                guard self.armAuthorization(operation:String(repeating:"0",count:64),stage:self.binary,resume:false) else { return }
                self.authAttempted=true; self.status("请在 macOS 原生授权窗口完成助手安装；不启动 VPN")
                self.run("/usr/bin/osascript",["-e",Self.authorizationScript(binary:self.binary,uid:self.uid,home:self.home)],120) { result in
                    self.recordAuthorization(result)
                    if result.timedOut { self.setupUncertain=true }
                    if result.code != 0 || result.timedOut { self.status("授权未完成或结果未知；正在只读检查，不重放安装") }
                    self.inspect(allowAuthorization:false,login:login)
                }
            case "ready":
                if var intent=try? self.intents.load(), intent.operation==String(repeating:"0",count:64) { intent.state="DONE"; do { try self.intents.save(intent); self.setupUncertain=false } catch { self.fail("授权记录无法同步；保持锁定"); return } }
                self.startConsole(login:login)
            default: self.fail("助手身份不匹配或不可用；请检查旧版迁移，拒绝覆盖")
            }
        }
    }
    private func armAuthorization(operation: String, stage: String, resume: Bool, pin: DesktopConsolePin? = nil)->Bool {
        guard candidateSafe(stage), digest(stage)==expectedSHA, stage==(operation==String(repeating:"0",count:64) ? binary : home+"/.anytls/.desktop-candidate-"+operation) else { fail("授权候选身份已改变；保持锁定"); return false }
        do { try intents.save(DesktopAuthorizationIntent(operation:operation,stage:stage,sha:expectedSHA,state:"ARMED",resume:resume,console:pin)); return true }
        catch { fail("无法持久保存授权意图；未调用系统授权"); return false }
    }
    private func recordAuthorization(_ result: DesktopCommandResult) {
        guard var intent=try? intents.load() else { setupUncertain=true; return }
        // Only native user-cancel (-128) proves no privileged worker launched.
        let text=String(data:result.stderr,encoding:.utf8) ?? ""
        intent.state = !result.timedOut && result.code != 0 && text.trimmingCharacters(in:.whitespacesAndNewlines).hasSuffix("(-128)") ? "DENIED" : (result.code==0 && !result.timedOut ? "READY" : "UNKNOWN")
        do { try intents.save(intent) } catch { setupUncertain=true }
    }
    private func inspectMigration(login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        run(source,["desktop","migration-inspect"],12) { result in
            guard let preview=DesktopMigration.parse(result), preview.valid(home:self.home,uid:self.uid,sha:self.expectedSHA), preview.phase=="INSPECTED", self.digest(self.binary)==preview.old_binary_sha256 else { self.fail("旧组件迁移检查 HOLD；未停止 VPN、未覆盖配置。请检查规范目录或待恢复事务"); return }
            self.locateConsole(sha:preview.old_binary_sha256) { safe,pin in
                guard safe else { self.fail("现有控制台身份或托管策略无法证明；更新前 HOLD，未停止 VPN"); return }
                guard let resume=self.consentMigration?(preview.was_running) else { self.fail("已取消更新；未停止 VPN"); return }
                guard pin?.stillMatches() != false else { self.fail("确认期间旧控制台身份改变；未停止 VPN"); return }
                self.run(self.source,["desktop","migration-commit",preview.plan],45) { result in
                    guard result.code==0, let pending=DesktopMigration.parse(result), pending.valid(home:self.home,uid:self.uid,sha:self.expectedSHA), pending.phase=="AWAITING_HELPER", let op=pending.operation, let stage=pending.stage else { self.setupUncertain=true; self.fail("迁移 STOP／暂存结果未知；只允许检查，不重放操作"); return }
                    guard self.armAuthorization(operation:op,stage:stage,resume:resume && preview.was_running,pin:pin) else { return }
                    self.authorizePending(login:login)
                }
            }
        }
    }
    private func authorizePending(login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        guard let intent=try? intents.load(), intent.sha==expectedSHA, intent.stage==(intent.operation==String(repeating:"0",count:64) ? binary : home+"/.anytls/.desktop-candidate-"+intent.operation), candidateSafe(intent.stage), digest(intent.stage)==expectedSHA else { fail("授权记录或候选 SHA 不匹配"); return }
        run("/usr/bin/osascript",["-e",Self.authorizationScript(binary:intent.stage,uid:uid,home:home)],120) { result in
            self.recordAuthorization(result); self.reconcileMigration(login:login)
        }
    }
    func retryAuthorization(login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        guard authorizationRetryAllowed, verifyBundle(), beginLifecycle() else { return }
        guard var intent=try? intents.load(), intent.state=="DENIED" else { endLifecycle(); return }; busy=true
        // Explicit separate action; never retry UNKNOWN/ARMED even after relaunch.
        if intent.operation==String(repeating:"0",count:64) {
            run(binary,["desktop","inspect"],10) { r in
                guard let m=self.decode(r), m.helper_state=="missing" else { self.fail("助手状态已改变；请只读检查"); return }
                intent.state="ARMED"; do { try self.intents.save(intent) } catch { self.fail("授权记录无法同步"); return }; self.authorizePending(login:login)
            }; return
        }
        run(source,["desktop","migration-inspect"],12) { result in
            guard let m=DesktopMigration.parse(result), m.valid(home:self.home,uid:self.uid,sha:self.expectedSHA), m.phase=="AWAITING_HELPER", m.operation==intent.operation, m.stage==intent.stage else { self.fail("待授权迁移身份不匹配"); return }
            intent.state="ARMED"; do { try self.intents.save(intent) } catch { self.fail("授权记录无法同步"); return }; self.authorizePending(login:login)
        }
    }
    private func reconcileMigration(login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        guard let intent=try? intents.load(), intent.sha==expectedSHA else { fail("授权记录不可读或版本不匹配；保持 HOLD"); return }
        if intent.state=="ACTIVATION_UNKNOWN" { fail("组件已安装，但 VPN 恢复结果未知；须人工核实，不会自动重试启动"); return }
        if intent.operation==String(repeating:"0",count:64) || intent.state=="DONE" { inspect(allowAuthorization:false,login:login); return }
        run(source,["desktop","migration-inspect"],12) { result in
            let metadata=DesktopMigration.parse(result)
            let awaiting=metadata.map { $0.valid(home:self.home,uid:self.uid,sha:self.expectedSHA) && $0.operation==intent.operation && $0.stage==intent.stage && $0.phase=="AWAITING_HELPER" } ?? false
            guard awaiting || (["READY","DRAINING"].contains(intent.state) && self.digest(self.binary)==self.expectedSHA) else { self.fail("迁移需要人工核实；不会重放 STOP 或授权"); return }
            // Go finish checks new protected-helper readiness before any publication.
            self.run(self.source,["desktop","migration-finish",intent.operation],20) { result in
                guard result.code==0, let m=DesktopMigration.parse(result), m.valid(home:self.home,uid:self.uid,sha:self.expectedSHA), m.phase=="COMMITTED", m.operation==intent.operation, self.digest(self.binary)==self.expectedSHA else { self.fail(intent.state=="DENIED" ? "系统授权已取消；可单独点击「重试已取消的授权…」" : "助手安装结果未就绪；保持未知锁定，只检查，不重新授权"); return }
                var ready=intent; if ready.state != "DRAINING" { ready.state="READY" }
                do { try self.intents.save(ready) } catch { self.fail("迁移已发布但应用记录无法同步；保持 HOLD"); return }
                self.restartMigratedConsole(ready,login:login)
            }
        }
    }
    private func restartMigratedConsole(_ intent: DesktopAuthorizationIntent, login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        func continueSetup() {
            self.adopted=nil; if self.console?.isRunning != true { self.console=nil }
            self.inspect(allowAuthorization:false) { origin,secret,finished in
                login(origin,secret) { ok in
                    guard ok else { finished(false); return }
                    var done=intent; done.state="DONE"; done.resume=false
                    do { try self.intents.save(done); self.setupUncertain=false } catch { finished(false); return }
                    finished(true)
                    if intent.resume { self.onMigrationResume?() }
                }
            }
        }
        guard let old=intent.console else { continueSetup(); return }
        if intent.state=="DRAINING" {
            guard !old.stillMatches() else { fail("旧控制台退出结果待确认；不会重复发送 TERM"); return }
            continueSetup(); return
        }
        guard old.stillMatches() else { fail("旧控制台进程已改变；不会结束未知进程，请人工核实"); return }
        var draining=intent; draining.state="DRAINING"
        do { try intents.save(draining) } catch { fail("控制台退出意图无法持久保存；未发送 TERM"); return }
        // PID birth and exact argv were pinned before canonical publication; the
        // now-new on-disk SHA is NOT claimed to hash the old process image.
        guard old.terminateIfMatching() else { fail("旧控制台未退出或身份改变；保持 HOLD"); return }
        let deadline=Date().addingTimeInterval(10)
        func wait() {
            if !old.stillMatches() { continueSetup() }
            else if Date()>=deadline { self.fail("旧控制台尚未退出；不会 SIGKILL 或卸载托管任务") }
            else { DispatchQueue.main.asyncAfter(deadline:.now()+0.15,execute:wait) }
        }
        wait()
    }
    private var managedLabel: String { "com.anytls.webui."+String(Self.sum(Data("\(uid)\0\(binary)\0\(config)".utf8)).prefix(24)) }
    static func consolePolicy(_ result: DesktopCommandResult, label: String, uid: Int, home: String, pid: Int32)->Bool? {
        guard result.code==0, !result.timedOut, let o=try? JSONSerialization.jsonObject(with:result.data) as? [String:Any],
              o["label"] as? String==label, o["target"] as? String=="gui/\(uid)/"+label,
              o["plist"] as? String==home+"/Library/LaunchAgents/"+label+".plist", let managed=o["restartManaged"] as? Bool,
              !managed || o["pid"] as? Int==Int(pid) else { return nil }
        return managed
    }
    private func locateConsole(sha: String, done: @escaping (Bool,DesktopConsolePin?)->Void) {
        run("/usr/sbin/lsof",["-nP","-iTCP:18089","-sTCP:LISTEN","-Fpu"],5) { r in
            if r.code==1 && !r.timedOut && r.data.isEmpty {
                self.absentJob("gui/\(self.uid)/"+self.managedLabel) { absent in done(absent && self.portFree(),nil) }; return
            }
            let lines=(String(data:r.data,encoding:.utf8) ?? "").split(separator:"\n").map(String.init)
            let pids=lines.filter { $0.hasPrefix("p") }
            guard r.code==0, !r.timedOut, pids.count==1, lines.contains("u\(self.uid)"), let pid=Int32(pids[0].dropFirst()), self.digest(self.binary)==sha else { done(false,nil); return }
            // Invoke incumbent, not bundled agent-status: its servicePaths must
            // refer to the actual canonical image, not Resources/runtime.
            self.run(self.binary,["webui","agent-status","--listen","0.0.0.0","--port","18089"],10) { result in
                guard let managed=Self.consolePolicy(result,label:self.managedLabel,uid:self.uid,home:self.home,pid:pid) else { done(false,nil); return }
                let manual=[self.binary,"webui","--listen","0.0.0.0","--port","18089"]
                guard let pin=DesktopConsolePin.observe(pid,sha:sha,managed:managed), pin.uid==UInt32(self.uid), pin.argv==(managed ? manual+["--managed-agent",self.managedLabel] : manual), self.digest(self.binary)==sha else { done(false,nil); return }
                if managed { done(true,pin) }
                else { self.absentJob("gui/\(self.uid)/"+self.managedLabel) { absent in done(absent && !self.exists(self.home+"/Library/LaunchAgents/"+self.managedLabel+".plist"),pin) } }
            }
        }
    }
    private func absentJob(_ target: String, _ done: @escaping (Bool)->Void) {
        run("/bin/launchctl",["print",target],5) { r in
            // launchctl diagnostics are stderr; runner intentionally discards it.
            // An independent list lookup provides a bounded, exact-label absence proof.
            self.run("/bin/launchctl",["list"],5) { list in
                let lines=String(data:list.data,encoding:.utf8)?.split(separator:"\n") ?? []
                done(!r.timedOut && r.code != 0 && !list.timedOut && list.code==0 && !lines.contains { $0.split(whereSeparator:{$0=="\t" || $0==" "}).last.map(String.init)==target.components(separatedBy:"/").last })
            }
        }
    }
    private func startConsole(login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        if let p=console, p.isRunning { confirmBind(p,attempt:0,login:login); return }
        let label=managedLabel
        if exists(home+"/Library/LaunchAgents/"+label+".plist") {
            func wait(_ left: Int) {
                self.locateConsole(sha:self.expectedSHA) { safe,pin in
                    if safe, let pin=pin, pin.managed { self.adopted=pin; self.authenticateAdopted(login:login) }
                    else if left>0 { DispatchQueue.main.asyncAfter(deadline:.now()+0.2) { wait(left-1) } }
                    else { self.fail("托管控制台尚未以新版本绑定；保持 HOLD，未启动第二个控制台") }
                }
            }
            wait(30); return
        }
        absentJob("gui/\(uid)/"+label) { absent in
            guard absent else { self.fail("无法证明托管控制台不存在；拒绝启动第二个控制台"); return }
            self.run("/usr/sbin/lsof",["-nP","-iTCP:18089","-sTCP:LISTEN","-Fp"],5) { r in
                guard !r.timedOut, r.code==1, r.data.isEmpty, self.portFree(), self.digest(self.binary)==self.expectedSHA else {
                    // Reuse only an exactly attested canonical manual/managed
                    // listener; mere port presence never releases credentials.
                    self.locateConsole(sha:self.expectedSHA) { safe,pin in
                        guard safe, let pin=pin else { self.fail("18089 被占用或身份未知；请检查现有控制台，未接管或结束任何进程"); return }
                        self.adopted=pin; self.authenticateAdopted(login:login)
                    }
                    return
                }
                let p: Process
                if let launch=self.launchConsole {
                    do { p=try launch() } catch { self.fail("无法启动自有控制台"); return }
                } else { p=Process(); p.executableURL=URL(fileURLWithPath:self.binary); p.arguments=["webui","--listen","0.0.0.0","--port","18089"] }
                do {
                    if !p.isRunning {
                        p.standardInput=FileHandle.nullDevice; p.standardOutput=FileHandle.nullDevice; p.standardError=FileHandle.nullDevice
                        try p.run()
                    }
                    self.console=p
                } catch { self.fail("无法启动自有控制台"); return }
                self.confirmBind(p,attempt:0,login:login)
            }
        }
    }
    private func confirmBind(_ p: Process, attempt: Int, login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        guard p.isRunning, attempt<25 else { fail("自有控制台绑定未确认；保留状态，请核实后退出"); return }
        run("/usr/sbin/lsof",["-nP","-a","-p",String(p.processIdentifier),"-iTCP:18089","-sTCP:LISTEN","-Fpun"],3) { r in
            let lines=Set((String(data:r.data,encoding:.utf8) ?? "").split(separator:"\n").map(String.init))
            if r.code==0 && !r.timedOut && lines.contains("p\(p.processIdentifier)") && lines.contains("u\(self.uid)") && lines.contains("n*:18089") && p.isRunning && self.digest(self.binary)==self.expectedSHA { self.authenticate(p,login:login) }
            else { DispatchQueue.main.asyncAfter(deadline:.now()+0.15) { self.confirmBind(p,attempt:attempt+1,login:login) } }
        }
    }
    private func authenticate(_ p: Process, login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        guard p.isRunning, console === p else { fail("自有控制台已退出"); return }
        run(binary,["desktop","credentials"],10) { r in
            guard p.isRunning, self.console === p, r.code==0, !r.timedOut,
                  let o=try? JSONSerialization.jsonObject(with:r.data) as? [String:Any], o["schema"] as? Int==1, o["endpoint"] as? String=="http://127.0.0.1:18089", let secret=o["password"] as? String, !secret.isEmpty, secret.utf8.count<=4096 else { self.fail("无法安全取得应用会话；请初始化或检查助手"); return }
            login("http://127.0.0.1:18089",secret) { ok in self.busy=false; self.endLifecycle(); self.status(ok ? "组件就绪；VPN 未自动启动" : "组件就绪但登录失败；请手动重试初始化") }
        }
    }
    private func authenticateAdopted(login: @escaping (String,String,@escaping (Bool)->Void)->Void) {
        guard let pin=adopted, pin.stillMatches(), digest(binary)==expectedSHA else { fail("托管控制台身份已改变"); return }
        run(binary,["desktop","credentials"],10) { r in
            guard pin.stillMatches(), r.code==0, !r.timedOut, let o=try? JSONSerialization.jsonObject(with:r.data) as? [String:Any], o["schema"] as? Int==1, o["endpoint"] as? String=="http://127.0.0.1:18089", let secret=o["password"] as? String, !secret.isEmpty, secret.utf8.count<=4096 else { self.fail("托管控制台凭据不可用"); return }
            login("http://127.0.0.1:18089",secret) { ok in self.busy=false; self.endLifecycle(); self.status(ok ? "托管控制台就绪；VPN 未自动启动" : "新控制台登录／版本验证失败") }
        }
    }
    // Never bypass STOP for partial setup. Only an independently absent fixed
    // root service + absent helper/runtime/snapshot permits an untouched app quit.
    func proveNeverInstalled(_ done: @escaping (Bool)->Void) {
        guard !blocksQuit, console==nil, !exists(binary), !exists(home+"/.anytls/anytls"), !exists(home+"/.anytls/service"), !exists("/Library/PrivilegedHelperTools/com.nousresearch.anytls-control"), !exists("/Library/LaunchDaemons/com.nousresearch.anytls-control.plist"), !exists("/Library/LaunchDaemons/com.nousresearch.anytls-macos.plist") else { done(false); return }
        run("/bin/launchctl",["print","system/com.nousresearch.anytls-macos"],5) { r in
            let text=String(data:r.stderr,encoding:.utf8) ?? ""
            guard !r.timedOut && r.code==113 && text.contains("Could not find service \"com.nousresearch.anytls-macos\" in domain for system") else { done(false); return }
            self.run("/bin/launchctl",["print","system/com.nousresearch.anytls-control"],5) { helper in
                let text=String(data:helper.stderr,encoding:.utf8) ?? ""
                done(!helper.timedOut && helper.code==113 && text.contains("Could not find service \"com.nousresearch.anytls-control\" in domain for system"))
            }
        }
    }
    func drainOwnedConsole(_ done: @escaping (Bool)->Void) {
        guard let p=console else { done(true); return }
        if !p.isRunning { console=nil; done(true); return }
        p.terminate() // Process handle: never kill/adopt by port/PID lookup.
        let end=Date().addingTimeInterval(drainTimeout)
        func check() {
            if !p.isRunning { self.console=nil; done(true) }
            else if Date()>=end { self.status("VPN 已停止，但自有控制台尚未退出；请稍后重试退出"); done(false) }
            else { DispatchQueue.main.asyncAfter(deadline:.now()+0.1,execute:check) }
        }
        check()
    }
}
