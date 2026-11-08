import AppKit
import ObjectiveC.runtime
private var desktopTerminationReplies=[Bool]()
extension NSApplication {
    @objc func desktop_reply(toApplicationShouldTerminate value: Bool) { desktopTerminationReplies.append(value) }
}

private final class DesktopQuitDriver: QuitDriver {
    var quitContext: QuitAuthContext? = QuitAuthContext(endpoint:try! LocalEndpoint("http://127.0.0.1:49179"),generation:1)
    var calls=0, result: QuitOutcome = .stopped
    func beginQuit(context: QuitAuthContext, completion: @escaping (QuitOutcome)->Void) { calls += 1; DispatchQueue.main.async { completion(self.result) } }
    func abandonQuit(context: QuitAuthContext) {}
}
private final class DesktopHTTP: URLProtocol {
    static var running=true, deny=false, denyLogin=false, posts=0, starts=0, unknownStart=false
    override class func canInit(with request: URLRequest)->Bool { true }
    override class func canonicalRequest(for request: URLRequest)->URLRequest { request }
    override func stopLoading() {}
    override func startLoading() {
        var body:[String:Any]=[:]; var status=200
        switch request.url!.path {
        case "/api/v1/login": if Self.denyLogin { status=403 }; body=["csrf":String(repeating:"x",count:43),"expiresIn":3600]
        case "/api/v1/service/start": Self.starts += 1; if Self.unknownStart { client?.urlProtocol(self,didFailWithError:URLError(.timedOut)); return }; Self.running=true; body=["ok":true,"running":true,"loaded":true]
        case "/api/v1/status": body=["loaded":Self.running,"running":Self.running,"availability":"AVAILABLE","version":"fixture","listenHost":"0.0.0.0"]
        case "/api/v1/helper/status": body=["available":true]
        case "/api/v1/nodes": body=["nodes":[],"etag":"fixture"]
        case "/api/v1/traffic": body=[:]
        case "/api/v1/service/stop": Self.posts += 1; if Self.deny { status=403; body=["error":"REJECTED"] } else { Self.running=false; body=["ok":true,"running":false,"loaded":false] }
        default: fatalError("Unexpected fixture route")
        }
        client?.urlProtocol(self,didReceive:HTTPURLResponse(url:request.url!,statusCode:status,httpVersion:nil,headerFields:nil)!,cacheStoragePolicy:.notAllowed)
        client?.urlProtocol(self,didLoad:try! JSONSerialization.data(withJSONObject:body)); client?.urlProtocolDidFinishLoading(self)
    }
}
@main struct DesktopRuntimeTests {
    static var checks=[String]()
    static func check(_ value: @autoclosure ()->Bool,_ name: String) { guard value() else { print("FAIL "+name); exit(1) }; checks.append(name); print("PASS "+name) }
    static func pump(_ condition: ()->Bool) { let end=Date().addingTimeInterval(3); while !condition() && Date()<end { RunLoop.main.run(until:Date().addingTimeInterval(0.01)) } }
    static func validNativeFloodCapture(_ data: Data, _ byte: UInt8) -> Bool {
        !data.isEmpty && data.count<=65536 && data.allSatisfy { $0==byte }
    }
    // A test-owned native child avoids /usr/bin/python3's SDK/toolchain startup.
    // write(2) may be short or interrupted; prove both complete finite floods.
    static func writeFlood(_ fd: Int32, _ byte: UInt8) {
        let bytes=[UInt8](repeating:byte,count:200000)
        bytes.withUnsafeBytes { raw in
            var offset=0
            while offset<raw.count {
                let n=Darwin.write(fd,raw.baseAddress!.advanced(by:offset),raw.count-offset)
                if n<0 && errno==EINTR { continue }
                guard n>0 else { exit(73) }
                offset += n
            }
        }
    }
    static func main() throws {
        if CommandLine.arguments.count==3 && CommandLine.arguments[1]=="--runner-flood" {
            writeFlood(STDOUT_FILENO,120); writeFlood(STDERR_FILENO,121)
            try Data("200000 200000".utf8).write(to:URL(fileURLWithPath:CommandLine.arguments[2]))
            return
        }
        if CommandLine.arguments.count>1 && CommandLine.arguments[1]=="webui" { Thread.sleep(forTimeInterval:30); return }
        if CommandLine.arguments.count>2 && CommandLine.arguments[1]=="--lease-holder" {
            let store=DesktopIntentStore(home:"",fixtureRoot:CommandLine.arguments[2])
            let fd=try store.acquireLease()
            print("LEASE_HELD"); fflush(stdout)
            Thread.sleep(forTimeInterval:20); DesktopIntentStore.releaseLease(fd); return
        }
        let root=URL(fileURLWithPath:CommandLine.arguments[1]); try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        let app=root.appendingPathComponent("AnyTLSMenuBar.app"), resources=app.appendingPathComponent("Contents/Resources/runtime")
        try FileManager.default.createDirectory(at:resources,withIntermediateDirectories:true)
        let sha=String(repeating:"a",count:64), home="/Users/owned fixture", uid=503, binary=home+"/.anytls/anytls-macos", config=home+"/.anytls/config.yaml"
        try JSONSerialization.data(withJSONObject:["schema":1,"binary":"anytls-macos","arch":DesktopRuntime.runtimeArchitecture,"version":"fixture","sha256":sha]).write(to:resources.appendingPathComponent("manifest.json"))
        #if arch(arm64)
        check(DesktopRuntime.runtimeArchitecture=="arm64","compiled runtime architecture uses canonical target identity")
        #elseif arch(x86_64)
        check(DesktopRuntime.runtimeArchitecture=="amd64","compiled runtime architecture uses canonical target identity")
        #endif
        // Only this owned fixture manifest is overwritten, then restored before
        // the existing lifecycle flows. No helper, authorization or child runs.
        do {
            let manifest=resources.appendingPathComponent("manifest.json")
            let validManifest=try Data(contentsOf:manifest)
            defer { try! validManifest.write(to:manifest) }
            let foreignArchitecture=DesktopRuntime.runtimeArchitecture=="arm64" ? "amd64" : "arm64"
            try JSONSerialization.data(withJSONObject:["schema":1,"binary":"anytls-macos","arch":foreignArchitecture,"version":"fixture","sha256":sha]).write(to:manifest)
            var dispatches=0, authorizations=0, credentials=0, logins=0
            var messages=[String]()
            let rejectRunner: DesktopRuntime.Runner = { path,args,_,done in
                dispatches += 1
                if path=="/usr/bin/osascript" { authorizations += 1 }
                if args.contains("credentials") { credentials += 1 }
                done(DesktopCommandResult(code:1,data:Data(),timedOut:false))
            }
            let rejectLogin: (String,String,@escaping (Bool)->Void)->Void = { _,_,done in logins += 1; done(false) }
            let rejectedSetup=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:rejectRunner,exists:{$0==binary},digest:{_ in sha},fixtureStateRoot:root.appendingPathComponent("architecture-initialize").path,candidateSafe:{_ in true})
            rejectedSetup.initialize(login:rejectLogin); messages.append(rejectedSetup.message)
            let rejectedAttach=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:rejectRunner,exists:{$0==binary},digest:{_ in sha},fixtureStateRoot:root.appendingPathComponent("architecture-attach").path,candidateSafe:{_ in true})
            let idleMessage=rejectedAttach.message
            rejectedAttach.attach(login:rejectLogin); messages.append(rejectedAttach.message)
            check(dispatches==0 && authorizations==0 && credentials==0 && logins==0 && messages[0].contains("拒绝安装") && messages[1]==idleMessage && !rejectedSetup.busy && !rejectedAttach.busy && rejectedSetup.console==nil && rejectedAttach.console==nil && !rejectedSetup.intents.present && !rejectedAttach.intents.present,"foreign manifest initialize and attach refuse before commands authorization credentials or login")
        }
        let migrationErrors=["CORE_RELOAD_PENDING","HOLD_PENDING","MIGRATION_UNKNOWN","MIGRATION_HOLD","HELPER_UNAVAILABLE","HELPER_CONFIG_MISMATCH"]
        var refusals=[(String,DesktopCommandResult,String?)]()
        for code in migrationErrors {
            refusals.append((code,DesktopCommandResult(code:1,data:try JSONSerialization.data(withJSONObject:["error":code,"detail":"PRIVATE_SENTINEL"]),timedOut:false),code))
        }
        let knownError=Data("{\"error\":\"CORE_RELOAD_PENDING\"}".utf8)
        refusals += [
            ("unknown",DesktopCommandResult(code:1,data:Data("{\"error\":\"PRIVATE_SENTINEL\"}".utf8),timedOut:false),nil),
            ("timeout",DesktopCommandResult(code:1,data:knownError,timedOut:true),nil),
            ("oversized",DesktopCommandResult(code:1,data:knownError+Data(repeating:32,count:4096),timedOut:false),nil),
            ("malformed",DesktopCommandResult(code:1,data:Data("PRIVATE_SENTINEL".utf8),timedOut:false),nil),
            ("success-code",DesktopCommandResult(code:0,data:knownError,timedOut:false),nil)
        ]
        for (name,result,expected) in refusals {
            var commands=[[String]]()
            let refusal=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{ _,args,_,done in
                commands.append(args)
                done(args==["desktop","prepare"] ? DesktopCommandResult(code:1,data:Data(),timedOut:false) : result)
            },exists:{$0==binary},digest:{_ in sha},fixtureStateRoot:root.appendingPathComponent("refusal-"+name).path,candidateSafe:{_ in true})
            refusal.initialize { _,_,_ in fatalError("Refused inspection must not login") }
            check(!refusal.busy && !refusal.intents.present && !refusal.message.contains("PRIVATE_SENTINEL") && (expected.map {refusal.message.contains("（"+$0+"）")} ?? refusal.message.contains("检查 HOLD")) && commands == [["desktop","prepare"],["desktop","migration-inspect"]],"migration inspection bounded nonsecret refusal: "+name)
        }
        var calls=[(String,[String])](), state="missing", ready=false, auths=0
        func metadata(_ prepare: Bool=false)->Data { try! JSONSerialization.data(withJSONObject:["schema":1,"version":"fixture","binary":binary,"config":config,"config_identity":DesktopRuntime.sum(Data(config.utf8)),"binary_sha256":sha,"endpoint":"http://127.0.0.1:18089","listen":"0.0.0.0","port":18089,"uid":uid,"home":home,"helper_state":prepare ? "not_checked" : state]) }
        let runner: DesktopRuntime.Runner = { path,args,_,done in
            calls.append((path,args))
            if path=="/usr/bin/osascript" { auths += 1; done(DesktopCommandResult(code:1,data:Data(),timedOut:false)); return }
            if args==["desktop","prepare"] { done(DesktopCommandResult(code:0,data:metadata(true),timedOut:false)); return }
            if args==["desktop","inspect"] { done(DesktopCommandResult(code:0,data:metadata(),timedOut:false)); return }
            if args.first=="print" { done(DesktopCommandResult(code:113,data:Data(),timedOut:false)); return }
            if args==["list"] { done(DesktopCommandResult(code:0,data:Data("PID Status Label\n".utf8),timedOut:false)); return }
            done(DesktopCommandResult(code:0,data:Data("p123\n".utf8),timedOut:false)) // unknown occupied listener
        }
        let runtime=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:runner,exists:{ $0==binary },digest:{ _ in sha },portFree:{false},fixtureStateRoot:root.appendingPathComponent("state").path,candidateSafe:{_ in true})
        let login: (String,String,@escaping (Bool)->Void)->Void = { _,_,_ in ready=true }
        runtime.initialize(login:login)
        check(auths==1,"explicit setup authorizes only missing helper once")
        check(runtime.message.contains("未安装") && !runtime.busy,"cancelled authorization remains truthful and idle")
        runtime.initialize(login:login)
        check(auths==1,"same launch never repeats authorization prompt")
        check(!ready,"cancel does not release secret or login")
        let held=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:runner,exists:{ $0==binary },digest:{ _ in sha },portFree:{false},fixtureStateRoot:root.appendingPathComponent("state").path,candidateSafe:{_ in true})
        held.initialize(login:login)
        check(auths==1 && held.blocksQuit && !held.authorizationRetryAllowed,"unknown authorization persists across relaunch and blocks retry and quit")
        var record=try runtime.intents.load()!; record.state="DONE"; try runtime.intents.save(record)
        state="mismatch"; runtime.attach(login:login)
        check(runtime.message.contains("不匹配") && auths==1,"mismatched helper refuses privileged dispatch")
        state="ready"; runtime.attach(login:login)
        check(runtime.message.contains("占用") && !ready,"unknown listener refused without adoption or credentials")
        check(!calls.contains { $0.1.contains("credentials") },"no private credentials before console ownership")
        check(!calls.contains { $0.1.contains("kill") || $0.1.contains("sudo") || $0.1.contains("/service/start") },"no kill sudo or automatic VPN start")
        let script=DesktopRuntime.authorizationScript(binary:"/Users/o'ne/.anytls/anytls-macos",uid:uid,home:"/Users/o'ne")
        check(script.contains("helper-install-root") && script.contains("administrator privileges") && script.contains("'\\\\''"),"native authorization quotes apostrophe argv")
        check(!script.contains("password"),"OS password is never requested or transported")
        let wrong=DesktopMetadata(schema:1,version:"fixture",binary:binary,config:config,config_identity:DesktopRuntime.sum(Data(config.utf8)),binary_sha256:sha,endpoint:"http://evil.invalid",listen:"0.0.0.0",port:18089,uid:uid,home:home,helper_state:"ready")
        check(!runtime.valid(wrong),"metadata endpoint mismatch fails closed")
        let badSHA=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:runner,exists:{ _ in false },digest:{ _ in "bad" },portFree:{false},fixtureStateRoot:root.appendingPathComponent("state").path,candidateSafe:{_ in true})
        let before=calls.count; badSHA.initialize(login:login)
        check(calls.count==before && badSHA.message.contains("SHA"),"manifest mismatch invokes no command")
        let partial=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:runner,exists:{ $0==binary },digest:{ _ in sha },portFree:{false},fixtureStateRoot:root.appendingPathComponent("state").path,candidateSafe:{_ in true})
        var proof: Bool?; partial.proveNeverInstalled { proof=$0 }
        check(proof==false,"half setup cannot use never-installed quit bypass")
        let driver=DesktopQuitDriver(), coordinator=QuitCoordinator(driver:driver,deadline:1)
        var replies=[Bool](); coordinator.start { replies.append($0) }; coordinator.start { replies.append($0) }; pump { !replies.isEmpty }
        check(replies==[true] && driver.calls==1,"duplicate quit coalesces verified stopped decision")
        driver.result = .blocked; let blocked=QuitCoordinator(driver:driver,deadline:1); var denied: Bool?; blocked.start { denied=$0 }; pump { denied != nil }
        check(denied==false,"not-stopped quit blocks termination")
        // Production delegate termination is exercised, with no launch/polling/keychain.
        let appKit=NSApplication.shared; appKit.setActivationPolicy(.accessory)
        let checkbox=AppDelegate.migrationResumeCheckbox(wasRunning:true)
        check(checkbox.state == .on && checkbox.isEnabled,"AppKit originally-running resume consent defaults on")
        checkbox.state = .off
        check(checkbox.state == .off,"AppKit explicit unchecked resume consent preserved")
        let stoppedCheckbox=AppDelegate.migrationResumeCheckbox(wasRunning:false)
        check(stoppedCheckbox.state == .off && !stoppedCheckbox.isEnabled,"AppKit stopped migration cannot auto resume")
        method_exchangeImplementations(class_getInstanceMethod(NSApplication.self,#selector(NSApplication.reply(toApplicationShouldTerminate:)))!,class_getInstanceMethod(NSApplication.self,#selector(NSApplication.desktop_reply(toApplicationShouldTerminate:)))!)
        let ui=AppDelegate(); ui.desktop=nil
        check(ui.applicationShouldTerminate(appKit) == .terminateLater,"real AppKit delegate uses asynchronous termination")
        check(ui.applicationShouldTerminate(appKit) == .terminateLater,"delegate coalesces pending normal termination")
        pump { !desktopTerminationReplies.isEmpty }; desktopTerminationReplies=[]
        // Exercise actual runner with anonymous pipes, >pipe-buffer data and cap.
        var result: DesktopCommandResult?
        DesktopProcessRunner.run("/usr/bin/printf",["PRIVATE_FIXTURE_SECRET"],2) { result=$0 }
        pump { result != nil }; check(result?.code==0 && result?.data==Data("PRIVATE_FIXTURE_SECRET".utf8),"private anonymous pipe transport remains memory only")
        result=nil; DesktopProcessRunner.run("/bin/sleep",["3"],0.05) { result=$0 }; pump { result != nil }
        check(result?.timedOut==true,"process deadline terminates owned test child asynchronously")
        let floodReceipt=root.appendingPathComponent("runner-flood-complete")
        result=nil; DesktopProcessRunner.run(CommandLine.arguments[0],["--runner-flood",floodReceipt.path],3) { result=$0 }; pump { result != nil }
        check(result?.code == -1 && result!.data.count<=65536 && result!.stderr.count<=65536 && result?.timedOut==false,"finite stdout stderr flood capped and fully drained")
        let floodResult=result
        result=nil; DesktopProcessRunner.run("/usr/bin/python3",["-c","import os,time; p=os.fork(); time.sleep(2) if p==0 else None"],0.1) { result=$0 }; pump { result != nil }
        check(result?.timedOut==true,"descendant retained pipes bounded without blocked reader threads")
        let sample=DesktopAuthorizationIntent(operation:String(repeating:"b",count:64),stage:home+"/.anytls/.desktop-candidate-"+String(repeating:"b",count:64),sha:sha,state:"ARMED",resume:true,console:nil)
        let store=DesktopIntentStore(home:home,fixtureRoot:root.appendingPathComponent("durable").path)
        try store.save(sample)
        check((try? DesktopIntentStore(home:home,fixtureRoot:store.root).load())?.state=="ARMED","atomic authorization intent survives new store instance")
        let attrs=try FileManager.default.attributesOfItem(atPath:store.root+"/authorization.json")
        check(attrs[.posixPermissions] as? Int==0o600,"durable intent JSON private0600")
        try FileManager.default.setAttributes([.posixPermissions:0o644],ofItemAtPath:store.root+"/authorization.json")
        check((try? store.load())==nil,"unsafe authorization metadata mode fails closed")
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:store.root+"/authorization.json")
        // Real child + production desktop prepare/inspect/authentication composition.
        var child: Process?
        let happyRunner: DesktopRuntime.Runner = { path,args,_,done in
            if args==["desktop","prepare"] { done(DesktopCommandResult(code:0,data:metadata(true),timedOut:false)); return }
            if args==["desktop","inspect"] { done(DesktopCommandResult(code:0,data:metadata(),timedOut:false)); return }
            if args==["desktop","credentials"] { done(DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:["schema":1,"endpoint":"http://127.0.0.1:18089","password":"PRIVATE_FIXTURE_ONLY"]),timedOut:false)); return }
            if args.first=="print" { done(DesktopCommandResult(code:113,data:Data(),timedOut:false)); return }
            if args==["list"] { done(DesktopCommandResult(code:0,data:Data(),timedOut:false)); return }
            if args.contains("-a"), let p=child { done(DesktopCommandResult(code:0,data:Data("p\(p.processIdentifier)\nu\(uid)\nn*:18089\n".utf8),timedOut:false)); return }
            done(DesktopCommandResult(code:1,data:Data(),timedOut:false))
        }
        let happy=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:happyRunner,exists:{ $0==binary },digest:{ _ in sha },portFree:{true},fixtureStateRoot:root.appendingPathComponent("happy").path,candidateSafe:{_ in true})
        happy.launchConsole={ let p=Process(); p.executableURL=URL(fileURLWithPath:"/bin/sleep"); p.arguments=["30"]; child=p; return p }
        var logged=false
        happy.initialize { _,secret,done in logged=secret=="PRIVATE_FIXTURE_ONLY"; done(logged) }
        check(logged && !happy.busy && child?.isRunning==true,"setup happy path owns actual private child before private credential login")
        let api=APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:49179"),configuration:{ let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[DesktopHTTP.self]; return c })
        var authenticated=false; api.login(password:"PRIVATE_ONLY") { authenticated=$0 }; pump { authenticated }
        let model=MenuModel(api:api,connectivityMonitor:nil), composition=AppDelegate(model:MenuModel(api:api,connectivityMonitor:nil)); _=model
        composition.desktop=happy
        desktopTerminationReplies=[]
        check(composition.applicationShouldTerminate(appKit) == .terminateLater,"composition enters real AppDelegate asynchronous quit")
        _=composition.applicationShouldTerminate(appKit)
        pump { !desktopTerminationReplies.isEmpty }
        check(desktopTerminationReplies==[true] && DesktopHTTP.posts==1 && child?.isRunning==false,"AppDelegate coordinator STOP acknowledgement owned child drain replyYES exactly once")
        let deniedUI=AppDelegate(model:MenuModel(api:api,connectivityMonitor:nil)); deniedUI.desktop=nil
        DesktopHTTP.running=true; DesktopHTTP.deny=true; desktopTerminationReplies=[]
        _=deniedUI.applicationShouldTerminate(appKit); pump { !desktopTerminationReplies.isEmpty }
        check(desktopTerminationReplies==[false] && DesktopHTTP.posts==2,"AppDelegate coordinator STOP rejection replyNO composition")
        // Original review P1-01: denied drain must discard only this ready proof.
        happy.launchConsole={ let p=Process(), out=Pipe(); p.executableURL=URL(fileURLWithPath:"/usr/bin/python3"); p.arguments=["-c","import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(30)"]; p.standardOutput=out; try p.run(); _=out.fileHandleForReading.availableData; child=p; return p }
        happy.initialize { _,_,done in done(true) }; happy.drainTimeout=0.02
        let retryUI=AppDelegate(model:MenuModel(api:api,connectivityMonitor:nil)); retryUI.desktop=happy
        DesktopHTTP.deny=false; DesktopHTTP.running=true; desktopTerminationReplies=[]
        let stopBaseline=DesktopHTTP.posts
        _=retryUI.applicationShouldTerminate(appKit); pump { !desktopTerminationReplies.isEmpty }
        check(desktopTerminationReplies==[false] && retryUI.quitCoordinator.state != .ready,"P1-01 drain failure invalidates attempt ready proof")
        if let p=child { kill(p.processIdentifier,SIGKILL); p.waitUntilExit() }
        DesktopHTTP.running=true; desktopTerminationReplies=[]
        _=retryUI.applicationShouldTerminate(appKit); pump { !desktopTerminationReplies.isEmpty }
        check(desktopTerminationReplies==[true] && DesktopHTTP.posts==stopBaseline+2,"P1-01 later quit after child exit requires fresh authenticated STOP")
        // Original review P1-02: production reattach must complete its owner.
        happy.launchConsole={ let p=Process(); p.executableURL=URL(fileURLWithPath:"/bin/sleep"); p.arguments=["30"]; child=p; return p }
        happy.initialize { _,_,done in done(true) }
        let freshAPI=APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:49179"),configuration:{let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[DesktopHTTP.self]; return c})
        let attachUI=AppDelegate(model:MenuModel(api:freshAPI,connectivityMonitor:nil)); attachUI.desktop=happy
        DesktopHTTP.denyLogin=true; desktopTerminationReplies=[]
        _=attachUI.applicationShouldTerminate(appKit); pump { !desktopTerminationReplies.isEmpty }
        check(desktopTerminationReplies==[false] && !happy.busy,"P1-02 production quit reattach login failure completes runtime owner")
        DesktopHTTP.denyLogin=false; DesktopHTTP.deny=true; desktopTerminationReplies=[]
        _=attachUI.applicationShouldTerminate(appKit); pump { !desktopTerminationReplies.isEmpty }
        check(desktopTerminationReplies==[false] && !happy.busy,"P1-02 production reattach STOP rejection releases runtime owner")
        attachUI.model.stopPolling(); freshAPI.reset(); DesktopHTTP.deny=false
        var cleanup: Bool?; happy.drainOwnedConsole {cleanup=$0}; pump {cleanup != nil}
        // Canonical occupied manual console reuse uses a real exact-argv child,
        // fixture-only metadata/HTTP, and never touches the actual console port.
        let adoptionHome=root.appendingPathComponent("adoption-home").path
        let adoptionBinary=adoptionHome+"/.anytls/anytls-macos", adoptionConfig=adoptionHome+"/.anytls/config.yaml"
        try FileManager.default.createDirectory(atPath:adoptionHome+"/.anytls",withIntermediateDirectories:true)
        try FileManager.default.copyItem(atPath:CommandLine.arguments[0],toPath:adoptionBinary)
        var manual=Process(); manual.executableURL=URL(fileURLWithPath:adoptionBinary); manual.arguments=["webui","--listen","0.0.0.0","--port","18089"]; try manual.run()
        var adoptionSecrets=0, adoptionLogins=0, adoptionManaged=false
        let adoptionRunner: DesktopRuntime.Runner={ _,args,_,done in
            if args==["desktop","inspect"] {
                let body:[String:Any]=["schema":1,"version":"fixture","binary":adoptionBinary,"config":adoptionConfig,"config_identity":DesktopRuntime.sum(Data(adoptionConfig.utf8)),"binary_sha256":sha,"endpoint":"http://127.0.0.1:18089","listen":"0.0.0.0","port":18089,"uid":Int(getuid()),"home":adoptionHome,"helper_state":"ready"]
                done(DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:body),timedOut:false))
            } else if args==["desktop","credentials"] {
                adoptionSecrets += 1
                done(DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:["schema":1,"endpoint":"http://127.0.0.1:18089","password":"PRIVATE_ONLY"]),timedOut:false))
            } else if args.first=="print" { done(DesktopCommandResult(code:113,data:Data(),timedOut:false)) }
            else if args==["list"] { done(DesktopCommandResult(code:0,data:Data(),timedOut:false)) }
            else if args.first=="webui" {
                let label="com.anytls.webui."+String(DesktopRuntime.sum(Data("\(getuid())\0\(adoptionBinary)\0\(adoptionConfig)".utf8)).prefix(24))
                let body:[String:Any]=["label":label,"target":"gui/\(getuid())/"+label,"plist":adoptionHome+"/Library/LaunchAgents/"+label+".plist","restartManaged":adoptionManaged,"pid":adoptionManaged ? Int(manual.processIdentifier) : 0]
                done(DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:body),timedOut:false))
            } else { done(DesktopCommandResult(code:0,data:Data("p\(manual.processIdentifier)\nu\(getuid())\n".utf8),timedOut:false)) }
        }
        let adoption=DesktopRuntime(bundle:app.path,home:adoptionHome,uid:Int(getuid()),run:adoptionRunner,exists:{FileManager.default.fileExists(atPath:$0)},digest:{_ in sha},portFree:{false},fixtureStateRoot:root.appendingPathComponent("adoption-state").path,candidateSafe:{_ in true})
        adoption.attach { _,_,done in adoptionLogins += 1; done(true) }
        check(adoptionLogins==1 && adoptionSecrets==1 && !adoption.busy && manual.isRunning,"exact canonical manual console is adopted and automatically authenticated without replacement")
        manual.terminate(); manual.waitUntilExit()
        // Canonical migration fixture uses exact Go JSON contract; commands are
        // injected, root authorization/helper/process/network are never executed.
        let op=String(repeating:"b",count:64), old=String(repeating:"c",count:64)
        func migration(_ phase: String)->Data {
            var o:[String:Any]=["schema":1,"phase":phase,"plan":String(repeating:"d",count:64),"binary":binary,"config":config,"config_identity":DesktopRuntime.sum(Data(config.utf8)),"binary_sha256":sha,"old_binary_sha256":old,"helper_sha256":old,"helper_version":"old","uid":uid,"home":home,"was_running":true]
            if phase != "INSPECTED" { o["operation"]=op; o["stage"]=home+"/.anytls/.desktop-candidate-"+op }
            return try! JSONSerialization.data(withJSONObject:o)
        }
        var migrationCalls=[[String]](), published=false, installed=false, migrationChild: Process?, resumed=0, cancelAuthorization=false
        let migrationRunner: DesktopRuntime.Runner = { path,args,_,done in
            migrationCalls.append(args)
            if path=="/usr/bin/osascript" { installed=true; done(DesktopCommandResult(code:cancelAuthorization ? 1 : 0,data:Data(),timedOut:false,stderr:cancelAuthorization ? Data("User canceled. (-128)".utf8) : Data())); return }
            switch args {
            case ["desktop","prepare"]: done(DesktopCommandResult(code:1,data:Data("{\"schema\":1,\"error\":\"UPDATE_REQUIRED\"}".utf8),timedOut:false))
            case ["desktop","migration-inspect"]: done(DesktopCommandResult(code:installed ? 1 : 0,data:installed ? try! JSONSerialization.data(withJSONObject:["schema":1,"error":"HOLD_PENDING","migration":try! JSONSerialization.jsonObject(with:migration("AWAITING_HELPER"))]) : migration("INSPECTED"),timedOut:false))
            case ["desktop","migration-commit",String(repeating:"d",count:64)]: done(DesktopCommandResult(code:0,data:migration("AWAITING_HELPER"),timedOut:false))
            case ["desktop","migration-finish",op]: if cancelAuthorization { done(DesktopCommandResult(code:1,data:Data("{}".utf8),timedOut:false)); return }; published=true; done(DesktopCommandResult(code:0,data:migration("COMMITTED"),timedOut:false))
            case ["desktop","inspect"]: done(DesktopCommandResult(code:0,data:metadata(),timedOut:false))
            case ["desktop","credentials"]: done(DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:["schema":1,"endpoint":"http://127.0.0.1:18089","password":"PRIVATE_ONLY"]),timedOut:false))
            case ["list"]: done(DesktopCommandResult(code:0,data:Data(),timedOut:false))
            default:
                if args.first=="print" { done(DesktopCommandResult(code:113,data:Data(),timedOut:false)) }
                else if args.contains("-a"), let p=migrationChild { done(DesktopCommandResult(code:0,data:Data("p\(p.processIdentifier)\nu\(uid)\nn*:18089\n".utf8),timedOut:false)) }
                else { done(DesktopCommandResult(code:1,data:Data(),timedOut:false)) }
            }
        }
        let migrated=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:migrationRunner,exists:{$0==binary},digest:{$0==binary && !published ? old : sha},portFree:{true},fixtureStateRoot:root.appendingPathComponent("migration").path,candidateSafe:{_ in true})
        migrated.consentMigration={ running in check(running,"migration preview captures original running policy"); return true }
        let resumeModel=MenuModel(api:api,connectivityMonitor:nil)
        DesktopHTTP.running=false; resumeModel.refresh(); pump { resumeModel.canMutate && resumeModel.status?.running==false }
        let startBaseline=DesktopHTTP.starts
        migrated.onMigrationResume={resumed += 1; if migrated.beginMigrationActivation() { resumeModel.mutate(path:"/service/start",consent:true) }}
        migrated.launchConsole={let p=Process(); p.executableURL=URL(fileURLWithPath:"/bin/sleep"); p.arguments=["30"]; migrationChild=p; return p}
        migrated.initialize { _,_,done in done(true) }
        pump { DesktopHTTP.starts>startBaseline && !resumeModel.pending && resumeModel.status?.running==true }
        migrated.observeMigrationActivation(running:resumeModel.status?.running==true,pending:resumeModel.pending,uncertain:resumeModel.uncertain)
        check(published && resumed==1 && DesktopHTTP.starts==startBaseline+1 && !migrated.blocksQuit,"migration old-running callback sends one normal model START then confirms")
        check(migrationCalls.filter{$0.first=="-e"}.count==1 && migrationCalls.filter{$0.contains("migration-commit")}.count==1 && !migrationCalls.contains{$0.contains("/service/stop")},"one fixed authorization one Go commit and no duplicate API STOP")
        var drained: Bool?; migrated.drainOwnedConsole {drained=$0}; pump {drained != nil}; check(drained==true,"migration fixture owned child drained")
        published=false; installed=false; cancelAuthorization=true; migrationCalls=[]
        let cancelledState=root.appendingPathComponent("migration-cancel").path
        func cancelledRuntime()->DesktopRuntime { DesktopRuntime(bundle:app.path,home:home,uid:uid,run:migrationRunner,exists:{$0==binary},digest:{$0==binary && !published ? old : sha},portFree:{true},fixtureStateRoot:cancelledState,candidateSafe:{_ in true}) }
        let cancelled=cancelledRuntime(); cancelled.consentMigration={ _ in false }; cancelled.initialize { _,_,done in done(false) }
        check(cancelled.authorizationRetryAllowed && cancelled.blocksQuit && !published,"definite native cancel persists DENIED not unknown and preserves no-resume choice")
        let relaunched=cancelledRuntime(); relaunched.initialize { _,_,done in done(false) }
        check(migrationCalls.filter{$0.first=="-e"}.count==1 && migrationCalls.filter{$0.contains("migration-commit")}.count==1,"relaunch reconciliation only inspects and finishes without STOP or authorization replay")
        check((try? relaunched.intents.load())?.resume==false,"unchecked resume policy persists across relaunch")
        check(DesktopHTTP.starts==startBaseline+1,"unchecked resume cancellation and relaunch dispatch zero additional START")
        let quitHeld=AppDelegate(); quitHeld.desktop=relaunched
        check(quitHeld.applicationShouldTerminate(appKit) == .terminateCancel,"AppDelegate refuses quit with durable pending migration")
        check(migrated.beginMigrationActivation(),"resume START intent durably armed before activation")
        DesktopHTTP.running=false; resumeModel.refresh(); pump { resumeModel.canMutate && resumeModel.status?.running==false }
        DesktopHTTP.unknownStart=true; resumeModel.mutate(path:"/service/start",consent:true); pump { resumeModel.uncertain }
        migrated.observeMigrationActivation(running:false,pending:resumeModel.pending,uncertain:resumeModel.uncertain)
        check(resumeModel.uncertain && DesktopHTTP.starts==startBaseline+2,"unknown normal model START is sticky and not replayed")
        let activationRelaunch=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:migrationRunner,exists:{$0==binary},digest:{_ in sha},portFree:{true},fixtureStateRoot:root.appendingPathComponent("migration").path,candidateSafe:{_ in true})
        activationRelaunch.initialize { _,_,done in done(false) }
        check(activationRelaunch.blocksQuit && activationRelaunch.message.contains("恢复结果未知"),"lost resume acknowledgement survives relaunch without START replay")
        check(!DesktopMigration.isToken(String(repeating:"Ａ",count:64)) && !DesktopMigration.isToken(String(repeating:"B",count:64)),"migration token rejects Unicode and uppercase")
        check(DesktopConsolePin.observe(getpid(),sha:sha,managed:false)?.stillMatches()==true,"native proc PID UID birth argv identity self observation")
        let owned=Process(); owned.executableURL=URL(fileURLWithPath:"/bin/sleep"); owned.arguments=["30"]; try owned.run()
        let observed=DesktopConsolePin.observe(owned.processIdentifier,sha:sha,managed:false)!
        let wrongBirth=DesktopConsolePin(pid:observed.pid,uid:observed.uid,seconds:observed.seconds+1,micros:observed.micros,argv:observed.argv,sha:sha,managed:false)
        check(!wrongBirth.terminateIfMatching() && owned.isRunning,"controlled manual fixture mismatched PID birth sends zero TERM")
        check(observed.terminateIfMatching(),"controlled manual owned fixture exact native identity sends one TERM")
        owned.waitUntilExit()
        check(!observed.terminateIfMatching(),"exited owned fixture cannot receive repeated TERM")
        let label="com.anytls.fixture."+UUID().uuidString
        func policy(_ managed: Bool,_ suppliedLabel: String,_ pid: Int)->DesktopCommandResult {
            DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:["label":suppliedLabel,"target":"gui/\(uid)/"+label,"plist":home+"/Library/LaunchAgents/"+label+".plist","restartManaged":managed,"pid":pid]),timedOut:false)
        }
        check(DesktopRuntime.consolePolicy(policy(true,label,123),label:label,uid:uid,home:home,pid:123)==true,"managed policy exact observed report decode accepted only pinned label PID")
        check(DesktopRuntime.consolePolicy(policy(true,label+"suffix",123),label:label,uid:uid,home:home,pid:123)==nil && DesktopRuntime.consolePolicy(policy(true,label,124),label:label,uid:uid,home:home,pid:123)==nil,"managed policy label suffix and PID mismatch deny before TERM")
        check(DesktopRuntime.consolePolicy(policy(false,label,0),label:label,uid:uid,home:home,pid:123)==false,"manual policy decode remains distinct from managed KeepAlive")
        let leaseStore=DesktopIntentStore(home:home,fixtureRoot:root.appendingPathComponent("lease").path)
        let holder=Process(), pipe=Pipe(); holder.executableURL=URL(fileURLWithPath:CommandLine.arguments[0]); holder.arguments=["--lease-holder",leaseStore.root]; holder.standardOutput=pipe
        try holder.run()
        let heldLine=pipe.fileHandleForReading.availableData
        check(String(data:heldLine,encoding:.utf8)?.contains("LEASE_HELD")==true,"actual second native process owns kernel lease")
        check(!leaseStore.present && (try? leaseStore.load())==nil,"lease-only root is not corrupt authorization intent")
        check((try? leaseStore.acquireLease())==nil,"actual cross-process flock excludes simultaneous open")
        var competingCalls=0
        let competing=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{_,_,_,_ in competingCalls += 1},exists:{_ in true},digest:{_ in sha},fixtureStateRoot:leaseStore.root)
        competing.initialize(login:login)
        check(competingCalls==0 && !competing.reserveQuitLifecycle(),"competing runtime refuses before prepare authorization STOP or TERM")
        var unknown=sample; unknown.state="UNKNOWN"; try leaseStore.save(unknown)
        holder.terminate(); holder.waitUntilExit()
        let reacquired=try leaseStore.acquireLease(); DesktopIntentStore.releaseLease(reacquired)
        check((try? leaseStore.load())?.state=="UNKNOWN","lockholder exit releases kernel lease but never clears durable UNKNOWN")
        let same=try leaseStore.acquireLease()
        check((try? DesktopIntentStore(home:home,fixtureRoot:leaseStore.root).acquireLease())==nil,"same-process separate opens cannot duplicate runtime lease")
        DesktopIntentStore.releaseLease(same)
        var inspected=0, authorized=0
        let afterCrash=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{path,args,_,done in
            if path=="/usr/bin/osascript" { authorized += 1 }
            if args.contains("migration-inspect") { inspected += 1 }
            done(DesktopCommandResult(code:1,data:Data(),timedOut:false))
        },exists:{_ in true},digest:{_ in sha},fixtureStateRoot:leaseStore.root)
        afterCrash.initialize(login:login)
        check(inspected==1 && authorized==0 && afterCrash.blocksQuit,"crashed lockholder UNKNOWN only reconciles and never reauthorizes")
        let member=leaseStore.root+"/unexpected"
        // createFile can return false under the release sandbox without creating
        // the fixture. Require successful publication before testing the guard.
        try Data().write(to:URL(fileURLWithPath:member),options:.withoutOverwriting)
        var memberStat=stat()
        guard lstat(member,&memberStat)==0, memberStat.st_mode & S_IFMT == S_IFREG,
              memberStat.st_size==0, memberStat.st_uid==getuid(), memberStat.st_nlink==1,
              try FileManager.default.contentsOfDirectory(atPath:leaseStore.root).contains("unexpected") else {
            throw CocoaError(.fileWriteUnknown)
        }
        check(leaseStore.present && (try? leaseStore.acquireLease())==nil,"unknown private-root member conservatively refuses mutation")
        try FileManager.default.removeItem(atPath:member)
        let lockPath=leaseStore.root+"/lifecycle.lock"
        try FileManager.default.setAttributes([.posixPermissions:0o644],ofItemAtPath:lockPath)
        check((try? leaseStore.acquireLease())==nil,"unsafe lease permissions refuse acquisition")
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:lockPath)
        let alias=root.appendingPathComponent("lock-alias").path
        check(link(lockPath,alias)==0 && (try? leaseStore.acquireLease())==nil,"hardlinked lease refuses acquisition")
        unlink(alias); unlink(lockPath)
        check(symlink("authorization.json",lockPath)==0 && (try? leaseStore.acquireLease())==nil,"symlink lease refuses acquisition without following target")
        unlink(lockPath)
        // Preserve the complete original inventory above; append argv regressions.
        manual=Process(); manual.executableURL=URL(fileURLWithPath:adoptionBinary); manual.arguments=["webui","--port","18089","--listen","0.0.0.0"]; try manual.run()
        adoptionSecrets=0; adoptionLogins=0
        let reversedAdoption=DesktopRuntime(bundle:app.path,home:adoptionHome,uid:Int(getuid()),run:adoptionRunner,exists:{FileManager.default.fileExists(atPath:$0)},digest:{_ in sha},portFree:{false},fixtureStateRoot:root.appendingPathComponent("adoption-reversed-state").path,candidateSafe:{_ in true})
        reversedAdoption.attach { _,_,done in adoptionLogins += 1; done(true) }
        let reversedAccepted=adoptionLogins==1 && adoptionSecrets==1 && !reversedAdoption.busy && manual.isRunning
        manual.terminate(); manual.waitUntilExit()
        check(reversedAccepted,"reversed port listen canonical manual console is adopted before private credential login")
        let adoptionLabel="com.anytls.webui."+String(DesktopRuntime.sum(Data("\(getuid())\0\(adoptionBinary)\0\(adoptionConfig)".utf8)).prefix(24))
        let integrationCases:[(String,[String],Bool,Bool)]=[
            ("managed reordered",["webui","--managed-agent",adoptionLabel,"--port","18089","--listen","0.0.0.0"],true,true),
            ("manual duplicate",["webui","--port","18089","--port","18089"],false,false),
            ("manual managed flag",["webui","--listen","0.0.0.0","--port","18089","--managed-agent",adoptionLabel],false,false),
            ("managed missing flag",["webui","--port","18089","--listen","0.0.0.0"],true,false),
            ("managed wrong label",["webui","--port","18089","--managed-agent",adoptionLabel+"suffix","--listen","0.0.0.0"],true,false)
        ]
        for (name,args,managed,accepted) in integrationCases {
            manual=Process(); manual.executableURL=URL(fileURLWithPath:adoptionBinary); manual.arguments=args; try manual.run()
            adoptionSecrets=0; adoptionLogins=0; adoptionManaged=managed
            let runtime=DesktopRuntime(bundle:app.path,home:adoptionHome,uid:Int(getuid()),run:adoptionRunner,exists:{FileManager.default.fileExists(atPath:$0)},digest:{_ in sha},portFree:{false},fixtureStateRoot:root.appendingPathComponent("argv-"+name).path,candidateSafe:{_ in true})
            runtime.attach { _,_,done in adoptionLogins += 1; done(true) }
            let valid=adoptionSecrets==(accepted ? 1 : 0) && adoptionLogins==(accepted ? 1 : 0) && !runtime.busy && manual.isRunning
            manual.terminate(); manual.waitUntilExit()
            check(valid,"real native observed argv adoption boundary: "+name)
        }
        let listen=["--listen","0.0.0.0"], port=["--port","18089"], agent=["--managed-agent",adoptionLabel]
        let prefix=[adoptionBinary,"webui"]
        for (index,pairs) in [[listen,port],[port,listen]].enumerated() {
            check(DesktopRuntime.consoleArguments(prefix+pairs.flatMap{$0},binary:adoptionBinary,managed:false,label:adoptionLabel),"manual option pair permutation \(index)")
        }
        let permutations=[[listen,port,agent],[listen,agent,port],[port,listen,agent],[port,agent,listen],[agent,listen,port],[agent,port,listen]]
        for (index,pairs) in permutations.enumerated() {
            check(DesktopRuntime.consoleArguments(prefix+pairs.flatMap{$0},binary:adoptionBinary,managed:true,label:adoptionLabel),"managed option pair permutation \(index)")
        }
        let invalid:[(String,[String])]=[
            ("empty",[]), ("path only",[adoptionBinary]), ("missing options",prefix),
            ("wrong path",[adoptionBinary+"suffix","webui"]+listen+port),
            ("noncanonical path",[adoptionHome+"/.anytls/./anytls-macos","webui"]+listen+port),
            ("wrong command",[adoptionBinary,"agent-status"]+listen+port),
            ("wrong host",prefix+["--listen","127.0.0.1"]+port),
            ("wrong port",prefix+listen+["--port","18090"]),
            ("missing listen",prefix+port), ("missing port",prefix+listen),
            ("missing value",prefix+listen+["--port"]),
            ("option as value",prefix+["--listen","--port","18089"]),
            ("duplicate equal listen",prefix+listen+listen),
            ("duplicate equal port",prefix+port+port),
            ("duplicate extra",prefix+listen+port+port),
            ("duplicate unequal",prefix+listen+port+["--port","18090"]),
            ("unknown option",prefix+["--host","0.0.0.0"]+port),
            ("extra unknown",prefix+listen+port+["--unknown","value"]),
            ("positional",prefix+["0.0.0.0","--listen"]+port),
            ("extra positional",prefix+listen+port+["value"]),
            ("swapped values",prefix+["--listen","18089","--port","0.0.0.0"]),
            ("equals form",prefix+["--listen=0.0.0.0","--port=18089"]),
            ("alias",prefix+["-listen","0.0.0.0"]+port),
            ("terminator",prefix+["--"]+listen+port)
        ]
        for (name,argv) in invalid {
            check(!DesktopRuntime.consoleArguments(argv,binary:adoptionBinary,managed:false,label:adoptionLabel),"manual argv rejects "+name)
            check(!DesktopRuntime.consoleArguments(argv+agent,binary:adoptionBinary,managed:true,label:adoptionLabel),"managed argv rejects "+name)
        }
        check(!DesktopRuntime.consoleArguments(prefix+listen+port+agent,binary:adoptionBinary,managed:false,label:adoptionLabel),"manual argv rejects managed flag")
        check(!DesktopRuntime.consoleArguments(prefix+listen+port,binary:adoptionBinary,managed:true,label:adoptionLabel),"managed argv requires flag")
        check(!DesktopRuntime.consoleArguments(prefix+listen+port+["--managed-agent",adoptionLabel+"suffix"],binary:adoptionBinary,managed:true,label:adoptionLabel),"managed argv requires exact label")
        check(!DesktopRuntime.consoleArguments(prefix+listen+agent+agent,binary:adoptionBinary,managed:true,label:adoptionLabel),"managed argv rejects equal duplicate flag replacing port")
        check(!DesktopRuntime.consoleArguments(prefix+listen+port+agent+agent,binary:adoptionBinary,managed:true,label:adoptionLabel),"managed argv rejects extra duplicate flag")
        check(floodResult.map { validNativeFloodCapture($0.data,120) && validNativeFloodCapture($0.stderr,121) } ?? false,"native flood retains bounded expected bytes on both streams")
        check((try? Data(contentsOf:floodReceipt)) == Data("200000 200000".utf8),"native flood completes both 200000 byte write loops before exit")
        // Recovery assertions append after the frozen Desktop150 prefix.
        var recoveryCalls=[[String]](), recoveryAuths=0, durableBeforeSTOP=false
        let recoveryState=root.appendingPathComponent("recovery-happy").path
        let oldOperation=String(repeating:"e",count:64), oldRawSHA=String(repeating:"f",count:64)
        func recoveryBody(_ phase: String)->Data {
            var body=try! JSONSerialization.jsonObject(with:migration(phase=="RECOVERY_INSPECTED" ? "INSPECTED" : phase)) as! [String:Any]
            body["phase"]=phase; body["recovery_of"]=oldOperation; body["recovery_plan_sha256"]=oldRawSHA
            return try! JSONSerialization.data(withJSONObject:body)
        }
        let recoveryRunner: DesktopRuntime.Runner={ path,args,_,done in
            recoveryCalls.append(args)
            if args==["desktop","migration-recovery-inspect"] { done(DesktopCommandResult(code:0,data:recoveryBody("RECOVERY_INSPECTED"),timedOut:false)); return }
            if args.contains("migration-recovery-commit") {
                let store=DesktopIntentStore(home:home,fixtureRoot:recoveryState)
                durableBeforeSTOP=(try? store.loadRecovery())?.state=="RECOVERY_ARMED" && !store.present && recoveryAuths==0
                done(DesktopCommandResult(code:0,data:recoveryBody("AWAITING_HELPER"),timedOut:false)); return
            }
            if path=="/usr/bin/osascript" { recoveryAuths += 1; done(DesktopCommandResult(code:1,data:Data(),timedOut:true)); return }
            if args==["desktop","migration-inspect"] { done(DesktopCommandResult(code:1,data:try! JSONSerialization.data(withJSONObject:["migration":try! JSONSerialization.jsonObject(with:recoveryBody("AWAITING_HELPER"))]),timedOut:false)); return }
            if args.first=="print" { done(DesktopCommandResult(code:113,data:Data(),timedOut:false)); return }
            if args==["list"] { done(DesktopCommandResult(code:0,data:Data(),timedOut:false)); return }
            done(DesktopCommandResult(code:1,data:Data(),timedOut:false))
        }
        let recoveryRuntime=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:recoveryRunner,exists:{$0==binary},digest:{$0==binary ? old : sha},portFree:{true},fixtureStateRoot:recoveryState,candidateSafe:{_ in true})
        recoveryRuntime.recover { _,_,_ in fatalError("Recovery auth timeout must not login") }
        check(durableBeforeSTOP && recoveryAuths==1 && recoveryCalls.filter{$0.contains("migration-recovery-commit")}.count==1,"recovery intent durable before one new STOP and no helper authorization before awaiting")
        check((try? recoveryRuntime.intents.loadRecovery())?.operation==op && (try? recoveryRuntime.intents.load())?.resume==false && recoveryRuntime.blocksQuit && !recoveryRuntime.recoveryAllowed,"recovery exact new operation binds separate intent and never authorizes resume")
        let recoveryBaseline=recoveryCalls.count
        recoveryRuntime.recover(login:login)
        check(recoveryCalls.count==recoveryBaseline,"second recovery click after authorization uncertainty cannot repeat commit")
        let restartedRecovery=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:recoveryRunner,exists:{$0==binary},digest:{$0==binary ? old : sha},portFree:{true},fixtureStateRoot:recoveryState,candidateSafe:{_ in true})
        restartedRecovery.initialize(login:login)
        check(Array(recoveryCalls.dropFirst(recoveryBaseline))==[["desktop","migration-inspect"]] && recoveryAuths==1,"recovery restart only inspects without STOP authorization finish or START replay")
        let recoveryAttrs=try FileManager.default.attributesOfItem(atPath:recoveryState+"/recovery.json")
        let recoveryRootAttrs=try FileManager.default.attributesOfItem(atPath:recoveryState)
        check(recoveryAttrs[.posixPermissions] as? Int==0o600 && recoveryRootAttrs[.posixPermissions] as? Int==0o700,"recovery intent uses private0600 owned0700 root")
        let previewResult=DesktopCommandResult(code:0,data:recoveryBody("RECOVERY_INSPECTED"),timedOut:false)
        check(sha != old && DesktopRecoveryPreview.parse(previewResult)?.valid(home:home,uid:uid,sha:sha)==true && DesktopMigration.parse(previewResult)?.valid(home:home,uid:uid,sha:sha)==false,"separate recovery preview accepts different new bundle and never weakens normal migration validator")
        let validPreview=try JSONSerialization.jsonObject(with:previewResult.data) as! [String:Any]
        let badPreviews:[(String,Any)]=[("schema",2),("phase","INSPECTED"),("plan",String(repeating:"A",count:64)),("binary",binary+".alias"),("config_identity",old),("binary_sha256",old),("helper_sha256","bad"),("helper_version",""),("uid",0),("home",home+"x"),("recovery_of",String(repeating:"a",count:32)),("recovery_plan_sha256","bad"),("unknown",true)]
        for (index,pair) in badPreviews.enumerated() {
            var object=validPreview; object[pair.0]=pair.1
            var commands=[[String]]()
            let refused=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{ _,args,_,done in commands.append(args); done(DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:object),timedOut:false)) },exists:{$0==binary},digest:{$0==binary ? old : sha},fixtureStateRoot:root.appendingPathComponent("recovery-bad-\(index)").path)
            refused.recover(login:login)
            check(commands==[["desktop","migration-recovery-inspect"]] && !refused.intents.recoveryPresent && !refused.intents.present && !refused.busy,"recovery bad preview refuses before intent STOP authorization: "+pair.0)
        }
        for (name,data) in [("duplicate",Data((String(data:previewResult.data,encoding:.utf8)!.dropLast()+",\"schema\":1}").utf8)),("case alias",Data((String(data:previewResult.data,encoding:.utf8)!.dropLast()+",\"Schema\":1}").utf8)),("timeout",previewResult.data),("oversize",Data(repeating:32,count:16385))] {
            check(DesktopRecoveryPreview.parse(DesktopCommandResult(code:0,data:data,timedOut:name=="timeout"))==nil,"strict recovery preview rejects "+name)
        }
        var lostCommit: ((DesktopCommandResult)->Void)?, lostCalls=[[String]]()
        let lostRoot=root.appendingPathComponent("recovery-lost").path
        let lostRunner: DesktopRuntime.Runner={ _,args,_,done in
            lostCalls.append(args)
            if args.contains("migration-recovery-commit") { lostCommit=done; return }
            if args==["desktop","migration-recovery-inspect"] { done(previewResult); return }
            if args.first=="print" { done(DesktopCommandResult(code:113,data:Data(),timedOut:false)); return }
            if args==["list"] { done(DesktopCommandResult(code:0,data:Data(),timedOut:false)); return }
            done(DesktopCommandResult(code:1,data:Data(),timedOut:false))
        }
        let lostRuntime=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:lostRunner,exists:{$0==binary},digest:{$0==binary ? old : sha},portFree:{true},fixtureStateRoot:lostRoot)
        lostRuntime.recover(login:login)
        check(lostCommit != nil && (try? lostRuntime.intents.loadRecovery())?.state=="RECOVERY_ARMED" && !lostRuntime.intents.present,"held STOP keeps genuine pre-STOP recovery intent not forged authorization")
        let competingRecovery=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:lostRunner,exists:{$0==binary},digest:{_ in sha},fixtureStateRoot:lostRoot)
        let beforeCompete=lostCalls.count; competingRecovery.recover(login:login)
        check(lostCalls.count==beforeCompete && !competingRecovery.recoveryAllowed,"durable recovery intent refuses another runtime before any dispatch")
        lostCommit?(DesktopCommandResult(code:1,data:Data(),timedOut:true))
        check((try? lostRuntime.intents.loadRecovery())?.state=="RECOVERY_UNKNOWN" && !lostRuntime.recoveryAllowed && lostRuntime.blocksQuit && !lostRuntime.intents.present,"lost recovery STOP response persists sticky UNKNOWN without helper authorization")
        let afterLost=lostCalls.count; lostRuntime.recover(login:login); lostRuntime.initialize(login:login)
        check(Array(lostCalls.dropFirst(afterLost))==[["desktop","migration-inspect"]],"unknown recovery repeated click and initialize never repeat STOP")
        lostCommit?(DesktopCommandResult(code:0,data:recoveryBody("AWAITING_HELPER"),timedOut:false))
        check(!lostRuntime.intents.present && (try? lostRuntime.intents.loadRecovery())?.state=="RECOVERY_UNKNOWN","late successful recovery callback after timeout cannot authorize or clear UNKNOWN")
        // The exact same lifecycle lease used by recovery is held in a separate
        // native process; no fixture Boolean stands in for kernel exclusion.
        let processRoot=root.appendingPathComponent("recovery-process-lease").path
        let recoveryHolder=Process(), recoveryPipe=Pipe(); recoveryHolder.executableURL=URL(fileURLWithPath:CommandLine.arguments[0]); recoveryHolder.arguments=["--lease-holder",processRoot]; recoveryHolder.standardOutput=recoveryPipe; try recoveryHolder.run()
        let processHeld=recoveryPipe.fileHandleForReading.availableData
        var processDispatches=0
        let processBlocked=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{_,_,_,_ in processDispatches += 1},exists:{$0==binary},digest:{_ in sha},fixtureStateRoot:processRoot)
        processBlocked.recover(login:login)
        check(String(data:processHeld,encoding:.utf8)?.contains("LEASE_HELD")==true && processDispatches==0 && !processBlocked.busy,"actual separate native process lifecycle lease blocks recovery inspection and STOP")
        recoveryHolder.terminate(); recoveryHolder.waitUntilExit()
        check(!processBlocked.intents.recoveryPresent && !processBlocked.intents.present,"lease process exit never fabricates recovery or authorization")
        // Exercise completion through actual owned console child + both durable
        // stores. The backend transport remains an offline fixture only.
        var completedPublished=false, completedCalls=[[String]](), completedChild: Process?, completedAuths=0, completedResumes=0
        let completeRoot=root.appendingPathComponent("recovery-complete").path
        let completeRunner: DesktopRuntime.Runner={ path,args,_,done in
            completedCalls.append(args)
            if args==["desktop","migration-recovery-inspect"] { done(previewResult); return }
            if args.contains("migration-recovery-commit") { done(DesktopCommandResult(code:0,data:recoveryBody("AWAITING_HELPER"),timedOut:false)); return }
            if path=="/usr/bin/osascript" { completedAuths += 1; done(DesktopCommandResult(code:0,data:Data(),timedOut:false)); return }
            if args==["desktop","migration-inspect"] { done(DesktopCommandResult(code:1,data:try! JSONSerialization.data(withJSONObject:["migration":try! JSONSerialization.jsonObject(with:recoveryBody(completedPublished ? "COMMITTED" : "AWAITING_HELPER"))]),timedOut:false)); return }
            if args==["desktop","migration-finish",op] { completedPublished=true; done(DesktopCommandResult(code:0,data:recoveryBody("COMMITTED"),timedOut:false)); return }
            if args==["desktop","migration-recovery-finalize",op] { done(DesktopCommandResult(code:0,data:recoveryBody("COMMITTED"),timedOut:false)); return }
            if args==["desktop","inspect"] { done(DesktopCommandResult(code:0,data:metadata(),timedOut:false)); return }
            if args==["desktop","credentials"] { done(DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:["schema":1,"endpoint":"http://127.0.0.1:18089","password":"PRIVATE_ONLY"]),timedOut:false)); return }
            if args.first=="print" { done(DesktopCommandResult(code:113,data:Data(),timedOut:false)); return }
            if args==["list"] { done(DesktopCommandResult(code:0,data:Data(),timedOut:false)); return }
            if args.contains("-a"), let p=completedChild { done(DesktopCommandResult(code:0,data:Data("p\(p.processIdentifier)\nu\(uid)\nn*:18089\n".utf8),timedOut:false)); return }
            done(DesktopCommandResult(code:1,data:Data(),timedOut:false))
        }
        let completedRuntime=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:completeRunner,exists:{$0==binary},digest:{$0==binary && !completedPublished ? old : sha},portFree:{true},fixtureStateRoot:completeRoot,candidateSafe:{_ in true})
        completedRuntime.launchConsole={ let p=Process(); p.executableURL=URL(fileURLWithPath:"/bin/sleep"); p.arguments=["30"]; completedChild=p; return p }
        completedRuntime.onMigrationResume={ completedResumes += 1 }
        let recoveryStartsBefore=DesktopHTTP.starts
        completedRuntime.recover { _,_,done in done(true) }
        check(completedPublished && completedAuths==1 && (try? completedRuntime.intents.loadRecovery())?.state=="DONE" && (try? completedRuntime.intents.load())?.state=="DONE" && !completedRuntime.blocksQuit,"recovery full finish and owned-console login mark both stores DONE")
        check(completedResumes==0 && DesktopHTTP.starts==recoveryStartsBefore && completedCalls.filter{$0.contains("migration-recovery-commit")}.count==1,"recovery completion never offers historical resume or automatically starts VPN")
        var completedDrain: Bool?; completedRuntime.drainOwnedConsole {completedDrain=$0}; pump {completedDrain != nil}
        check(completedDrain==true && completedChild?.isRunning==false,"recovery happy path owned console child reaped")
        // Explicit terminal-only finalization from retained COMMITTED metadata.
        var finalRecovery=try completedRuntime.intents.loadRecovery()!; finalRecovery.state="AWAITING_HELPER"; try completedRuntime.intents.saveRecovery(finalRecovery)
        var finalAuth=try completedRuntime.intents.load()!; finalAuth.state="READY"; try completedRuntime.intents.save(finalAuth)
        let finalBaseline=completedCalls.count
        completedRuntime.completeRecovery { _,_,done in done(true) }
        let finalCommands=Array(completedCalls.dropFirst(finalBaseline))
        check(finalCommands.contains(["desktop","migration-recovery-finalize",op]) && !finalCommands.contains{$0.contains("migration-finish") || $0.contains("migration-recovery-commit") || $0.first=="-e"} && (try? completedRuntime.intents.loadRecovery())?.state=="DONE","explicit COMMITTED finalization dispatches only terminal write before console handoff no STOP authorization publication")
        completedDrain=nil; completedRuntime.drainOwnedConsole {completedDrain=$0}; pump {completedDrain != nil}
        check(completedDrain==true && completedResumes==0,"finalization also never starts VPN and reaps only owned child")
        // Provenance and exact new-op refusals after an otherwise valid STOP.
        for key in ["recovery_of","recovery_plan_sha256","operation","binary_sha256","helper_sha256","helper_version"] {
            var body=try JSONSerialization.jsonObject(with:recoveryBody("AWAITING_HELPER")) as! [String:Any]
            body[key]=key=="operation" ? oldOperation : key=="helper_version" ? "foreign" : String(repeating:"9",count:64)
            var authorized=0
            let refusalRoot=root.appendingPathComponent("recovery-return-"+key).path
            let refusal=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{ path,args,_,done in
                if path=="/usr/bin/osascript" { authorized += 1 }
                if args==["desktop","migration-recovery-inspect"] { done(previewResult) }
                else if args.contains("migration-recovery-commit") { done(DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:body),timedOut:false)) }
                else if args.first=="print" { done(DesktopCommandResult(code:113,data:Data(),timedOut:false)) }
                else if args==["list"] { done(DesktopCommandResult(code:0,data:Data(),timedOut:false)) }
                else { done(DesktopCommandResult(code:1,data:Data(),timedOut:false)) }
            },exists:{$0==binary},digest:{$0==binary ? old : sha},portFree:{true},fixtureStateRoot:refusalRoot,candidateSafe:{_ in true})
            refusal.recover(login:login)
            check(authorized==0 && !refusal.intents.present && (try? refusal.intents.loadRecovery())?.state=="RECOVERY_UNKNOWN","recovery awaiting provenance refusal never authorizes: "+key)
        }
        // Console absence must be proven both by lsof and managed job policy.
        for blockedPolicy in ["listener","managed-job","port-busy"] {
            var commands=[[String]]()
            let policyRefusal=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{ _,args,_,done in
                commands.append(args)
                if args==["desktop","migration-recovery-inspect"] { done(previewResult) }
                else if args.first=="print" { done(DesktopCommandResult(code:blockedPolicy=="managed-job" ? 0 : 113,data:Data(),timedOut:false)) }
                else if args==["list"] { done(DesktopCommandResult(code:0,data:Data(),timedOut:false)) }
                else { done(DesktopCommandResult(code:blockedPolicy=="listener" ? 0 : 1,data:blockedPolicy=="listener" ? Data("p123\nu503\n".utf8) : Data(),timedOut:false)) }
            },exists:{$0==binary},digest:{$0==binary ? old : sha},portFree:{blockedPolicy != "port-busy"},fixtureStateRoot:root.appendingPathComponent("recovery-policy-"+blockedPolicy).path)
            policyRefusal.recover(login:login)
            check(!commands.contains{$0.contains("migration-recovery-commit") || $0.first=="-e"} && !policyRefusal.intents.recoveryPresent,"recovery console policy refuses before durable intent and STOP: "+blockedPolicy)
        }
        let armingRoot=root.appendingPathComponent("recovery-armed-restart").path
        let arming=DesktopIntentStore(home:home,fixtureRoot:armingRoot)
        try arming.saveRecovery(DesktopRecoveryIntent(state:"RECOVERY_ARMED",plan:String(repeating:"d",count:64),recoveryOf:oldOperation,recoveryPlanSHA:oldRawSHA,sha:sha,console:nil,operation:nil))
        var armCommands=[[String]]()
        let armRestart=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{ _,args,_,done in armCommands.append(args); done(DesktopCommandResult(code:1,data:Data(),timedOut:false)) },exists:{$0==binary},digest:{_ in sha},fixtureStateRoot:armingRoot)
        armRestart.initialize(login:login); armRestart.recover(login:login)
        check((try? arming.loadRecovery())?.state=="RECOVERY_UNKNOWN" && armCommands==[["desktop","migration-inspect"]] && !arming.present,"restart of pre-STOP ARMED is sticky UNKNOWN with no replay or forged helper intent")
        let invalidState=root.appendingPathComponent("recovery-invalid-store").path
        let invalidStore=DesktopIntentStore(home:home,fixtureRoot:invalidState)
        try invalidStore.saveRecovery(DesktopRecoveryIntent(state:"RECOVERY_UNKNOWN",plan:String(repeating:"d",count:64),recoveryOf:oldOperation,recoveryPlanSHA:oldRawSHA,sha:sha,console:nil,operation:nil))
        let invalidPath=invalidState+"/recovery.json"
        let invalidSaved=try Data(contentsOf:URL(fileURLWithPath:invalidPath))
        try FileManager.default.setAttributes([.posixPermissions:0o644],ofItemAtPath:invalidPath)
        check((try? invalidStore.loadRecovery())==nil && invalidStore.recoveryPresent,"unsafe recovery JSON mode is HOLD not absent")
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:invalidPath)
        let recoveryAlias=root.appendingPathComponent("recovery-hardlink").path
        check(link(invalidPath,recoveryAlias)==0 && (try? invalidStore.loadRecovery())==nil,"hardlinked recovery JSON refuses authority")
        unlink(recoveryAlias); unlink(invalidPath)
        check(symlink("authorization.json",invalidPath)==0 && (try? invalidStore.loadRecovery())==nil && invalidStore.recoveryPresent,"symlink recovery JSON is sticky HOLD")
        unlink(invalidPath)
        let fifoMade=mkfifo(invalidPath,0o600)==0
        check(fifoMade && (try? invalidStore.loadRecovery())==nil,"FIFO recovery JSON refuses boundedly without blocking read")
        unlink(invalidPath); try invalidSaved.write(to:URL(fileURLWithPath:invalidPath)); chmod(invalidPath,0o600)
        let guardRoot=root.appendingPathComponent("recovery-model-guard").path
        var guardCommands=[[String]](), guardDone: ((DesktopCommandResult)->Void)?
        let guardedRuntime=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{ _,args,_,done in
            guardCommands.append(args)
            if args==["desktop","migration-recovery-inspect"] { guardDone=done }
            else { fatalError("Model guard must refuse before console admission") }
        },exists:{$0==binary},digest:{$0==binary ? old : sha},fixtureStateRoot:guardRoot)
        guardedRuntime.recover(login:login); guardedRuntime.recoveryActionAllowed={false}
        // The async admission fence is checked before dispatching console work.
        guardDone?(previewResult)
        check(guardCommands==[["desktop","migration-recovery-inspect"]] && !guardedRuntime.intents.recoveryPresent,"model policy changing after consent refuses before STOP")
        for (name,raw) in [("duplicate","{\"state\":\"RECOVERY_UNKNOWN\",\"state\":\"DONE\"}"),("escaped duplicate","{\"state\":1,\"st\\u0061te\":2}"),("case alias","{\"state\":1,\"State\":2}")] {
            check(!DesktopIntentStore.uniqueJSONKeys(Data(raw.utf8)),"durable recovery parser rejects "+name)
        }
        check(DesktopIntentStore.uniqueJSONKeys(Data("{\"console\":{\"argv\":[\"a:b\",\"{x}\"],\"pid\":1},\"state\":\"DONE\"}".utf8)),"durable recovery key scanner preserves nested console and quoted punctuation")
        var setupFailureCommands=[[String]]()
        let setupFailure=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{ _,args,_,done in
            setupFailureCommands.append(args)
            if args==["desktop","prepare"] { done(DesktopCommandResult(code:1,data:Data(),timedOut:true)) }
            else { done(DesktopCommandResult(code:1,data:Data(),timedOut:false)) }
        },exists:{$0==binary},digest:{$0==binary ? old : sha},fixtureStateRoot:root.appendingPathComponent("recovery-old-setup-unknown").path)
        setupFailure.initialize(login:login)
        check(setupFailure.blocksQuit && setupFailure.recoveryAllowed,"old setup uncertainty permits only explicit recovery without active durable authority")
        let activeRoot=root.appendingPathComponent("recovery-active-auth").path
        let activeStore=DesktopIntentStore(home:home,fixtureRoot:activeRoot); try activeStore.save(sample)
        var activeDispatches=0
        let activeRuntime=DesktopRuntime(bundle:app.path,home:home,uid:uid,run:{_,_,_,_ in activeDispatches += 1},exists:{$0==binary},digest:{_ in sha},fixtureStateRoot:activeRoot)
        activeRuntime.recover(login:login)
        check(!activeRuntime.recoveryAllowed && activeDispatches==0,"existing helper authorization ARMED refuses explicit recovery before inspection")
        let refreshBefore=lostCalls.count; lostRuntime.refreshRecovery()
        check(Array(lostCalls.dropFirst(refreshBefore))==[["desktop","migration-inspect"]] && (try? lostRuntime.intents.loadRecovery())?.state=="RECOVERY_UNKNOWN","explicit refresh is read-only inspection and preserves recovery UNKNOWN")
        let forbidden=DesktopCommandResult(code:0,data:Data("{\"schema\":1,\"schema\":1}".utf8),timedOut:false)
        check(DesktopMigration.parse(forbidden)==nil,"recovery continuation rejects duplicate metadata keys before Foundation folding")
        try JSONSerialization.data(withJSONObject:["checks":checks,"count":checks.count,"systemAuthorization":"NOT_RUN","productionChanges":false],options:[.prettyPrinted,.sortedKeys]).write(to:root.appendingPathComponent("desktop-checks.json"))
        print("DESKTOP_TESTS_OK checks=\(checks.count)")
    }
}
