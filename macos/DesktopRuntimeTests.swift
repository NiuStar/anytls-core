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
    static func main() throws {
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
        try JSONSerialization.data(withJSONObject:["schema":1,"binary":"anytls-macos","arch":"arm64","version":"fixture","sha256":sha]).write(to:resources.appendingPathComponent("manifest.json"))
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
        result=nil; DesktopProcessRunner.run("/usr/bin/python3",["-c","import os; os.write(1,b'x'*200000); os.write(2,b'y'*200000)"],3) { result=$0 }; pump { result != nil }
        check(result?.code == -1 && result!.data.count<=65536 && result!.stderr.count<=65536 && result?.timedOut==false,"finite stdout stderr flood capped and fully drained")
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
        let manual=Process(); manual.executableURL=URL(fileURLWithPath:adoptionBinary); manual.arguments=["webui","--listen","0.0.0.0","--port","18089"]; try manual.run()
        var adoptionSecrets=0, adoptionLogins=0
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
                let body:[String:Any]=["label":label,"target":"gui/\(getuid())/"+label,"plist":adoptionHome+"/Library/LaunchAgents/"+label+".plist","restartManaged":false,"pid":0]
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
        let member=leaseStore.root+"/unexpected"; FileManager.default.createFile(atPath:member,contents:Data())
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
        try JSONSerialization.data(withJSONObject:["checks":checks,"count":checks.count,"systemAuthorization":"NOT_RUN","productionChanges":false],options:[.prettyPrinted,.sortedKeys]).write(to:root.appendingPathComponent("desktop-checks.json"))
        print("DESKTOP_TESTS_OK checks=\(checks.count)")
    }
}
