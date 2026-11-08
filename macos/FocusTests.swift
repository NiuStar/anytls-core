import AppKit
import ObjectiveC.runtime

// Offline AppKit regression: production launch/render/login; only transport,
// credential storage and OS polling/observers are isolated. No real VPN or WAN.
private enum PresentationProbe {
    static var activations=0, fronts=0, sheets=0, modals=0
    static var lastMessage=""
    static var response: NSApplication.ModalResponse = .alertSecondButtonReturn
    static var counts: [Int] { [activations,fronts,sheets,modals] }
    static func install(_ type: AnyClass, _ a: Selector, _ b: Selector) {
        method_exchangeImplementations(class_getInstanceMethod(type,a)!,class_getInstanceMethod(type,b)!)
    }
}
extension NSApplication {
    @objc func focus_activate(ignoringOtherApps flag: Bool) {
        PresentationProbe.activations += 1 // Never activate the physical user's Mac.
    }
}
extension NSWindow {
    @objc func focus_makeKeyAndOrderFront(_ sender: Any?) {
        PresentationProbe.fronts += 1
        focus_makeKeyAndOrderFront(sender) // Real native visibility, only explicit user fixtures.
    }
}
extension NSAlert {
    @objc func focus_beginSheetModal(for window: NSWindow, completionHandler handler: ((NSApplication.ModalResponse) -> Void)?) {
        PresentationProbe.sheets += 1 // Record a regression without blocking on a modal.
    }
    @objc func focus_runModal() -> NSApplication.ModalResponse {
        PresentationProbe.lastMessage=messageText
        PresentationProbe.modals += 1; return PresentationProbe.response
    }
}
private final class FocusHTTP: URLProtocol {
    static var loginStatus=200, serviceStatus=200, online=false, loginOffline=false
    static var logins=0, requests: [String]=[]
    static let gate=NSLock()
    static var holdStatus=false, held: (() -> Void)?
    static var timeline=[String]()
    static func event(_ text: String) { gate.lock(); timeline.append(text); gate.unlock() }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let path=request.url!.path, probe=request.url!.scheme == "https"
        let login=path.hasSuffix("/login")
        Self.requests.append(path); if login { Self.logins += 1 }
        if login && Self.loginOffline { client?.urlProtocol(self,didFailWithError:URLError(.notConnectedToInternet)); return }
        let status=probe ? (Self.online ? 204 : 503) : login ? Self.loginStatus : Self.serviceStatus
        var body: [String:Any]=[:]
        if login { body=["csrf":String(repeating:"t",count:43),"expiresIn":3600] }
        else if path.hasSuffix("/status") { body=["availability":"AVAILABLE","loaded":true,"running":true,"available":true,"version":"fixture","listenHost":"0.0.0.0"] }
        else if path.hasSuffix("/nodes") { body=["nodes":[],"etag":"\""+String(repeating:"a",count:64)+"\""] }
        let data=probe ? Data() : try! JSONSerialization.data(withJSONObject:body)
        let deliver: () -> Void = {
            Self.event("deliver " + path)
            self.client?.urlProtocol(self,didReceive:HTTPURLResponse(url:self.request.url!,statusCode:status,httpVersion:nil,headerFields:nil)!,cacheStoragePolicy:.notAllowed)
            if !data.isEmpty { self.client?.urlProtocol(self,didLoad:data) }
            self.client?.urlProtocolDidFinishLoading(self)
        }
        Self.gate.lock()
        if Self.holdStatus && path == "/api/v1/status" { Self.held=deliver; Self.timeline.append("held " + path); Self.gate.unlock(); return }
        Self.gate.unlock()
        DispatchQueue.global().asyncAfter(deadline:.now()+(login ? 0.12 : 0.01),execute:deliver)
    }
    override func stopLoading() {}
}
@main struct FocusTests {
    static var checks=[String](), delegates=[AppDelegate](), children=[Process]()
    static func check(_ ok: @autoclosure ()->Bool,_ name: String) { guard ok() else { print("FAIL: "+name); for child in children where child.isRunning { child.terminate(); child.waitUntilExit() }; exit(1) }; checks.append(name); print("PASS: "+name) }
    static func pump(_ duration: Double=0.12) { RunLoop.main.run(until:Date().addingTimeInterval(duration)) }
    static func wait(_ name: String,_ ready: ()->Bool) { let end=Date().addingTimeInterval(5); while !ready() && Date()<end { pump(0.02) }; check(ready(),name) }
    static func config()->URLSessionConfiguration { let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[FocusHTTP.self]; return c }
    static var root: URL!
    static var tick=Date()
    static func launch(missing: Bool=false)->AppDelegate {
        let dir=root.appendingPathComponent(UUID().uuidString), bundle=dir.appendingPathComponent("Fixture.app")
        let resource=bundle.appendingPathComponent("Contents/Resources/runtime")
        try! FileManager.default.createDirectory(at:resource,withIntermediateDirectories:true)
        let sha=String(repeating:"a",count:64), home="/Users/owned fixture", uid=503, binary=home+"/.anytls/anytls-macos", config=home+"/.anytls/config.yaml"
        try! JSONSerialization.data(withJSONObject:["schema":1,"binary":"anytls-macos","arch":DesktopRuntime.runtimeArchitecture,"version":"fixture","sha256":sha]).write(to:resource.appendingPathComponent("manifest.json"))
        var child: Process?
        let runner: DesktopRuntime.Runner={ _,args,_,done in
            var body: [String:Any]=[:]; var code: Int32=0
            if args==["desktop","inspect"] { body=["schema":1,"version":"fixture","binary":binary,"config":config,"config_identity":DesktopRuntime.sum(Data(config.utf8)),"binary_sha256":sha,"endpoint":"http://127.0.0.1:18089","listen":"0.0.0.0","port":18089,"uid":uid,"home":home,"helper_state":"ready"] }
            else if args==["desktop","credentials"] { body=["schema":1,"endpoint":"http://127.0.0.1:18089","password":"OWNED_SYNTHETIC_ONLY"] }
            else if args.first=="print" { code=113 }
            else if args==["list"] { done(DesktopCommandResult(code:0,data:Data(),timedOut:false)); return }
            else if args.contains("-a"), let p=child { done(DesktopCommandResult(code:0,data:Data("p\(p.processIdentifier)\nu\(uid)\nn*:18089\n".utf8),timedOut:false)); return }
            else { code=1 }
            done(DesktopCommandResult(code:code,data:code==1 ? Data() : try! JSONSerialization.data(withJSONObject:body),timedOut:false))
        }
        let runtime=DesktopRuntime(bundle:bundle.path,home:home,uid:uid,run:runner,exists:{ !missing && $0==binary },digest:{_ in sha},portFree:{true},fixtureStateRoot:dir.appendingPathComponent("state").path,candidateSafe:{_ in true})
        runtime.launchConsole={ let p=Process(); p.executableURL=URL(fileURLWithPath:"/bin/sleep"); p.arguments=["60"]; child=p; children.append(p); return p }
        let model=MenuModel(api:APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:49173"),configuration:Self.config),connectivityMonitor:ConnectivityMonitor(configuration:Self.config))
        let ui=AppDelegate(model:model); ui.desktop=runtime; ui.now={tick}; delegates.append(ui)
        ui.applicationDidFinishLaunching(Notification(name:NSApplication.didFinishLaunchingNotification)); return ui
    }
    static var baselineWindows=Set<Int>()
    static func contentWindows()->[NSWindow] {
        NSApp.windows.filter { window in
            !baselineWindows.contains(window.windowNumber) && !delegates.contains { ui in
                window === ui.item?.button?.window && NSStringFromClass(type(of:window)) == "NSStatusBarWindow" && !window.isKeyWindow
            }
        }
    }
    static func quiet(_ ui: AppDelegate,_ name: String) {
        pump(); check(PresentationProbe.counts == [0,0,0,0],name+" zero activation/front/sheet/modal")
        check(contentWindows().isEmpty,name+" zero application content windows (owned framework status host excluded)")
    }
    static func main() throws {
        root=URL(fileURLWithPath:CommandLine.arguments[1]); try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        let app=NSApplication.shared; app.setActivationPolicy(.accessory); app.finishLaunching()
        baselineWindows=Set(app.windows.map { $0.windowNumber })
        PresentationProbe.install(NSApplication.self,#selector(NSApplication.activate(ignoringOtherApps:)),#selector(NSApplication.focus_activate(ignoringOtherApps:)))
        PresentationProbe.install(NSWindow.self,#selector(NSWindow.makeKeyAndOrderFront(_:)),#selector(NSWindow.focus_makeKeyAndOrderFront(_:)))
        PresentationProbe.install(NSAlert.self,#selector(NSAlert.beginSheetModal(for:completionHandler:)),#selector(NSAlert.focus_beginSheetModal(for:completionHandler:)))
        PresentationProbe.install(NSAlert.self,#selector(NSAlert.runModal),#selector(NSAlert.focus_runModal))
        let fresh=launch(missing:true); quiet(fresh,"uninitialized startup")
        autoreleasepool {
            let hidden=NSWindow(contentRect:NSRect(x:0,y:0,width:570,height:410),styleMask:[.titled,.closable],backing:.buffered,defer:false)
            hidden.isReleasedWhenClosed=false
            check(contentWindows().contains { $0 === hidden },"negative control detects even a hidden ordinary NSWindow")
            hidden.close()
        }
        quiet(fresh,"after hidden-window negative control")
        check(fresh.item.button!.toolTip!.contains("组件待初始化"),"fresh menu explains explicit native installation")
        check(!fresh.item.menu!.items.contains { $0.title.contains("登录") || $0.title.contains("连接设置") || $0.title.contains("记住") },"manual app login menu removed rather than hidden")
        let saved=launch(); wait("private pipe automatic startup authenticates") {saved.model.api.authenticated && saved.desktop?.busy==false}
        wait("offline connectivity verdict retained") {saved.model.connectivity == .offline}; quiet(saved,"authenticated offline startup")
        check(saved.speedView.icon.contentTintColor == NSColor.systemRed,"offline indication stays red")
        check(saved.item.button!.toolTip!.contains("网络连接失败"),"offline menu stays actionable")
        for _ in 0..<4 {saved.model.tick(); saved.model.connectivityMonitor!.check(force:true); pump()}; quiet(saved,"background ticks")
        FocusHTTP.online=true; saved.model.connectivityMonitor!.check(force:true)
        wait("connectivity recovers") {saved.model.connectivity == .online}; quiet(saved,"network recovery")
        saved.model.environmentChanged(sleeping:true); quiet(saved,"sleep")
        saved.model.environmentChanged(); quiet(saved,"wake")
        saved.model.environmentChanged(); quiet(saved,"path change")
        check(!saved.applicationShouldHandleReopen(app,hasVisibleWindows:false),"Finder reopen never requests a window"); quiet(saved,"reopen")
        tick=tick.addingTimeInterval(16); FocusHTTP.serviceStatus=401; saved.model.refresh()
        wait("401 expires session") {!saved.model.api.authenticated}; pump(0.4); quiet(saved,"expiry")
        let failedCount=FocusHTTP.logins
        for _ in 0..<20 {saved.model.tick(); saved.sessionExpired()}; pump(0.3)
        check(FocusHTTP.logins==failedCount,"expiry failure never becomes 250ms login loop")
        FocusHTTP.serviceStatus=200
        for status in [401,429] {
            FocusHTTP.loginStatus=status; let ui=launch(); wait("HTTP \(status) failure completed") {ui.desktop?.busy==false}
            let count=FocusHTTP.logins; for _ in 0..<10 {ui.model.tick(); ui.sessionExpired(); ui.connectRuntime()}; pump(0.3)
            check(FocusHTTP.logins==count,"HTTP \(status) cooldown and singleflight"); quiet(ui,"HTTP \(status) failure")
        }
        FocusHTTP.loginStatus=200
        FocusHTTP.loginOffline=true; let disconnected=launch()
        wait("offline app session failure completes") { disconnected.desktop?.busy==false }
        quiet(disconnected,"transport offline"); let offlineCount=FocusHTTP.logins
        for _ in 0..<12 { disconnected.model.tick(); disconnected.connectRuntime() }; pump(0.2)
        check(FocusHTTP.logins==offlineCount,"offline transport never loops application authentication")
        FocusHTTP.loginOffline=false
        tick=tick.addingTimeInterval(16); saved.refresh()
        wait("explicit refresh reconnects verified runtime") {saved.model.api.authenticated && saved.desktop?.busy==false}; quiet(saved,"reconnection")
        // Exact production delayed migration callback is now status-only, even
        // when called after fresh authenticated stopped status becomes available.
        saved.desktop?.onMigrationResume?(); pump(0.5)
        check(saved.pendingMigrationResume,"late migration records pending user action"); quiet(saved,"late migration completion")
        check(saved.item.menu!.items.contains {$0.title=="恢复 VPN…"},"pending resume appears in status menu")
        saved.desktop?.onMigrationResume?(); saved.model.tick(); pump(0.3); quiet(saved,"repeated stale migration callback")
        check(!FocusHTTP.requests.contains {$0.contains("/service/") || $0.contains("/selection")},"all background paths send zero VPN mutations")
        // Real production menu action: explicit Continue, then held asynchronous
        // admission failure. Swizzles suppress the physical modal/activation.
        let installUI=launch(missing:true)
        let fixtureRuntime=installUI.desktop!
        var installCommands=[[String]](), inspectDone: ((DesktopCommandResult)->Void)?
        let installRuntime=DesktopRuntime(bundle:fixtureRuntime.bundle,home:fixtureRuntime.home,uid:fixtureRuntime.uid,run:{ _,args,_,done in
            installCommands.append(args)
            if args==["desktop","prepare"] { done(DesktopCommandResult(code:1,data:Data("{\"error\":\"UPDATE_REQUIRED\"}".utf8),timedOut:false)) }
            else if args==["desktop","migration-inspect"] { inspectDone=done }
            else { fatalError("Installation refusal must not mutate or authorize") }
        },exists:{$0==fixtureRuntime.binary},digest:{_ in String(repeating:"a",count:64)},fixtureStateRoot:root.appendingPathComponent("install-feedback").path,candidateSafe:{_ in true})
        installUI.desktop=installRuntime; installRuntime.onChange={ [weak installUI] in installUI?.render() }; installUI.render()
        func installRow()->NSMenuItem { installUI.item.menu!.items.first {$0.action == #selector(AppDelegate.initializeDesktop)}! }
        PresentationProbe.response = .alertFirstButtonReturn
        let dispatched=autoreleasepool { NSApp.sendAction(installRow().action!,to:installRow().target,from:installRow()) }
        check(dispatched,"installation Continue dispatches actual production menu action")
        PresentationProbe.response = .alertSecondButtonReturn
        check(inspectDone != nil && installRuntime.busy && PresentationProbe.counts == [1,0,0,1],"Continue starts read-only inspection with only immediate explicit confirmation")
        PresentationProbe.activations=0; PresentationProbe.modals=0
        inspectDone?(DesktopCommandResult(code:1,data:Data("{\"error\":\"CORE_RELOAD_PENDING\",\"detail\":\"PRIVATE_SENTINEL\"}".utf8),timedOut:false))
        check(installRuntime.message.contains("旧重载事务尚未完成或回执无法验证（CORE_RELOAD_PENDING）") && !installRuntime.busy,"Continue failure exposes allowlisted migration reason")
        check(installUI.item.button!.toolTip!.contains(installRuntime.message) && installUI.item.menu!.items.contains {$0.title==installRuntime.message},"installation failure retained in menu and tooltip")
        check(!installRuntime.message.contains("PRIVATE_SENTINEL") && installCommands == [["desktop","prepare"],["desktop","migration-inspect"]],"installation refusal reveals no raw output and sends zero STOP authorization or credentials")
        quiet(installUI,"asynchronous installation refusal")
        // Prove a real read-owner collision separately from the pending contract.
        // The APIClient completion barrier below owns no production state: each
        // sentinel must be admitted and completed through the actual transport.
        func savedInstallRow()->NSMenuItem { saved.item.menu!.items.first {$0.action == #selector(AppDelegate.initializeDesktop)}! }
        func settled(_ ready: ()->Bool) -> Bool {
            let end=Date().addingTimeInterval(5)
            while !ready() && Date()<end { pump(0.02) }
            return ready()
        }
        func heldResponse()->(() -> Void)? {
            FocusHTTP.gate.lock(); defer { FocusHTTP.gate.unlock() }; return FocusHTTP.held
        }
        func drainReads()->Bool {
            let paths=["/status","/helper/status","/nodes","/traffic"]
            var sent=Set<String>(), completed=Set<String>()
            return settled {
                for path in paths where !sent.contains(path) {
                    if saved.model.api.request(path,completion:{ _ in completed.insert(path) }) { sent.insert(path) }
                }
                return completed.count == paths.count
            }
        }
        let initiallyDrained=drainReads()
        guard initiallyDrained else { check(false,"fixture prior owned reads drain"); return }
        let context=saved.model.quitContext!
        FocusHTTP.gate.lock(); FocusHTTP.holdStatus=true; FocusHTTP.held=nil; FocusHTTP.gate.unlock()
        saved.model.refresh()
        guard settled({ heldResponse() != nil }) else { check(false,"fixture refresh status held"); return }
        var collisionOutcomes=[QuitOutcome]()
        FocusHTTP.event("collision before pending=\(saved.model.pending) row=\(savedInstallRow().isEnabled)")
        saved.model.beginQuit(context:context) { collisionOutcomes.append($0) }
        let collisionBlocked=collisionOutcomes == [.blocked] && !saved.model.pending && !saved.model.uncertain && savedInstallRow().isEnabled
        FocusHTTP.event("collision after pending=\(saved.model.pending) row=\(savedInstallRow().isEnabled) outcomes=\(collisionOutcomes)")
        // External native mutation leaves the identical controlled refresh held,
        // restoring the old fixture assumption without changing product code.
        let restoreCollision=ProcessInfo.processInfo.environment["FOCUS_RESTORE_OWNER_COLLISION"] == "1"
        var priorReadsDrained=false
        if !restoreCollision {
            FocusHTTP.gate.lock(); FocusHTTP.holdStatus=false; let release=FocusHTTP.held; FocusHTTP.held=nil; FocusHTTP.gate.unlock()
            release?()
            priorReadsDrained=drainReads()
            guard priorReadsDrained else { check(false,"fixture all prior owned reads drain"); return }
        }
        FocusHTTP.gate.lock(); FocusHTTP.holdStatus=true; FocusHTTP.gate.unlock()
        var quitOutcomes=[QuitOutcome]()
        saved.model.beginQuit(context:context) { quitOutcomes.append($0) }
        FocusHTTP.event("pending before assertion pending=\(saved.model.pending) row=\(savedInstallRow().isEnabled) outcomes=\(quitOutcomes)")
        try JSONSerialization.data(withJSONObject:FocusHTTP.timeline,options:.prettyPrinted).write(to:root.appendingPathComponent("timeline.json"))
        check(saved.model.pending && !savedInstallRow().isEnabled,"pending operation disables installation menu")
        saved.initializeDesktop()
        check(saved.connectionMessage.contains("当前操作进行中") && PresentationProbe.counts == [0,0,0,0],"stale pending install action explains refusal without dispatch")
        let quitResponseHeld=settled { heldResponse() != nil }
        saved.model.abandonQuit(context:context)
        let requestsBeforeLate=FocusHTTP.requests.count
        FocusHTTP.gate.lock(); FocusHTTP.holdStatus=false; FocusHTTP.gate.unlock()
        let lateResponse=heldResponse(); lateResponse?()
        let lateOwnerDrained=drainReads()
        let lateFenced=quitOutcomes.isEmpty && saved.model.uncertain && !saved.model.pending
        FocusHTTP.event("late response fenced=\(lateFenced) drained=\(lateOwnerDrained)")
        check(saved.model.uncertain && !savedInstallRow().isEnabled,"unknown result disables installation menu")
        saved.initializeDesktop()
        check(saved.connectionMessage.contains("当前操作结果未知") && saved.connectionMessage.contains("未开始安装") && PresentationProbe.counts == [0,0,0,0],"stale unknown install action explains refusal without retry")
        quiet(saved,"pending and unknown installation refusal")
        for ui in delegates {ui.applicationWillTerminate(Notification(name:NSApplication.willTerminateNotification)); NSStatusBar.system.removeStatusItem(ui.item)}
        for child in children where child.isRunning {child.terminate(); child.waitUntilExit()}
        check(children.allSatisfy {!$0.isRunning},"all owned fixture children reaped")
        check(initiallyDrained && priorReadsDrained,"all prior API read owners complete before pending scenario")
        check(collisionBlocked,"outstanding status owner blocks quit without claiming pending")
        check(quitResponseHeld,"pending quit owns an actual held API preflight response")
        check(lateOwnerDrained && lateFenced,"abandoned quit fences the released late preflight completion")
        check(!FocusHTTP.requests.dropFirst(requestsBeforeLate).contains {$0.contains("/service/")} && !FocusHTTP.requests.contains {$0.contains("/service/")},"controlled collision and late quit completion send zero STOP")
        check(PresentationProbe.counts == [0,0,0,0] && installCommands == [["desktop","prepare"],["desktop","migration-inspect"]],"controlled quit never authorizes installs or activates UI")
        try JSONSerialization.data(withJSONObject:FocusHTTP.timeline,options:.prettyPrinted).write(to:root.appendingPathComponent("timeline.json"))
        // Append recovery action composition after the complete Focus73 prefix.
        let recoveryUI=launch(missing:true), fixture=recoveryUI.desktop!
        var recoveryCommands=[[String]](), recoveryDone: ((DesktopCommandResult)->Void)?
        let recovery=DesktopRuntime(bundle:fixture.bundle,home:fixture.home,uid:fixture.uid,run:{ _,args,_,done in
            recoveryCommands.append(args)
            if args==["desktop","migration-recovery-inspect"] { recoveryDone=done }
            else { fatalError("Invalid preview must not dispatch STOP or authorization") }
        },exists:{$0==fixture.binary},digest:{_ in String(repeating:"a",count:64)},fixtureStateRoot:root.appendingPathComponent("recovery-action").path,candidateSafe:{_ in true})
        recoveryUI.desktop=recovery; recovery.onChange={ [weak recoveryUI] in recoveryUI?.render() }; recoveryUI.render()
        let selector=NSSelectorFromString("recoverDesktop")
        check(recoveryUI.responds(to:selector),"recovery production selector exists")
        func recoveryRow()->NSMenuItem { recoveryUI.item.menu!.items.first {$0.action==selector}! }
        check(recoveryRow().title=="恢复未完成的组件更新…" && recoveryRow().isEnabled,"explicit recovery menu is provisionally enabled without mutation")
        PresentationProbe.response = .alertSecondButtonReturn
        let cancelled=autoreleasepool { NSApp.sendAction(selector,to:recoveryUI,from:recoveryRow()) }
        check(cancelled && PresentationProbe.counts == [1,0,0,1] && recoveryCommands.isEmpty && !recovery.intents.recoveryPresent && !recovery.intents.present,"native recovery Cancel has zero commands STOP authorization or durable intent")
        PresentationProbe.activations=0; PresentationProbe.modals=0
        PresentationProbe.response = .alertFirstButtonReturn
        let continued=autoreleasepool { NSApp.sendAction(selector,to:recoveryUI,from:recoveryRow()) }
        check(continued && recovery.busy && recoveryDone != nil && recoveryCommands==[["desktop","migration-recovery-inspect"]] && PresentationProbe.counts == [1,0,0,1],"native recovery Continue immediately consents before held read-only inspection")
        PresentationProbe.activations=0; PresentationProbe.modals=0
        recoveryUI.recoverDesktop()
        check(recoveryCommands.count==1 && PresentationProbe.counts == [0,0,0,0] && !recoveryRow().isEnabled,"repeated busy recovery click cannot prompt or dispatch a second STOP")
        recoveryDone?(DesktopCommandResult(code:1,data:Data("{\"error\":\"PRIVATE_SENTINEL\"}".utf8),timedOut:false))
        check(!recovery.busy && recovery.message.contains("未停止 VPN") && !recovery.message.contains("PRIVATE_SENTINEL") && recoveryCommands.count==1,"delayed recovery inspection refusal is bounded nonsecret and mutation free")
        quiet(recoveryUI,"delayed recovery refusal")
        check(recoveryUI.item.button!.toolTip!.contains(recovery.message) && recoveryUI.item.menu!.items.contains {$0.title==recovery.message},"recovery failure persists in actual menu and tooltip")
        let savedRecovery=saved.item.menu!.items.first {$0.action==selector}!
        check(!savedRecovery.isEnabled,"model UNKNOWN disables recovery despite runtime setup eligibility")
        saved.recoverDesktop()
        check(PresentationProbe.counts == [0,0,0,0],"stale model UNKNOWN recovery action never prompts or mutates")
        check(PresentationProbe.lastMessage.contains("独立事务") && PresentationProbe.lastMessage.contains("旧 UNKNOWN") && PresentationProbe.lastMessage.contains("中断") && PresentationProbe.lastMessage.contains("不会自动重试或启动"),"owned native recovery alert discloses independent STOP retained UNKNOWN interruption and no retry or start")
        var uiSTOPs=0, uiDurable=false, uiCommitDone: ((DesktopCommandResult)->Void)?
        let durableUIRoot=root.appendingPathComponent("recovery-action-durable").path
        let oldSHA=String(repeating:"c",count:64), bundleSHA=String(repeating:"a",count:64), oldOp=String(repeating:"e",count:64), rawSHA=String(repeating:"f",count:64), plan=String(repeating:"d",count:64)
        let preview:[String:Any]=["schema":1,"phase":"RECOVERY_INSPECTED","plan":plan,"binary":fixture.binary,"config":fixture.config,"config_identity":DesktopRuntime.sum(Data(fixture.config.utf8)),"binary_sha256":bundleSHA,"old_binary_sha256":oldSHA,"helper_sha256":oldSHA,"helper_version":"old","uid":fixture.uid,"home":fixture.home,"was_running":false,"recovery_of":oldOp,"recovery_plan_sha256":rawSHA]
        let uiRuntime=DesktopRuntime(bundle:fixture.bundle,home:fixture.home,uid:fixture.uid,run:{ _,args,_,done in
            if args==["desktop","migration-recovery-inspect"] { done(DesktopCommandResult(code:0,data:try! JSONSerialization.data(withJSONObject:preview),timedOut:false)) }
            else if args==["desktop","migration-recovery-commit",plan] {
                uiSTOPs += 1
                let store=DesktopIntentStore(home:fixture.home,fixtureRoot:durableUIRoot)
                uiDurable=(try? store.loadRecovery())?.state=="RECOVERY_ARMED" && !store.present
                uiCommitDone=done
            }
            else if args.first=="print" { done(DesktopCommandResult(code:113,data:Data(),timedOut:false)) }
            else if args==["list"] { done(DesktopCommandResult(code:0,data:Data(),timedOut:false)) }
            else { done(DesktopCommandResult(code:1,data:Data(),timedOut:false)) }
        },exists:{$0==fixture.binary},digest:{$0==fixture.binary ? oldSHA : bundleSHA},portFree:{true},fixtureStateRoot:durableUIRoot)
        recoveryUI.desktop=uiRuntime; uiRuntime.onChange={ [weak recoveryUI] in recoveryUI?.render() }; recoveryUI.render()
        PresentationProbe.response = .alertFirstButtonReturn
        _=autoreleasepool { NSApp.sendAction(selector,to:recoveryUI,from:recoveryRow()) }
        check(uiSTOPs==1 && uiDurable && uiCommitDone != nil && PresentationProbe.counts == [1,0,0,1],"actual production recovery selector persists durable pre-STOP intent before commit")
        PresentationProbe.activations=0; PresentationProbe.modals=0
        recoveryUI.recoverDesktop()
        check(uiSTOPs==1 && PresentationProbe.counts == [0,0,0,0],"actual production repeated recovery selector cannot send duplicate STOP")
        uiCommitDone?(DesktopCommandResult(code:1,data:Data(),timedOut:true))
        recoveryUI.recoverDesktop()
        check(uiSTOPs==1 && !uiRuntime.intents.present && (try? uiRuntime.intents.loadRecovery())?.state=="RECOVERY_UNKNOWN","actual production timeout keeps recovery UNKNOWN and zero authorization")
        quiet(recoveryUI,"delayed recovery STOP timeout")
        recoveryUI.applicationWillTerminate(Notification(name:NSApplication.willTerminateNotification)); NSStatusBar.system.removeStatusItem(recoveryUI.item)
        try JSONSerialization.data(withJSONObject:["checks":checks,"count":checks.count,"presentationCounts":PresentationProbe.counts,"realNetworkRequests":0,"productionKeychainAccessed":false,"osPollingObserversDisabledInFixture":true],options:[.prettyPrinted,.sortedKeys]).write(to:root.appendingPathComponent("focus-checks.json"))
        print("FOCUS_TESTS_OK checks=\(checks.count)")
    }
}
