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
    static var nodeNames=[String](), heldProbes=[() -> Void]()
    // The two URLProtocol startLoading calls are independent. Expose the first
    // completion owner before the second, across the real event-tracking tick.
    static var splitProbeAdmission=false, probeAdmissions=0
    static var deferredProbe: (() -> Void)?
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
        else if path.hasSuffix("/nodes") { body=["nodes":Self.nodeNames.map { ["name":$0,"selectable":true,"selected":false,"skipVerify":false] },"etag":"\""+String(repeating:"a",count:64)+"\""] }
        let data=probe ? Data() : try! JSONSerialization.data(withJSONObject:body)
        let deliver: () -> Void = {
            Self.event("deliver " + path)
            self.client?.urlProtocol(self,didReceive:HTTPURLResponse(url:self.request.url!,statusCode:status,httpVersion:nil,headerFields:nil)!,cacheStoragePolicy:.notAllowed)
            if !data.isEmpty { self.client?.urlProtocol(self,didLoad:data) }
            self.client?.urlProtocolDidFinishLoading(self)
        }
        Self.gate.lock()
        if path == "/api/v1/nodes/probe" {
            Self.probeAdmissions += 1
            if Self.splitProbeAdmission && Self.probeAdmissions == 2 { Self.deferredProbe=deliver }
            else { Self.heldProbes.append(deliver) }
            Self.gate.unlock(); return
        }
        if Self.holdStatus && path == "/api/v1/status" { Self.held=deliver; Self.timeline.append("held " + path); Self.gate.unlock(); return }
        Self.gate.unlock()
        DispatchQueue.global().asyncAfter(deadline:.now()+(login ? 0.12 : 0.01),execute:deliver)
    }
    override func stopLoading() {}
}
extension NSStatusBar {
    @objc func focus_statusItem(withLength length: CGFloat)->NSStatusItem {
        let before=Set(NSApp.windows.map { ObjectIdentifier($0) })
        // This swizzled call is only the real AppKit status-item factory. Pump
        // before returning to production, so no delegate UI runs in this scope.
        let item=focus_statusItem(withLength:length)
        let button=item.button // Force lazy AppKit host creation inside this scope.
        let host=button?.window
        RunLoop.main.run(until:Date().addingTimeInterval(0.5))
        let created=NSApp.windows.filter { !before.contains(ObjectIdentifier($0)) }
        guard created.allSatisfy({ NSStringFromClass(type(of:$0)) == "NSStatusBarWindow" && !$0.isKeyWindow }),
              let host=host,
              (created+FocusTests.calibratedHosts).contains(where:{ $0 === host }) else {
            fatalError("status-item factory did not establish exact owned hosts")
        }
        FocusTests.calibratedHosts.append(contentsOf:created)
        return item
    }
}
@main struct FocusTests {
    static var checks=[String](), delegates=[AppDelegate](), children=[Process]()
    static func check(_ ok: @autoclosure ()->Bool,_ name: String) { guard ok() else { print("FAIL: "+name); for child in children where child.isRunning { child.terminate(); child.waitUntilExit() }; exit(1) }; checks.append(name); print("PASS: "+name) }
    @MainActor static func pump(_ duration: Double=0.12) async { try! await Task.sleep(nanoseconds:UInt64(duration * 1_000_000_000)) }
    @MainActor static func wait(_ name: String,_ ready: ()->Bool) async {
        let end=Date().addingTimeInterval(5); while !ready() && Date()<end { await pump(0.02) }
        if !ready() {
            let rows=delegates.map { ["connection":$0.connectionMessage,"runtime":$0.desktop?.message ?? "nil","busy":String($0.desktop?.busy ?? false),"initializing":String($0.model.initializingConnection),"model":$0.model.message,"auth":String($0.model.api.authenticated)] }
            try? JSONSerialization.data(withJSONObject:["wait":name,"delegates":rows,"requests":FocusHTTP.requests,"timeline":FocusHTTP.timeline],options:[.prettyPrinted,.sortedKeys]).write(to:root.appendingPathComponent("wait-failure.json"))
        }
        check(ready(),name)
    }
    static func config()->URLSessionConfiguration { let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[FocusHTTP.self]; return c }
    static var root: URL!
    static var tick=Date()
    static var heldInspection: ((DesktopCommandResult)->Void)?
    static var holdInspection=false
    static var lastInspectResult: DesktopCommandResult?
    static var launchCommands=[[String]]()
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
            launchCommands.append(args)
            let result=DesktopCommandResult(code:code,data:code==1 ? Data() : try! JSONSerialization.data(withJSONObject:body),timedOut:false)
            if args==["desktop","inspect"] {
                lastInspectResult=result
                if holdInspection { heldInspection=done; return }
            }
            done(result)
        }
        let runtime=DesktopRuntime(bundle:bundle.path,home:home,uid:uid,run:runner,exists:{ !missing && $0==binary },digest:{_ in sha},portFree:{true},fixtureStateRoot:dir.appendingPathComponent("state").path,candidateSafe:{_ in true})
        runtime.launchConsole={ let p=Process(); p.executableURL=URL(fileURLWithPath:"/bin/sleep"); p.arguments=["60"]; child=p; children.append(p); return p }
        let model=MenuModel(api:APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:49173"),configuration:Self.config),connectivityMonitor:ConnectivityMonitor(configuration:Self.config))
        let ui=AppDelegate(model:model); ui.desktop=runtime; ui.now={tick}; delegates.append(ui)
        ui.applicationDidFinishLaunching(Notification(name:NSApplication.didFinishLaunchingNotification))
        hostsReused = hostsReused && (ui.item?.button?.window.map { window in calibratedHosts.contains { $0 === window } } ?? false)
        return ui
    }
    // Test-only factory attribution: retain the exact windows made by each
    // real status-item call, before any subsequent production UI can run.
    static var statusCalibration: NSStatusItem?
    static var calibratedHosts=[NSWindow]()
    static var hostsReused=true
    static var baselineWindows=Set<Int>()
    static func calibrateStatusHosts() {
        autoreleasepool {
            let hidden=NSWindow(contentRect:NSRect(x:0,y:0,width:80,height:40),styleMask:.borderless,backing:.buffered,defer:false)
            hidden.isReleasedWhenClosed=false; hidden.level = .statusBar
            statusCalibration=NSStatusBar.system.statusItem(withLength:1)
            RunLoop.main.run(until:Date().addingTimeInterval(0.12))
            guard contentWindows().contains(where:{ $0 === hidden }) else {
                fatalError("status-item attribution swallowed preexisting hidden content window")
            }
            hidden.close()
        }
        guard !calibratedHosts.isEmpty,
              calibratedHosts.allSatisfy({ NSStringFromClass(type(of:$0)) == "NSStatusBarWindow" && !$0.isKeyWindow }),
              calibratedHosts.contains(where:{ $0 === statusCalibration?.button?.window }) else {
            fatalError("status-item calibration did not establish exact owned hosts")
        }
        recordOwnedWindows("status-item calibration before production UI")
    }
    static func ownedStatusHost(_ window: NSWindow)->Bool {
        let original=delegates.contains { window === $0.item?.button?.window }
        let calibrated=calibratedHosts.contains { $0 === window }
        let restore=ProcessInfo.processInfo.environment["FOCUS_RESTORE_BUTTON_ONLY_HOST"] == "1"
        return (restore ? original : calibrated) && NSStringFromClass(type(of:window)) == "NSStatusBarWindow" && !window.isKeyWindow
    }
    static func contentWindows()->[NSWindow] {
        NSApp.windows.filter { window in
            !baselineWindows.contains(window.windowNumber) && !ownedStatusHost(window)
        }
    }
    static func recordOwnedWindows(_ phase: String) {
        // Only NSApp's own objects: no desktop/window-server enumeration.
        let rows: [[String:Any]]=NSApp.windows.map { window in
            var chain=[String](), type: AnyClass?=Swift.type(of:window)
            while let cls=type { chain.append(NSStringFromClass(cls)); type=class_getSuperclass(cls) }
            let owned=delegates.contains { window === $0.item?.button?.window }
            let exactClass=NSStringFromClass(Swift.type(of:window)) == "NSStatusBarWindow"
            return ["object":String(describing:ObjectIdentifier(window)),"number":window.windowNumber,
                    "classes":chain,"key":window.isKeyWindow,"main":window.isMainWindow,"visible":window.isVisible,
                    "level":window.level.rawValue,"style":window.styleMask.rawValue,
                    "baselineNumberMatch":baselineWindows.contains(window.windowNumber),"ownedButtonWindowMatch":owned,
                    "exactClassMatch":exactClass,"nonKey":!window.isKeyWindow,
                    "calibratedHostIdentity":calibratedHosts.contains { $0 === window },
                    "includedAsContent":contentWindows().contains { $0 === window }]
        }
        let owners: [[String:Any]]=delegates.map { ui in
            ["desktopPresent":ui.desktop != nil,"itemPresent":ui.item != nil,"buttonPresent":ui.item?.button != nil,
             "buttonWindow":ui.item?.button?.window.map { String(describing:ObjectIdentifier($0)) } ?? "nil"]
        }
        let data: [String:Any]=["phase":phase,"windows":rows,"owners":owners,"presentationCounts":PresentationProbe.counts,"screenCount":NSScreen.screens.count]
        if let bytes=try? JSONSerialization.data(withJSONObject:data,options:[.sortedKeys]),
           let stream=try? FileHandle(forWritingTo:root.appendingPathComponent("owned-windows.jsonl")) {
            stream.seekToEndOfFile(); stream.write(bytes); stream.write(Data([10])); stream.closeFile()
        } else if let bytes=try? JSONSerialization.data(withJSONObject:data,options:[.sortedKeys]) {
            try? (bytes+Data([10])).write(to:root.appendingPathComponent("owned-windows.jsonl"))
        }
    }
    @MainActor static func quiet(_ ui: AppDelegate,_ name: String) async {
        await pump()
        hostsReused = hostsReused && NSApp.windows.filter { NSStringFromClass(type(of:$0)) == "NSStatusBarWindow" }.allSatisfy { window in calibratedHosts.contains { $0 === window } }
        hostsReused = hostsReused && delegates.allSatisfy { ui in ui.item?.button?.window.map { window in calibratedHosts.contains { $0 === window } } ?? false }
        recordOwnedWindows(name)
        check(PresentationProbe.counts == [0,0,0,0],name+" zero activation/front/sheet/modal")
        check(contentWindows().isEmpty,name+" zero application content windows (owned framework status host excluded)")
    }
    // AppKit menu teardown can stop the main run loop while the fixture task
    // is suspended. Own that loop until the task finishes rather than letting
    // async-main's drain routine mistake a run-loop return for completion.
    @MainActor static func main() {
        var outcome: Int32?
        Task { @MainActor in
            do { try await run(); outcome=0 }
            catch { fputs("FAIL: Focus fixture threw\n",stderr); outcome=1 }
            CFRunLoopStop(CFRunLoopGetMain())
        }
        while outcome == nil { CFRunLoopRun() }
        exit(outcome!)
    }

    @MainActor static func closedMenuComparison() async throws {
        let api=APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:49173"),configuration:Self.config)
        let model=MenuModel(api:api,connectivityMonitor:nil)
        var logged=false; api.login(password:"OWNED_SYNTHETIC_ONLY") { logged=$0 }
        await wait("closed fixture real API login") { logged }
        let ui=AppDelegate(model:model); ui.desktop=nil; delegates.append(ui)
        ui.applicationDidFinishLaunching(Notification(name:NSApplication.didFinishLaunchingNotification))
        var results=[[String:Any]]()
        func rows(_ menu:NSMenu)->[String] {
            var out=[String]()
            for row in menu.items {
                let snap=row.representedObject as? [String:Any] ?? [:]
                let button=row.view?.subviews.first as? NSButton
                out.append([row.title,String(row.isEnabled),String(row.state.rawValue),row.toolTip ?? "",row.action.map { NSStringFromSelector($0) } ?? "",String(describing:snap["name"] ?? ""),String(describing:snap["etag"] ?? ""),String(describing:snap["generation"] ?? ""),button?.title ?? "",String(button?.isEnabled ?? false)].joined(separator:"|"))
                if let sub=row.submenu { out += rows(sub) }
            }; return out
        }
        func oracle(_ name:String) {
            let actual=rows(ui.item.menu!); ui.fixtureForceRebuild()
            check(actual == rows(ui.item.menu!),"closed fresh-build oracle "+name)
        }
        func objects(_ menu:NSMenu)->[NSMenuItem] { menu.items.flatMap { row in [row]+(row.submenu.map { objects($0) } ?? []) } }
        for count in [1,20,200] {
            model.fixtureSeed(count:count);ui.render()
            let kept=objects(ui.item.menu!)
            let initial=ui.fixtureRebuilds
            var elapsed=[Double]()
            let original=model.onChange;var callbacks=0
            model.onChange={ callbacks += 1; original?() }
            let startRequests=FocusHTTP.requests.count
            for i in 1...60 {
                let start=DispatchTime.now().uptimeNanoseconds
                model.fixtureTraffic(i)
                elapsed.append(Double(DispatchTime.now().uptimeNanoseconds-start))
            }
            let rebuilt=ui.fixtureRebuilds-initial
            let retained=kept.count==objects(ui.item.menu!).count && zip(kept,objects(ui.item.menu!)).allSatisfy { $0 === $1 }
            let trafficCallbacks=callbacks
            // Independent equal-input virtual-clock window: real installed Timer
            // and actual URLProtocol/API owners, not inferred request budgets.
            model.startPolling();model.pollingTimer!.fireDate = .distantFuture
            for _ in 1...60 {
                model.fixtureClockAdvance();model.pollingTimer!.fire()
                await waitSilent { model.api.requestsInFlight == 0 }
            }
            model.stopPolling();model.onChange=original
            results.append(["nodes":count,"trafficRenders":60,"rebuilds":rebuilt,"retainedRootItems":retained,"trafficCallbacks":trafficCallbacks,"timerCallbacks":callbacks-trafficCallbacks,"requests":Array(FocusHTTP.requests.dropFirst(startRequests)),"elapsedNs":elapsed])
            let baseline=ProcessInfo.processInfo.environment["CLOSED_BASELINE"] == "1"
            if !baseline { check(rebuilt == 0 && retained,"closed traffic-only retains all menu objects \(count) nodes") }
            else { check(rebuilt >= 60 && !retained,"baseline witnesses traffic menu reconstruction \(count) nodes") }
            oracle("traffic \(count)")
        }
        // Keep the recorded baseline even though the new performance contract is RED.
        try JSONSerialization.data(withJSONObject:results,options:[.prettyPrinted,.sortedKeys]).write(to:root.appendingPathComponent("closed-comparison.json"))
        if ProcessInfo.processInfo.environment["CLOSED_BASELINE"] == "1" {
            check(results.allSatisfy { ($0["rebuilds"] as! Int)==0 },"closed traffic-only contract RED on accepted Stage1")
        }
        for field in ["order","selected","skipVerify","needsSync","selectable","name","etag","generation"] {
            model.fixtureSeed(count:20);ui.render();let previous=ui.item.menu!.items
            model.fixtureStructure(field);ui.render()
            check(!zip(previous,ui.item.menu!.items).allSatisfy { $0 === $1 },"closed structural invalidation "+field)
            oracle(field)
        }
        var relogged=false;api.login(password:"OWNED_SYNTHETIC_ONLY") { relogged=$0 }
        await wait("closed safety fixture reauthenticated") { relogged }
        model.fixtureSeed(count:20);ui.render()
        model.fixtureLatency(1_700_000_000);ui.render()
        let latencyItem=ui.item.menu!.items.first {$0.title=="启动节点"}!.submenu!.items[3]
        let oldTooltip=latencyItem.toolTip, oldTitle=latencyItem.title
        model.fixtureLatency(1_700_000_060);ui.render()
        check(latencyItem.title==oldTitle && latencyItem.toolTip != oldTooltip,"same latency label updates checkedAt tooltip without replacing node")
        oracle("latency checkedAt")
        let beforeFeedback=objects(ui.item.menu!)
        model.fixtureFeedback();ui.render()
        check(zip(beforeFeedback,objects(ui.item.menu!)).allSatisfy {$0 === $1} && ui.item.menu!.items.contains {$0.title==model.message} && ui.item.menu!.items.contains {$0.title==model.failureDiagnostic?.explanation},"diagnostic and model feedback update without rebuilding")
        oracle("diagnostic feedback")
        for state in ["expiry","recovered","helperOff","helperOn","pending","free","unknown","free","sleep","wake","noauth"] {
            model.fixtureSafety(state);ui.render();oracle(state)
        }
        model.fixtureSeed(count:20);ui.render()
        let root=ui.item.menu!, held=root.items
        ui.menuWillOpen(root);model.fixtureStructure("etag");ui.render()
        check(zip(held,root.items).allSatisfy { $0 === $1 },"open structural change retains menu identities")
        check(root.items.first {$0.title=="启动节点"}!.submenu!.items.dropFirst(3).allSatisfy {!$0.isEnabled},"open obsolete node representations stay disabled")
        ui.menuDidClose(root);oracle("closed after open stale structure")
        check(PresentationProbe.counts == [0,0,0,0],"closed incremental path zero focus presentation calls")
        ui.applicationWillTerminate(Notification(name:NSApplication.willTerminateNotification));NSStatusBar.system.removeStatusItem(ui.item)
    }
    @MainActor static func waitSilent(_ ready:()->Bool) async {
        let end=Date().addingTimeInterval(5)
        while !ready() && Date()<end { await pump(0.005) }
        guard ready() else { fatalError("closed fixture owner drain timeout") }
    }

    @MainActor static func run() async throws {
        root=URL(fileURLWithPath:CommandLine.arguments[1]); try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        let app=NSApplication.shared; app.setActivationPolicy(.accessory); app.finishLaunching()
        baselineWindows=Set(app.windows.map { $0.windowNumber })
        PresentationProbe.install(NSApplication.self,#selector(NSApplication.activate(ignoringOtherApps:)),#selector(NSApplication.focus_activate(ignoringOtherApps:)))
        PresentationProbe.install(NSWindow.self,#selector(NSWindow.makeKeyAndOrderFront(_:)),#selector(NSWindow.focus_makeKeyAndOrderFront(_:)))
        PresentationProbe.install(NSAlert.self,#selector(NSAlert.beginSheetModal(for:completionHandler:)),#selector(NSAlert.focus_beginSheetModal(for:completionHandler:)))
        PresentationProbe.install(NSAlert.self,#selector(NSAlert.runModal),#selector(NSAlert.focus_runModal))
        PresentationProbe.install(NSStatusBar.self,#selector(NSStatusBar.statusItem(withLength:)),#selector(NSStatusBar.focus_statusItem(withLength:)))
        calibrateStatusHosts()
        if ProcessInfo.processInfo.environment["CLOSED_ONLY"] == "1" { try await closedMenuComparison(); return }
        let fresh=launch(missing:true); await quiet(fresh,"uninitialized startup")
        autoreleasepool {
            let hidden=NSWindow(contentRect:NSRect(x:0,y:0,width:570,height:410),styleMask:[.titled,.closable],backing:.buffered,defer:false)
            hidden.isReleasedWhenClosed=false
            check(contentWindows().contains { $0 === hidden },"negative control detects even a hidden ordinary NSWindow")
            hidden.close()
        }
        await quiet(fresh,"after hidden-window negative control")
        check(fresh.item.button!.toolTip!.contains("组件待初始化"),"fresh menu explains explicit native installation")
        check(!fresh.item.menu!.items.contains { $0.title.contains("登录") || $0.title.contains("连接设置") || $0.title.contains("记住") },"manual app login menu removed rather than hidden")
        let saved=launch(); await wait("private pipe automatic startup authenticates") {saved.model.api.authenticated && saved.desktop?.busy==false}
        check(!saved.model.initializingConnection && saved.connectionMessage.contains("初始化完成"),"startup composition completes only after fresh HTTP and runtime proof")
        check(!FocusHTTP.requests.contains { $0.contains("/service/") },"startup initialization never starts or installs VPN")
        await wait("offline connectivity verdict retained") {saved.model.connectivity == .offline}; await quiet(saved,"authenticated offline startup")
        check(saved.speedView.icon.contentTintColor == NSColor.systemRed,"offline indication stays red")
        check(saved.item.button!.toolTip!.contains("联网检测未通过"),"offline menu stays actionable")
        for _ in 0..<4 {saved.model.tick(); saved.model.connectivityMonitor!.check(force:true); await pump()}; await quiet(saved,"background ticks")
        FocusHTTP.online=true; saved.model.connectivityMonitor!.check(force:true)
        await wait("connectivity recovers") {saved.model.connectivity == .online}; await quiet(saved,"network recovery")
        saved.model.environmentChanged(sleeping:true); await quiet(saved,"sleep")
        saved.model.environmentChanged(); await quiet(saved,"wake")
        saved.model.environmentChanged(); await quiet(saved,"path change")
        check(!saved.applicationShouldHandleReopen(app,hasVisibleWindows:false),"Finder reopen never requests a window"); await quiet(saved,"reopen")
        tick=tick.addingTimeInterval(16); FocusHTTP.serviceStatus=401; saved.model.refresh()
        await wait("401 expires session") {!saved.model.api.authenticated}
        await wait("401 during initialization releases actual runtime and model owners") {saved.desktop?.busy==false && !saved.model.initializingConnection}
        await pump(0.4); await quiet(saved,"expiry")
        let failedCount=FocusHTTP.logins
        for _ in 0..<20 {saved.model.tick(); saved.sessionExpired()}; await pump(0.3)
        check(FocusHTTP.logins==failedCount,"expiry failure never becomes 250ms login loop")
        FocusHTTP.serviceStatus=200
        for status in [401,429] {
            FocusHTTP.loginStatus=status; let ui=launch(); await wait("HTTP \(status) failure completed") {ui.desktop?.busy==false}
            let count=FocusHTTP.logins; for _ in 0..<10 {ui.model.tick(); ui.sessionExpired(); ui.connectRuntime()}; await pump(0.3)
            check(FocusHTTP.logins==count,"HTTP \(status) cooldown and singleflight"); await quiet(ui,"HTTP \(status) failure")
        }
        FocusHTTP.loginStatus=200
        FocusHTTP.loginOffline=true; let disconnected=launch()
        await wait("offline app session failure completes") { disconnected.desktop?.busy==false }
        await quiet(disconnected,"transport offline"); let offlineCount=FocusHTTP.logins
        for _ in 0..<12 { disconnected.model.tick(); disconnected.connectRuntime() }; await pump(0.2)
        check(FocusHTTP.logins==offlineCount,"offline transport never loops application authentication")
        FocusHTTP.loginOffline=false
        tick=tick.addingTimeInterval(16); saved.refresh()
        await wait("explicit refresh reconnects verified runtime") {saved.model.api.authenticated && saved.desktop?.busy==false}; await quiet(saved,"reconnection")
        // Exact production delayed migration callback is now status-only, even
        // when called after fresh authenticated stopped status becomes available.
        saved.desktop?.onMigrationResume?(); await pump(0.5)
        check(saved.pendingMigrationResume,"late migration records pending user action"); await quiet(saved,"late migration completion")
        check(saved.item.menu!.items.contains {$0.title=="恢复 VPN…"},"pending resume appears in status menu")
        saved.desktop?.onMigrationResume?(); saved.model.tick(); await pump(0.3); await quiet(saved,"repeated stale migration callback")
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
        await quiet(installUI,"asynchronous installation refusal")
        // Prove a real read-owner collision separately from the pending contract.
        // The APIClient completion barrier below owns no production state: each
        // sentinel must be admitted and completed through the actual transport.
        func savedInstallRow()->NSMenuItem { saved.item.menu!.items.first {$0.action == #selector(AppDelegate.initializeDesktop)}! }
        @MainActor func settled(_ ready: ()->Bool) async -> Bool {
            let end=Date().addingTimeInterval(5)
            while !ready() && Date()<end { await pump(0.02) }
            return ready()
        }
        func heldResponse()->(() -> Void)? {
            FocusHTTP.gate.lock(); defer { FocusHTTP.gate.unlock() }; return FocusHTTP.held
        }
        @MainActor func drainReads() async -> Bool {
            let paths=["/status","/helper/status","/nodes","/traffic"]
            var sent=Set<String>(), completed=Set<String>()
            return await settled {
                for path in paths where !sent.contains(path) {
                    if saved.model.api.request(path,completion:{ _ in completed.insert(path) }) { sent.insert(path) }
                }
                return completed.count == paths.count
            }
        }
        let initiallyDrained=await drainReads()
        guard initiallyDrained else { check(false,"fixture prior owned reads drain"); return }
        let context=saved.model.quitContext!
        FocusHTTP.gate.lock(); FocusHTTP.holdStatus=true; FocusHTTP.held=nil; FocusHTTP.gate.unlock()
        saved.model.refresh()
        guard await settled({ heldResponse() != nil }) else { check(false,"fixture refresh status held"); return }
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
            priorReadsDrained=await drainReads()
            guard priorReadsDrained else { check(false,"fixture all prior owned reads drain"); return }
        }
        FocusHTTP.gate.lock(); FocusHTTP.holdStatus=true; FocusHTTP.gate.unlock()
        var quitOutcomes=[QuitOutcome]()
        saved.model.beginQuit(context:context) { quitOutcomes.append($0) }
        FocusHTTP.event("pending before assertion pending=\(saved.model.pending) row=\(savedInstallRow().isEnabled) outcomes=\(quitOutcomes)")
        try JSONSerialization.data(withJSONObject:FocusHTTP.timeline,options:.prettyPrinted).write(to:root.appendingPathComponent("timeline.json"))
        check(saved.model.pending && !savedInstallRow().isEnabled,"pending operation disables installation menu")
        saved.initializeDesktop()
        saved.reinitializeConnection()
        check(PresentationProbe.counts == [0,0,0,0] && saved.model.pending,"pending quit refuses connection initialization before confirmation")
        check(saved.connectionMessage.contains("当前操作进行中") && PresentationProbe.counts == [0,0,0,0],"stale pending install action explains refusal without dispatch")
        let quitResponseHeld=await settled { heldResponse() != nil }
        saved.model.abandonQuit(context:context)
        let requestsBeforeLate=FocusHTTP.requests.count
        FocusHTTP.gate.lock(); FocusHTTP.holdStatus=false; FocusHTTP.gate.unlock()
        let lateResponse=heldResponse(); lateResponse?()
        let lateOwnerDrained=await drainReads()
        let lateFenced=quitOutcomes.isEmpty && saved.model.uncertain && !saved.model.pending
        FocusHTTP.event("late response fenced=\(lateFenced) drained=\(lateOwnerDrained)")
        check(saved.model.uncertain && !savedInstallRow().isEnabled,"unknown result disables installation menu")
        saved.initializeDesktop()
        check(saved.connectionMessage.contains("当前操作结果未知") && saved.connectionMessage.contains("未开始安装") && PresentationProbe.counts == [0,0,0,0],"stale unknown install action explains refusal without retry")
        await quiet(saved,"pending and unknown installation refusal")
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
        await quiet(recoveryUI,"delayed recovery refusal")
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
        await quiet(recoveryUI,"delayed recovery STOP timeout")
        // New connection initialization composes the shipping delegate, runtime,
        // URLProtocol session and persistent store; no standalone model shortcut.
        let blocked=recoveryUI.desktop!, durableBefore=try Data(contentsOf:URL(fileURLWithPath:durableUIRoot).appendingPathComponent("recovery.json"))
        let commandsBefore=uiSTOPs
        recoveryUI.reinitializeConnection()
        recoveryUI.connectRuntime(userInitiated:true,discardUnknown:true)
        check(blocked.blocksQuit && uiSTOPs==commandsBefore && PresentationProbe.counts == [0,0,0,0],"durable recovery UNKNOWN refuses reinitialization without prompt or dispatch")
        check((try? Data(contentsOf:URL(fileURLWithPath:durableUIRoot).appendingPathComponent("recovery.json"))) == durableBefore,"connection initialization preserves exact durable UNKNOWN bytes")
        // Saved has only transient model UNKNOWN from the abandoned quit above.
        check(saved.model.uncertain && saved.desktop?.blocksQuit == false,"transient UNKNOWN composition precondition remains locked")
        let loginBefore=FocusHTTP.logins
        PresentationProbe.response = .alertSecondButtonReturn
        autoreleasepool { saved.reinitializeConnection() }
        check(saved.model.uncertain && FocusHTTP.logins==loginBefore && PresentationProbe.counts == [1,0,0,1],"explicit reinitialization Cancel preserves UNKNOWN and sends no login")
        PresentationProbe.activations=0; PresentationProbe.modals=0
        PresentationProbe.response = .alertFirstButtonReturn
        autoreleasepool { saved.reinitializeConnection() }
        check(saved.model.initializingConnection && saved.model.uncertain && saved.desktop?.busy == true && PresentationProbe.counts == [1,0,0,1],"explicit reinitialization Continue holds UNKNOWN until fresh proof")
        PresentationProbe.activations=0; PresentationProbe.modals=0
        saved.reinitializeConnection()
        check(PresentationProbe.counts == [0,0,0,0],"in-flight initialization refuses repeated confirmation")
        await wait("explicit reinitialization composes fresh runtime login and observations") { !saved.model.initializingConnection && saved.desktop?.busy == false }
        check(saved.model.api.authenticated && !saved.model.uncertain && saved.model.message.contains("不追认"),"fresh composition clears only transient UNKNOWN without historical success")
        check(FocusHTTP.logins==loginBefore+1 && !FocusHTTP.requests.contains {$0.contains("/service/") || $0.contains("/selection")},"explicit reinitialization sends one login and zero lifecycle or selection mutations")
        await quiet(saved,"completed explicit reinitialization")
        holdInspection=true
        let raced=launch(), oldInspection=heldInspection!, oldResult=lastInspectResult!
        oldInspection(DesktopCommandResult(code:1,data:Data(),timedOut:false))
        check(!raced.model.initializingConnection && raced.desktop?.busy == false,"failed attach inspection releases composite owner")
        raced.connectRuntime(userInitiated:true)
        let newInspection=heldInspection!, newResult=lastInspectResult!, commands=launchCommands.count
        check(raced.model.initializingConnection && raced.desktop?.busy == true && raced.applicationShouldTerminate(app) == .terminateCancel,"active initialization blocks termination before STOP")
        oldInspection(oldResult)
        check(raced.model.initializingConnection && raced.desktop?.busy == true && launchCommands.count==commands,"obsolete runtime inspect callback cannot reopen or finish newer initialization")
        holdInspection=false; newInspection(newResult)
        await wait("new initialization succeeds after obsolete callback rejection") {raced.model.api.authenticated && !raced.model.initializingConnection && raced.desktop?.busy==false}
        await quiet(raced,"late callback fenced initialization")
        raced.applicationWillTerminate(Notification(name:NSApplication.willTerminateNotification))
        if let child=raced.desktop?.console, child.isRunning { child.terminate(); child.waitUntilExit() }
        check(!launchCommands.contains {$0.contains("prepare") || $0.contains("helper-install-root") || $0.contains("migration-commit")} && !FocusHTTP.requests.contains {$0.contains("/service/")},"new initialization composition never installs authorizes or starts VPN")
        saved.applicationWillTerminate(Notification(name:NSApplication.willTerminateNotification))
        if let child=saved.desktop?.console, child.isRunning { child.terminate(); child.waitUntilExit() }
        recoveryUI.applicationWillTerminate(Notification(name:NSApplication.willTerminateNotification)); NSStatusBar.system.removeStatusItem(recoveryUI.item)
        FocusHTTP.nodeNames=["UI node","UI other"]
        let live=launch(); await wait("live probe fixture authenticated") { live.model.canProbe }
        live.render()
        let rootMenu=live.item.menu!
        live.menuWillOpen(rootMenu)
        let nodesMenu=rootMenu.items.first { $0.title == "启动节点" }!.submenu!
        let probeItem=nodesMenu.items[0]
        check(probeItem.view?.subviews.first is NSButton,"probe uses native non-dismissing custom-view button on deployed SDK")
        live.menuWillOpen(nodesMenu)
        let button=probeItem.view!.subviews.first as! NSButton
        button.performClick(nil)
        await wait("live probe client holds two simultaneous requests") { FocusHTTP.gate.lock();defer { FocusHTTP.gate.unlock() };return FocusHTTP.heldProbes.count==2 }
        check(rootMenu.items.first { $0.title == "启动节点" }?.submenu === nodesMenu && nodesMenu.items[0] === probeItem,"root and submenu item identities stable while tracking")
        check(!button.isEnabled && button.title.contains("0/2") && nodesMenu.items[3].title.contains("测试中"),"same native rows show progress and testing without reopening")
        FocusHTTP.gate.lock();let finishes=FocusHTTP.heldProbes;FocusHTTP.heldProbes=[];FocusHTTP.gate.unlock()
        finishes[1]();await wait("out of order result appears during tracking") { nodesMenu.items[4].title.contains("不可用") }
        check(nodesMenu.items[3].title.contains("测试中") && button.title.contains("1/2"),"partial live progress changes only completed row")
        finishes[0]();await wait("live batch finishes without menu rebuild") { !live.model.probing }
        check(button.isEnabled && nodesMenu.items[0] === probeItem && nodesMenu.items[3].title.contains("上次"),"same probe button reenabled and completed result retained in place")
        live.menuDidClose(nodesMenu);live.menuDidClose(rootMenu)
        // Exercise actual AppKit tracking, not only delegate callback simulation.
        let popup=live.item.menu!.items.first { $0.title == "启动节点" }!.submenu!
        let popupButton=popup.items[0].view!.subviews.first as! NSButton
        FocusHTTP.gate.lock(); FocusHTTP.splitProbeAdmission=true; FocusHTTP.probeAdmissions=0; FocusHTTP.gate.unlock()
        var clicked=false, stayed=false, delivered=false, splitObserved=false
        var admissionCounts=[Int]()
        let nativeDeadline=Date().addingTimeInterval(4)
        let nativeTimer=Timer(timeInterval:0.15,repeats:true) { timer in
            if Date() >= nativeDeadline { timer.invalidate(); popup.cancelTrackingWithoutAnimation();return }
            if !clicked { clicked=true; popupButton.performClick(nil); return }
            if !delivered {
                FocusHTTP.gate.lock()
                let pending=FocusHTTP.heldProbes
                admissionCounts.append(pending.count)
                // Never discard a completion owner on a partial batch. The
                // two independent URLProtocol admissions may straddle this tick.
                if pending.count == 2 { FocusHTTP.heldProbes=[] }
                // Release the second real transport owner only AFTER observing
                // the one-owner boundary. No fake result or extra product call.
                if pending.count == 1, let second=FocusHTTP.deferredProbe {
                    splitObserved=true; FocusHTTP.deferredProbe=nil; FocusHTTP.heldProbes.append(second)
                }
                FocusHTTP.gate.unlock()
                if pending.count != 2 { return }; delivered=true;for finish in pending { finish() };return
            }
            let rowVisible=popup.items[0].view?.window != nil
            stayed=popupButton.window != nil && rowVisible
            if live.model.probing { return }
            timer.invalidate(); popup.cancelTrackingWithoutAnimation()
        }
        RunLoop.main.add(nativeTimer,forMode:.eventTracking)
        // Suspend the enclosing main-actor task before entering AppKit's own
        // event-tracking loop. A nested popup inside that task starves GCD.
        await withCheckedContinuation { (continuation:CheckedContinuation<Void,Never>) in
            let entry=Timer(timeInterval:0,repeats:false) { _ in
                popup.popUp(positioning:nil,at:NSPoint(x:30,y:30),in:nil)
                continuation.resume()
            }
            RunLoop.main.add(entry,forMode:.default)
        }
        nativeTimer.invalidate()
        try JSONSerialization.data(withJSONObject:["counts":admissionCounts,"splitObserved":splitObserved,"clicked":clicked,"stayed":stayed,"delivered":delivered,"probing":live.model.probing],options:[.prettyPrinted,.sortedKeys]).write(to:root.appendingPathComponent("popup-admission.json"))
        check(clicked && stayed,"actual AppKit popUp tracking remains presented after native probe button click")
        check(delivered && !live.model.probing && popup.items[3].title.contains("上次"),"real event-tracking run loop delivers client results and updates existing native rows")
        FocusHTTP.gate.lock(); FocusHTTP.splitProbeAdmission=false;let closing=FocusHTTP.heldProbes;FocusHTTP.heldProbes=[];FocusHTTP.gate.unlock()
        live.model.stopPolling();for finish in closing { finish() }
        await pump()
        check(popupButton.window == nil,"explicit menu close is respected and late completion never reopens it")
        check(splitObserved && admissionCounts.prefix(2).elementsEqual([1,2]),"native fixture preserves first completion owner across split transport admission")
        live.model.stopPolling(); live.model.api.reset()
        // Append after the complete original 125-check inventory.
        check(!calibratedHosts.isEmpty && calibratedHosts.contains { $0 === statusCalibration?.button?.window },"controlled status-item creation establishes exact framework host identities before production UI")
        check(hostsReused,"production status-item factory scopes attribute every exact host object throughout quiet scenarios")
        autoreleasepool {
            let hidden=NSWindow(contentRect:NSRect(x:0,y:0,width:80,height:40),styleMask:.borderless,backing:.buffered,defer:false)
            hidden.isReleasedWhenClosed=false; hidden.level = .statusBar
            check(!hidden.isVisible && !hidden.isKeyWindow && contentWindows().contains { $0 === hidden },"hidden nonkey ordinary window at status-bar level remains content despite calibrated hosts")
            hidden.close()
        }
        // UX regressions run after the complete predecessor inventory.
        let feedback=launch(); await wait("feedback fixture authenticated") { feedback.model.canMutate }
        feedback.render()
        let feedbackMenu=feedback.item.menu!
        var identities=[ObjectIdentifier](), fixedChanged=false, controlsDisabled=false, stable=false
        let feedbackTimer=Timer(timeInterval:0.15,repeats:false) { _ in
            identities=feedbackMenu.items.map { ObjectIdentifier($0) }
            feedback.model.environmentChanged(sleeping:true)
            feedback.render()
            stable=identities == feedbackMenu.items.map { ObjectIdentifier($0) }
            fixedChanged=feedbackMenu.items[0].title.contains("状态未知") && feedbackMenu.items.contains { $0.title == feedback.model.message }
            controlsDisabled=feedbackMenu.items.filter { ["启动 VPN","停止 VPN","重新连接…"].contains($0.title) }.allSatisfy { !$0.isEnabled }
            feedbackMenu.cancelTrackingWithoutAnimation()
        }
        RunLoop.main.add(feedbackTimer,forMode:.eventTracking)
        await withCheckedContinuation { (continuation:CheckedContinuation<Void,Never>) in
            let entry=Timer(timeInterval:0,repeats:false) { _ in
                feedbackMenu.popUp(positioning:nil,at:NSPoint(x:30,y:30),in:nil); continuation.resume()
            };RunLoop.main.add(entry,forMode:.default)
        }
        check(stable,"actual root popup updates fixed rows without insertion removal or identity replacement")
        check(fixedChanged,"actual root popup immediately updates status and model feedback")
        check(controlsDisabled,"actual root popup disables stale service controls")
        feedback.model.environmentChanged(); await wait("feedback fixture revalidated") { feedback.model.canMutate }
        feedback.menuWillOpen(feedbackMenu)
        feedback.model.api.reset();feedback.render()
        check(feedbackMenu.items.filter { ["启动 VPN","停止 VPN","重新连接…","安装／更新组件…"].contains($0.title) }.allSatisfy { !$0.isEnabled },"old menu generation never re-enables stale actions")
        feedback.menuDidClose(feedbackMenu)
        let privatePasteboard=NSPasteboard(name:NSPasteboard.Name("AnyTLS-UX-"+UUID().uuidString))
        privatePasteboard.setString("OWNED_SENTINEL",forType:.string)
        feedback.copyFailureDiagnostic(to:privatePasteboard)
        check(privatePasteboard.string(forType:.string) == "OWNED_SENTINEL","missing diagnostic leaves private clipboard unchanged")
        feedback.connectRuntime(userInitiated:true); await wait("diagnostic fixture revalidated") { feedback.model.canMutate }
        feedback.model.mutate(path:"/service/stop",consent:false)
        await wait("unknown diagnostic callback retained") { !feedback.model.pending && feedback.model.failureDiagnostic != nil }
        feedback.copyFailureDiagnostic(to:privatePasteboard)
        let copied=privatePasteboard.string(forType:.string) ?? ""
        check(copied.contains("未验证／未知") && copied.contains("不追认"),"private clipboard copies fixed unknown summary without claiming ACK")
        check(!copied.contains("fixture") && !copied.contains("127.0.0.1") && !copied.contains("UI node"),"private diagnostic excludes runtime body endpoint and nodes")
        check(feedback.model.uncertain && !feedback.model.canMutate,"diagnostic copy never unlocks UNKNOWN or retries")
        privatePasteboard.releaseGlobally()
        feedback.applicationWillTerminate(Notification(name:NSApplication.willTerminateNotification));NSStatusBar.system.removeStatusItem(feedback.item)
        if let child=feedback.desktop?.console, child.isRunning {child.terminate();child.waitUntilExit()}
        try await closedMenuComparison()
        NSStatusBar.system.removeStatusItem(statusCalibration!)
        try JSONSerialization.data(withJSONObject:["checks":checks,"count":checks.count,"presentationCounts":PresentationProbe.counts,"realNetworkRequests":0,"productionKeychainAccessed":false,"osPollingObserversDisabledInFixture":true],options:[.prettyPrinted,.sortedKeys]).write(to:root.appendingPathComponent("focus-checks.json"))
        print("FOCUS_TESTS_OK checks=\(checks.count)")
    }
}
