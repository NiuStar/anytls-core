import AppKit
import Network

final class SpeedView: NSView {
    let up=NSTextField(labelWithString:"↑—"), down=NSTextField(labelWithString:"↓—")
    let icon=NSImageView(frame:NSRect(x:3,y:2,width:17,height:18))
    override init(frame: NSRect) {
        super.init(frame:frame)
        icon.image=NSImage(systemSymbolName:"shield.lefthalf.filled",accessibilityDescription:"AnyTLS")
        icon.contentTintColor = .labelColor; addSubview(icon)
        for (field,y) in [(up,CGFloat(11)),(down,CGFloat(0))] {
            field.frame=NSRect(x:25,y:y,width:90,height:11); field.font=NSFont.monospacedSystemFont(ofSize:9,weight:.medium)
            field.textColor = .labelColor; field.lineBreakMode = .byClipping; addSubview(field)
        }
    }
    required init?(coder: NSCoder) { fatalError("not used") }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
}
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private(set) var speedView: SpeedView!
    private(set) var item: NSStatusItem!
    let model: MenuModel
    var desktop: DesktopRuntime? = {
        #if FOCUS_TESTS || DESKTOP_TESTS
        return nil
        #else
        guard !CommandLine.arguments.contains("--ui-smoke") else { return nil }
        return DesktopRuntime()
        #endif
    }()
    lazy var quitCoordinator=QuitCoordinator(model:model)
    private var terminationPending=false
    init(model: MenuModel = MenuModel(api:APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:18089")))) {
        self.model=model; super.init()
    }
    private(set) var connectionMessage="正在连接本机组件…"
    private var attaching=false
    private var nextAttach=Date.distantPast
    private var expiryAttempted=false
    var now: ()->Date = Date.init
    private(set) var pendingMigrationResume=false
    private var menu: NSMenu!
    private let smoke=CommandLine.arguments.contains("--ui-smoke")
    private var pathMonitor: NWPathMonitor?
    private var observers: [NSObjectProtocol]=[]
    private var lastPath: String?
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        item=NSStatusBar.system.statusItem(withLength:118)
        speedView=SpeedView(frame:NSRect(x:0,y:0,width:118,height:22))
        item.button?.addSubview(speedView)
        menu=NSMenu(); menu.autoenablesItems=false; menu.delegate=self; item.menu=menu
        model.onChange={ [weak self] in
            guard let self=self else { return }
            self.desktop?.observeMigrationActivation(running:self.model.status?.running==true,pending:self.model.pending,uncertain:self.model.uncertain)
            self.render()
        }
        desktop?.onChange={ [weak self] in
            guard let self=self else { return }
            if self.desktop?.busy == false && self.attaching {
                self.attaching=false
                if !self.model.api.authenticated { self.connectionMessage="组件待初始化或连接失败，请安装／更新组件，或稍后刷新状态" }
            }
            self.render()
        }
        quitCoordinator.onChange={ [weak self] in self?.render() }
        desktop?.onMigrationResume={ [weak self] in self?.migrationResumeAvailable() }
        let expired=model.api.onExpired
        model.api.onExpired={ [weak self] in
            expired?()
            // Leave the expiry callback stack before replacing its session.
            DispatchQueue.main.async { self?.sessionExpired() }
        }
        render()
        if smoke {
            // Offline: construct actual AppKit controls without any login/timer/API.
            DispatchQueue.main.asyncAfter(deadline:.now()+0.6) { self.smokeCapture() }
        } else {
            connectRuntime()
            #if !FOCUS_TESTS
            model.startPolling()
            let center=NSWorkspace.shared.notificationCenter
            observers.append(center.addObserver(forName:NSWorkspace.willSleepNotification,object:nil,queue:.main) { [weak self] _ in self?.model.environmentChanged(sleeping:true) })
            observers.append(center.addObserver(forName:NSWorkspace.didWakeNotification,object:nil,queue:.main) { [weak self] _ in self?.model.environmentChanged() })
            let monitor=NWPathMonitor(); pathMonitor=monitor
            monitor.pathUpdateHandler={ [weak self] path in
                let signature="\(path.status)|\(path.availableInterfaces.map { $0.name }.sorted().joined(separator:","))|\(path.isExpensive)|\(path.isConstrained)"
                DispatchQueue.main.async {
                    guard let self=self else { return }
                    if let old=self.lastPath, old != signature { self.model.environmentChanged() }
                    self.lastPath=signature
                }
            }
            monitor.start(queue:DispatchQueue(label:"org.anytls.menubar.path"))
            #endif
        }
    }
    @discardableResult private func add(_ title: String, _ action: Selector? = nil, enabled: Bool = true) -> NSMenuItem {
        let row=NSMenuItem(title:title,action:action,keyEquivalent:""); row.target=self; row.isEnabled=enabled; menu.addItem(row); return row
    }
    private func safeName(_ name: String) -> String {
        String(name.unicodeScalars.map { CharacterSet.controlCharacters.contains($0) ? " " : String($0) }.joined().prefix(140))
    }
    func render() {
        let rate=model.traffic.flatMap { $0.fresh() ? $0 : nil }
        let up=rate.map { TrafficRate.label($0.upload,$0.duration) } ?? "—"
        let down=rate.map { TrafficRate.label($0.download,$0.duration) } ?? "—"
        if speedView.up.stringValue != "↑ \(up)" { speedView.up.stringValue="↑ \(up)" }
        if speedView.down.stringValue != "↓ \(down)" { speedView.down.stringValue="↓ \(down)" }
        let network: String
        switch model.connectivity {
        case .checking: network="正在检查网络连接…"
        case .online: network="网络已连接"
        case .offline: network="网络连接失败，请检查节点或网络"
        case .idle: network="VPN 运行中"
        }
        let state = !model.api.authenticated ? connectionMessage : model.uncertain ? "操作结果未知" : model.status.map { $0.running ? network : ($0.loaded ? "VPN 已加载 · 未运行" : "VPN 未启动") } ?? "状态未知"
        item.button?.toolTip="AnyTLS · \(state)\n↑ \(up)  ↓ \(down)"
        item.button?.setAccessibilityLabel("AnyTLS，\(state)，上传 \(up)，下载 \(down)")
        speedView.icon.contentTintColor = model.connectivity == .offline ? .systemRed : .labelColor
        speedView.icon.setAccessibilityLabel(model.connectivity == .offline ? "AnyTLS，网络连接失败，请检查节点或网络" : "AnyTLS，\(state)")
        if !connectionMessage.isEmpty { item.button?.toolTip?.append("\n"+connectionMessage) }
        if let desktop=desktop { item.button?.toolTip?.append("\n"+desktop.message) }
        if !quitCoordinator.message.isEmpty { item.button?.toolTip?.append("\n"+quitCoordinator.message) }
        if let rate=rate { item.button?.toolTip?.append("\n本实例累计上传 \(rate.totalUpload) bytes，下载 \(rate.totalDownload) bytes") }
        // Never rebuild an open menu under the pointer. Refresh its contents on open.
        if !menuIsOpen { rebuildMenu(state:state) }
    }
    private var menuIsOpen=false
    func menuWillOpen(_ menu: NSMenu) { render(); menuIsOpen=true }
    func menuDidClose(_ menu: NSMenu) { menuIsOpen=false; render() }
    private func rebuildMenu(state: String) {
        menu.removeAllItems()
        add("AnyTLS · \(state)",enabled:false)
        if model.api.authenticated { add(model.message,enabled:false) }
        add("安装／更新组件…",#selector(initializeDesktop),enabled:desktop?.busy == false && !terminationPending && !model.pending && !model.uncertain)
        if model.pending || model.uncertain { add(model.message+"；暂不能安装／更新组件，请先在完整控制台核实",enabled:false) }
        if let desktop=desktop { add(desktop.message,enabled:false); if desktop.authorizationRetryAllowed { add("重试已取消的授权…",#selector(retryDesktopAuthorization)) } }
        if !quitCoordinator.message.isEmpty { add(quitCoordinator.message,enabled:false) }
        if !connectionMessage.isEmpty { add(connectionMessage,enabled:false) }
        if model.api.authenticated && !model.helperAvailable { add("助手不可用：请在完整控制台检查",enabled:false) }
        menu.addItem(.separator())
        let can=model.canMutate && desktop?.blocksQuit != true && !terminationPending, status=model.status
        if pendingMigrationResume { add("恢复 VPN…",#selector(resumeMigration),enabled:can && status?.running == false && status?.loaded == false) }
        add("启动 VPN",#selector(start),enabled:can && status?.running == false && status?.loaded == false)
        add("停止 VPN",#selector(stop),enabled:can && (status?.running == true || status?.loaded == true))
        add("重新连接…",#selector(reload),enabled:can && status?.running == true)
        let nodeMenu=NSMenu(); nodeMenu.autoenablesItems=false
        let note=NSMenuItem(title:"勾选 = 已保存启动节点，非实时出口",action:nil,keyEquivalent:""); note.isEnabled=false; nodeMenu.addItem(note)
        for node in model.nodes {
            let row=NSMenuItem(title:safeName(node.name)+(node.needsSync ? " · 需同步默认组" : "")+(node.skipVerify ? " ⚠︎ 跳过证书校验" : ""),action:#selector(selectNode(_:)),keyEquivalent:"")
            row.target=self; row.representedObject=["name":node.name,"etag":model.etag,"generation":model.api.generation] as [String:Any]; row.state=node.selected ? .on : .off
            row.isEnabled=can && node.selectable && (!node.selected || node.needsSync) && !model.etag.isEmpty
            nodeMenu.addItem(row)
        }
        if model.nodes.isEmpty { let empty=NSMenuItem(title:"尚未读取可选节点",action:nil,keyEquivalent:""); empty.isEnabled=false; nodeMenu.addItem(empty) }
        add("启动节点").submenu=nodeMenu
        menu.addItem(.separator())
        add("打开完整控制台",#selector(openConsole))
        add("刷新状态",#selector(refresh),enabled:!terminationPending && !attaching)
        let version=Bundle.main.object(forInfoDictionaryKey:"CFBundleShortVersionString") as? String ?? "0.4.0 candidate"
        add("AnyTLS 菜单栏 \(version)",enabled:false)
        add("核心："+(Bundle.main.object(forInfoDictionaryKey:"AnyTLSCoreVersion") as? String ?? "unknown"),enabled:false)
        menu.addItem(.separator())
        let quit=add("退出并停止 VPN",#selector(quit)); quit.keyEquivalent="q"
    }
    private func confirm(_ title: String, risk: Bool = true) -> Bool {
        NSApp.activate(ignoringOtherApps:true)
        let alert=NSAlert(); alert.messageText=title
        alert.informativeText="操作可能短暂中断网络。"+(risk ? "\n若已有节点配置跳过证书验证，本次操作也将允许该风险，无法验证服务器身份；不会修改其他节点的 TLS 策略。" : "")
        alert.addButton(withTitle:"继续"); alert.addButton(withTitle:"取消"); alert.alertStyle = .warning
        return alert.runModal() == .alertFirstButtonReturn
    }
    @objc private func start() {
        if pendingMigrationResume { resumeMigration(); return }
        if confirm("启动 VPN？") { model.mutate(path:"/service/start",consent:true) }
    }
    @objc private func stop() { if confirm("停止 VPN？",risk:false) { model.mutate(path:"/service/stop",consent:false) } }
    @objc private func reload() { if confirm("停止并重新连接 VPN？") { model.mutate(path:"/service/reload",consent:true) } }
    @objc private func selectNode(_ sender: NSMenuItem) {
        guard let snapshot=sender.representedObject as? [String:Any], let name=snapshot["name"] as? String,
              snapshot["etag"] as? String == model.etag, snapshot["generation"] as? Int == model.api.generation else { return }
        let epoch=model.api.generation, etag=model.etag
        // Confirm before allowing pre-existing insecure configuration. Never a silent true.
        if confirm("切换启动节点为「\(safeName(name))」？"), epoch == model.api.generation, etag == model.etag { model.mutate(path:"/nodes/selection",name:name,consent:true) }
    }
    @objc func refresh() {
        if model.api.authenticated { model.refresh() } else { connectRuntime(userInitiated:true) }
    }
    @objc private func openConsole() { NSWorkspace.shared.open(model.api.endpoint.url) }
    // No credential UI or Keychain exists in this shipping target. Startup and
    // expiry can only use DesktopRuntime's attested private-pipe authority.
    func connectRuntime(userInitiated: Bool = false) {
        guard !smoke, !terminationPending, !attaching, !model.api.authenticated,
              !model.pending, !model.uncertain, desktop?.blocksQuit == false,
              now() >= nextAttach else { return }
        attaching=true; nextAttach=now().addingTimeInterval(15)
        connectionMessage="正在连接本机组件…"; renderIfReady()
        desktop?.attach(login:runtimeLogin)
        // attach may synchronously refuse before invoking login (missing runtime,
        // bundle mismatch, unsafe lifecycle state). Never schedule an auto-loop.
        if desktop?.busy != true { attaching=false; connectionMessage="组件待初始化，请安装／更新组件；或稍后刷新状态"; renderIfReady() }
    }
    func sessionExpired() {
        guard !expiryAttempted, !terminationPending, !model.pending, !model.uncertain else { return }
        expiryAttempted=true
        connectRuntime()
    }
    func migrationResumeAvailable() {
        pendingMigrationResume=true
        connectionMessage="组件已更新，请从菜单恢复 VPN；不会后台弹窗或自动启动"
        renderIfReady()
    }
    @objc func resumeMigration() {
        guard pendingMigrationResume, model.canMutate, model.status?.running==false,
              model.status?.loaded==false, desktop?.blocksQuit==false, !terminationPending else { return }
        let epoch=model.api.generation, etag=model.etag
        guard confirm("组件已更新，恢复原 VPN？"), epoch==model.api.generation,
              etag==model.etag, model.canMutate, desktop?.beginMigrationActivation()==true else { return }
        pendingMigrationResume=false
        model.mutate(path:"/service/start",consent:true)
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool)->Bool { false }
    private func renderIfReady() { if item != nil { render() } }
    @objc private func quit() { NSApp.terminate(nil) }
    static func migrationResumeCheckbox(wasRunning: Bool)->NSButton {
        let resume=NSButton(checkboxWithTitle:"更新后在菜单提供「恢复 VPN…」（不会自动启动）",target:nil,action:nil)
        resume.state=wasRunning ? .on : .off; resume.isEnabled=wasRunning; return resume
    }
    @objc func initializeDesktop() {
        guard !terminationPending, !model.pending, !model.uncertain else {
            connectionMessage = model.uncertain ? "当前操作结果未知，未开始安装／更新组件；请在完整控制台核实" : "当前操作进行中，未开始安装／更新组件；请等待结果后核实"
            renderIfReady(); return
        }
        // This explicit install click is the only app-owned setup confirmation.
        // Migration inspection is asynchronous, so do not queue a later modal.
        guard confirm("安装／更新 AnyTLS 组件？更新将停止 VPN，保留配置；更新完成后须从菜单恢复 VPN。",risk:false) else { return }
        desktop?.consentMigration={ wasRunning in wasRunning }
        desktop?.initialize(login:runtimeLogin)
    }
    @objc func retryDesktopAuthorization() { guard !terminationPending, !model.pending, !model.uncertain else { return }; desktop?.retryAuthorization(login:runtimeLogin) }
    private func runtimeLogin(_ origin: String, _ secret: String, _ completion: @escaping (Bool)->Void) {
        guard let endpoint=try? LocalEndpoint(origin), !model.pending, !model.uncertain else { attaching=false; completion(false); return }
        // Bootstrap application secret never enters fields, defaults or Keychain.
        model.stopPolling()
        model.api.reset(endpoint:endpoint)
        model.api.login(password:secret) { ok in
            guard ok else {
                self.attaching=false; self.connectionMessage="本机组件连接失败，请稍后刷新状态或安装／更新组件"
                self.model.startPolling(); self.renderIfReady(); completion(false); return
            }
            var finished=false
            func finish(_ value: Bool) {
                guard !finished else { return }; finished=true; self.attaching=false
                if !value { self.model.api.reset(); self.model.clearObservations() }
                self.connectionMessage=value ? "本机组件已连接" : "本机组件身份验证失败，请检查组件后刷新状态"
                if value { self.expiryAttempted=false }
                self.model.startPolling(); if value { self.model.refresh() }
                self.renderIfReady(); completion(value)
            }
            func read(_ remaining: Int) {
                guard !finished, remaining>0 else { finish(false); return }
                let sent=self.model.api.request("/status") { result in
                    if case .success(let reply)=result, reply.status==200, self.desktop?.validConsoleMetadata(reply.body)==true { finish(true) }
                    else { finish(false) }
                }
                if !sent { DispatchQueue.main.asyncAfter(deadline:.now()+0.25) { read(remaining-1) } }
            }
            read(32)
            DispatchQueue.main.asyncAfter(deadline:.now()+12) { finish(false) }
        }
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if smoke { return .terminateNow }
        guard desktop?.blocksQuit != true else { return .terminateCancel }
        guard !terminationPending else { return .terminateLater }
        terminationPending=true
        DispatchQueue.main.async {
            var replied=false
            var quitLease=false
            func answer(_ allowed: Bool) {
                guard !replied else { return }; replied=true
                self.terminationPending=false
                if quitLease { quitLease=false; self.desktop?.finishQuitLifecycle() }
                if !allowed && self.quitCoordinator.state == .ready { self.quitCoordinator=QuitCoordinator(model:self.model) }
                sender.reply(toApplicationShouldTerminate:allowed)
            }
            func stop() {
                guard self.desktop?.reserveQuitLifecycle() != false else { answer(false); return }
                quitLease=self.desktop != nil
                self.quitCoordinator.start { allowed in
                    guard allowed else { answer(false); return }
                    if let desktop=self.desktop { desktop.drainOwnedConsole(answer) } else { answer(true) }
                }
            }
            if self.model.api.authenticated { stop(); return }
            guard let desktop=self.desktop else { stop(); return }
            desktop.proveNeverInstalled { absent in
                if absent { answer(true); return }
                desktop.attach { origin, secret, finished in
                    self.runtimeLogin(origin,secret) { ok in finished(ok); if !replied && ok { stop() } else { answer(false) } }
                }
                // attach can refuse without callback; keep termination bounded.
                DispatchQueue.main.asyncAfter(deadline:.now()+20) {
                    if !replied && self.terminationPending && self.quitCoordinator.state != .stopping {
                        self.connectionMessage="无法确认 VPN 已停止；请完成初始化或连接控制台后重试退出"
                        self.renderIfReady(); answer(false)
                    }
                }
            }
        }
        return .terminateLater
    }
    func applicationWillTerminate(_ notification: Notification) {
        pathMonitor?.cancel()
        for observer in observers { NSWorkspace.shared.notificationCenter.removeObserver(observer) }
        model.stopPolling(); model.api.reset()
    }
    private func smokeCapture() {
        let dir=ProcessInfo.processInfo.environment["ANYTLS_SMOKE_OUTPUT"] ?? FileManager.default.currentDirectoryPath
        speedView.appearance=NSAppearance(named:.aqua)
        speedView.wantsLayer=true
        speedView.layer?.backgroundColor=NSColor.windowBackgroundColor.cgColor
        speedView.displayIfNeeded()
        var lines=["OFFLINE_APPKIT_SMOKE", "statusItem=\(item != nil)","menuItems=\(menu.items.count)","windowsOwned=\(NSApp.windows.filter { $0 !== item.button?.window }.count)","frameworkStatusWindows=\(NSApp.windows.filter { $0 === item.button?.window }.count)","authenticated=\(model.api.authenticated)","networkPolling=false","desktopRuntime=\(desktop != nil)"]
        for (name,view) in [("status-button",speedView! as NSView)] {
            if let rep=view.bitmapImageRepForCachingDisplay(in:view.bounds) {
                view.cacheDisplay(in:view.bounds,to:rep)
                if let png=rep.representation(using:.png,properties:[:]) { try? png.write(to:URL(fileURLWithPath:dir).appendingPathComponent(name+".png")); lines.append("rendered=\(name) \(rep.pixelsWide)x\(rep.pixelsHigh)") }
            }
        }
        lines.append(contentsOf:menu.items.map { "menu="+$0.title })
        try? lines.joined(separator:"\n").write(toFile:dir+"/ui-smoke.txt",atomically:true,encoding:.utf8)
        print(lines.joined(separator:"\n")); NSApp.terminate(nil)
    }
}
#if !FOCUS_TESTS && !DESKTOP_TESTS
@main struct MenuBarApplication {
    static func main() {
        let app=NSApplication.shared
        let delegate=AppDelegate()
        app.delegate=delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}
#endif
