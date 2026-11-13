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
    private(set) var connectionMessage="正在初始化连接…"
    private var attaching=false
    private var connectionOwner: UUID?
    private var nextAttach=Date.distantPast
    private var expiryAttempted=false
    var now: ()->Date = Date.init
    private(set) var pendingMigrationResume=false
    private var menu: NSMenu!
    private var trackingMenus=Set<ObjectIdentifier>()
    private var fixedRows=[String:NSMenuItem]()
    // Ordered structural projection: changes replace closed-menu snapshots only.
    private struct NodeStructure: Equatable {
        let name: String
        let selected, selectable, skipVerify, needsSync: Bool
        init(_ node: Node) { name=node.name; selected=node.selected; selectable=node.selectable; skipVerify=node.skipVerify; needsSync=node.needsSync }
    }
    private var menuNodes=[NodeStructure]()
    private var nodePresentation=[String:[String]]()
    #if FOCUS_TESTS
    var fixtureRebuilds=0
    private var fixtureState=""
    func fixtureForceRebuild() { rebuildMenu(state:fixtureState) }
    #endif
    private var menuGeneration = -1
    private var menuETag=""
    private var probeItem: NSMenuItem?
    private var probeButton: NSButton?
    private var latencyRows=[String:(NSMenuItem,String)]()
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
                if let owner=self.connectionOwner {
                    self.connectionOwner=nil; self.model.finishConnectionInitialization(owner:owner,verified:false)
                }
                if !self.model.api.authenticated { self.connectionMessage="连接初始化失败；组件待初始化，可重新初始化连接或安装／更新组件" }
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
        case .online: network="VPN 本地运行 · 联网检测通过"
        case .offline: network="VPN 本地运行，联网检测未通过（不等于节点失效）；可手动切换节点或检查网络"
        case .idle: network="VPN 本地运行 · 尚未检测或已过期"
        }
        let state = !model.api.authenticated ? connectionMessage : model.uncertain ? "操作结果未知" : model.status.map { $0.running ? network : ($0.loaded ? "VPN 已加载 · 未运行" : "VPN 未启动") } ?? "状态未知"
        item.button?.toolTip="AnyTLS · \(state)\n↑ \(up)  ↓ \(down)"
        item.button?.setAccessibilityLabel("AnyTLS，\(state)，上传 \(up)，下载 \(down)")
        speedView.icon.contentTintColor = model.connectivity == .offline ? .systemRed : .labelColor
        speedView.icon.setAccessibilityLabel("AnyTLS，\(state)")
        if !connectionMessage.isEmpty { item.button?.toolTip?.append("\n"+connectionMessage) }
        if let desktop=desktop { item.button?.toolTip?.append("\n"+desktop.message) }
        if !quitCoordinator.message.isEmpty { item.button?.toolTip?.append("\n"+quitCoordinator.message) }
        if let rate=rate { item.button?.toolTip?.append("\n本实例累计上传 \(rate.totalUpload) bytes，下载 \(rate.totalDownload) bytes") }
        #if FOCUS_TESTS
        fixtureState=state
        #endif
        // Traffic and feedback change presentation, not menu structure. Bundle
        // versions are immutable for this process and are allocated on first build.
        let structural = menuGeneration != model.api.generation || menuETag != model.etag || menuNodes != model.nodes.map { NodeStructure($0) }
        if !menuIsOpen && structural { rebuildMenu(state:state) }
        else { updateFixedRows(state:state); updateProbeRows() }
    }
    private var menuIsOpen=false
    func menuWillOpen(_ opening: NSMenu) {
        if trackingMenus.isEmpty && opening === menu { render() }
        trackingMenus.insert(ObjectIdentifier(opening)); menuIsOpen=true; model.setMenuOpen(true)
        updateProbeRows()
    }
    func menuDidClose(_ closing: NSMenu) {
        trackingMenus.remove(ObjectIdentifier(closing)); menuIsOpen = !trackingMenus.isEmpty
        if !menuIsOpen { model.setMenuOpen(false); render() }
    }
    private func updateProbeRows() {
        guard let probe=probeItem else { return }
        let title=model.probing ? "直连 TCP 延迟测试（\(model.probeCompleted)/\(model.probeTotal)）" : "直连 TCP 延迟测试（全部节点）"
        probe.title=title; probeButton?.title=title
        let snapshot=probe.representedObject as? [String:Any]
        let fresh=snapshot?["etag"] as? String == model.etag && snapshot?["generation"] as? Int == model.api.generation
        probe.isEnabled=fresh && model.canProbe && !model.probing && desktop?.blocksQuit != true && !terminationPending
        probeButton?.isEnabled=probe.isEnabled
        let structureCurrent=menuNodes == model.nodes.map { NodeStructure($0) }
        let canSelect=model.canMutate && desktop?.blocksQuit != true && !terminationPending && !model.etag.isEmpty
        for node in menuNodes {
            let name=node.name
            guard let (row,title)=latencyRows[name] else { continue }
            let label=model.latencyLabel(name), tooltip=model.latencyTooltip(name)
            let presentation=[label,tooltip ?? ""]
            if nodePresentation[name] != presentation {
                row.title=title+"\t"+label
                let paragraph=NSMutableParagraphStyle(); paragraph.tabStops=[NSTextTab(textAlignment:.right,location:520,options:[:])]
                row.attributedTitle=NSAttributedString(string:row.title,attributes:[.paragraphStyle:paragraph])
                row.toolTip=tooltip; nodePresentation[name]=presentation
            }
            let snapshot=row.representedObject as? [String:Any]
            let own=snapshot?["name"] as? String == name && snapshot?["etag"] as? String == model.etag && snapshot?["generation"] as? Int == model.api.generation
            // Restore only our current representation; old tracking snapshots
            // cannot inherit authorization from a newly observed configuration.
            row.isEnabled=own && structureCurrent && canSelect && node.selectable && (!node.selected || node.needsSync)
        }
    }
    @objc private func probeButtonClicked(_ sender: NSButton) { if let probe=probeItem { probeNodes(probe) } }
    private func updateFixedRows(state: String) {
        fixedRows["state"]?.title="AnyTLS · \(state)"
        fixedRows["message"]?.title=model.api.authenticated ? model.message : "本机控制台尚未连接"
        fixedRows["desktop"]?.title=desktop?.message ?? "组件状态尚未读取"
        fixedRows["quitMessage"]?.title=quitCoordinator.message.isEmpty ? "退出时将核实停止 VPN" : quitCoordinator.message
        fixedRows["connection"]?.title=connectionMessage.isEmpty ? "连接初始化无待处理消息" : connectionMessage
        fixedRows["blocked"]?.title=model.pending || model.uncertain ? model.message+"；暂不能安装／更新组件，请先在完整控制台核实" : "组件操作仍须明确确认"
        if let observation=model.connectivityObservation {
            fixedRows["networkObservation"]?.title="最近联网检测："+observation.reason.rawValue+" · 完成于本次开机第 \(Int(observation.finishedAt)) 秒（OS 路由 HTTPS）"
        } else { fixedRows["networkObservation"]?.title="最近联网检测：尚无当前会话结果" }
        fixedRows["helper"]?.title=model.api.authenticated && !model.helperAvailable ? "助手不可用：请在完整控制台检查" : "助手状态以当前读取为准"
        fixedRows["diagnostic"]?.title=model.failureDiagnostic?.explanation ?? "暂无已验证失败原因；未知结果仍须核实"
        let fresh=menuGeneration == model.api.generation && menuETag == model.etag
        let free = !terminationPending && !model.pending && !model.uncertain
        let can=fresh && model.canMutate && desktop?.blocksQuit != true && !terminationPending
        let status=model.status
        let controls: [String:Bool] = [
            "install":fresh && desktop?.busy == false && free,
            "reinit":fresh && desktop?.blocksQuit == false && !terminationPending && !model.pending && !attaching && !model.initializingConnection,
            "recover":fresh && desktop?.recoveryAllowed == true && free,
            "complete":fresh && desktop?.recoveryCompletionAllowed == true && free,
            "retry":fresh && desktop?.authorizationRetryAllowed == true && free,
            "resume":pendingMigrationResume && can && status?.running == false && status?.loaded == false,
            "start":can && status?.running == false && status?.loaded == false,
            "stop":can && (status?.running == true || status?.loaded == true),
            "reload":can && status?.running == true,
            "refresh":!terminationPending && !attaching,
            "copy":model.failureDiagnostic != nil,
            "quit":!terminationPending && !model.pending && desktop?.blocksQuit != true]
        for (key,enabled) in controls { fixedRows[key]?.isEnabled=enabled }
        // Never revive stale selection snapshots under the pointer.
        if !can { for (_,entry) in latencyRows { entry.0.isEnabled=false } }
    }
    func copyFailureDiagnostic(to pasteboard: NSPasteboard) {
        guard let diagnostic=model.failureDiagnostic else { return }
        pasteboard.clearContents(); pasteboard.setString(diagnostic.summary,forType:.string)
    }
    @objc private func copyDiagnostic() { copyFailureDiagnostic(to:.general) }
    private func rebuildMenu(state: String) {
        #if FOCUS_TESTS
        fixtureRebuilds += 1
        #endif
        menuNodes=model.nodes.map { NodeStructure($0) }; nodePresentation=[:]
        menu.removeAllItems()
        latencyRows=[:]; probeItem=nil; probeButton=nil; fixedRows=[:]
        menuGeneration=model.api.generation; menuETag=model.etag
        fixedRows["state"]=add("AnyTLS · \(state)",enabled:false)
        fixedRows["message"]=add(model.message,enabled:false)
        fixedRows["install"]=add("安装／更新组件…",#selector(initializeDesktop),enabled:desktop?.busy == false && !terminationPending && !model.pending && !model.uncertain)
        fixedRows["reinit"]=add("重新初始化连接…",#selector(reinitializeConnection),enabled:desktop?.blocksQuit == false && !terminationPending && !model.pending && !attaching && !model.initializingConnection)
        fixedRows["recover"]=add("恢复未完成的组件更新…",#selector(recoverDesktop),enabled:desktop?.recoveryAllowed == true && !terminationPending && !model.pending && !model.uncertain)
        fixedRows["complete"]=add("继续已确认停止的组件更新…",#selector(completeDesktopRecovery),enabled:false)
        fixedRows["blocked"]=add("组件操作仍须明确确认",enabled:false)
        fixedRows["desktop"]=add("组件状态尚未读取",enabled:false)
        fixedRows["retry"]=add("重试已取消的授权…",#selector(retryDesktopAuthorization),enabled:false)
        fixedRows["quitMessage"]=add("退出时将核实停止 VPN",enabled:false)
        fixedRows["connection"]=add("连接初始化无待处理消息",enabled:false)
        fixedRows["helper"]=add("助手状态以当前读取为准",enabled:false)
        fixedRows["networkObservation"]=add("最近联网检测：尚无当前会话结果",enabled:false)
        fixedRows["diagnostic"]=add("暂无已验证失败原因；未知结果仍须核实",enabled:false)
        fixedRows["copy"]=add("复制安全失败诊断",#selector(copyDiagnostic),enabled:false)
        menu.addItem(.separator())
        let can=model.canMutate && desktop?.blocksQuit != true && !terminationPending, status=model.status
        fixedRows["resume"]=add("恢复 VPN…",#selector(resumeMigration),enabled:pendingMigrationResume && can && status?.running == false && status?.loaded == false)
        fixedRows["start"]=add("启动 VPN",#selector(start),enabled:can && status?.running == false && status?.loaded == false)
        fixedRows["stop"]=add("停止 VPN",#selector(stop),enabled:can && (status?.running == true || status?.loaded == true))
        fixedRows["reload"]=add("重新连接…",#selector(reload),enabled:can && status?.running == true)
        let nodeMenu=NSMenu(); nodeMenu.autoenablesItems=false; nodeMenu.delegate=self
        let probe=NSMenuItem(title:model.probing ? "TCP 延迟测试中…" : "TCP 延迟测试（全部节点）",action:#selector(probeNodes),keyEquivalent:"")
        probe.target=self; probe.isEnabled=model.canProbe && !model.probing && desktop?.blocksQuit != true && !terminationPending
        probe.representedObject=["etag":model.etag,"generation":model.api.generation] as [String:Any]
        probe.toolTip="本机物理网络直连节点 TCP 延迟；无法确认直连时显示不可用，不回退 VPN 路由。不是代理 HTTPS 或带宽测试，不切换节点或启停 VPN。结果在当前菜单原位更新。"
        // The deployed SDK has no keepsMenuPresented API. A native custom-view
        // button does not invoke NSMenu selection tracking dismissal (macOS 13+).
        let view=NSView(frame:NSRect(x:0,y:0,width:540,height:30))
        let button=NSButton(title:probe.title,target:self,action:#selector(probeButtonClicked(_:)))
        button.frame=NSRect(x:12,y:2,width:516,height:26); button.bezelStyle = .inline
        button.alignment = .left; button.isEnabled=probe.isEnabled; button.toolTip=probe.toolTip
        button.setAccessibilityLabel("直连 TCP 延迟测试，全部节点")
        view.addSubview(button); probe.view=view; probeItem=probe; probeButton=button
        nodeMenu.addItem(probe); nodeMenu.addItem(.separator())
        let note=NSMenuItem(title:"勾选 = 已保存启动节点，非实时出口",action:nil,keyEquivalent:""); note.isEnabled=false; nodeMenu.addItem(note)
        for node in model.nodes {
            let title=safeName(node.name)+(node.needsSync ? " · 需同步默认组" : "")+(node.skipVerify ? " ⚠︎ 跳过证书校验" : "")
            let row=NSMenuItem(title:title+"\t"+model.latencyLabel(node.name),action:#selector(selectNode(_:)),keyEquivalent:"")
            let paragraph=NSMutableParagraphStyle()
            paragraph.tabStops=[NSTextTab(textAlignment:.right,location:520,options:[:])]
            row.attributedTitle=NSAttributedString(string:row.title,attributes:[.paragraphStyle:paragraph])
            row.target=self; row.representedObject=["name":node.name,"etag":model.etag,"generation":model.api.generation] as [String:Any]; row.state=node.selected ? .on : .off
            row.isEnabled=can && node.selectable && (!node.selected || node.needsSync) && !model.etag.isEmpty
            row.toolTip=model.latencyTooltip(node.name)
            nodeMenu.addItem(row)
            latencyRows[node.name]=(row,title)
        }
        if model.nodes.isEmpty { let empty=NSMenuItem(title:"尚未读取可选节点",action:nil,keyEquivalent:""); empty.isEnabled=false; nodeMenu.addItem(empty) }
        add("启动节点").submenu=nodeMenu
        menu.addItem(.separator())
        add("打开完整控制台",#selector(openConsole))
        fixedRows["refresh"]=add("刷新状态",#selector(refresh),enabled:!terminationPending && !attaching)
        let version=Bundle.main.object(forInfoDictionaryKey:"CFBundleShortVersionString") as? String ?? "0.4.0 candidate"
        add("AnyTLS 菜单栏 \(version)",enabled:false)
        add("核心："+(Bundle.main.object(forInfoDictionaryKey:"AnyTLSCoreVersion") as? String ?? "unknown"),enabled:false)
        menu.addItem(.separator())
        let quit=add("退出并停止 VPN",#selector(quit)); quit.keyEquivalent="q"; fixedRows["quit"]=quit
        updateFixedRows(state:state)
        updateProbeRows()
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
    @objc private func probeNodes(_ sender: NSMenuItem) {
        guard !terminationPending, desktop?.blocksQuit != true,
              let snapshot=sender.representedObject as? [String:Any], snapshot["etag"] as? String == model.etag,
              snapshot["generation"] as? Int == model.api.generation else { return }
        model.probeNodes()
    }
    @objc private func selectNode(_ sender: NSMenuItem) {
        guard let snapshot=sender.representedObject as? [String:Any], let name=snapshot["name"] as? String,
              snapshot["etag"] as? String == model.etag, snapshot["generation"] as? Int == model.api.generation else { return }
        let epoch=model.api.generation, etag=model.etag
        // Confirm before allowing pre-existing insecure configuration. Never a silent true.
        if confirm("切换启动节点为「\(safeName(name))」？"), epoch == model.api.generation, etag == model.etag { model.mutate(path:"/nodes/selection",name:name,consent:true) }
    }
    @objc func refresh() {
        if !terminationPending && !model.pending && !model.uncertain { desktop?.refreshRecovery() }
        if model.api.authenticated { model.refresh() } else { connectRuntime(userInitiated:true) }
    }
    @objc private func openConsole() { NSWorkspace.shared.open(model.api.endpoint.url) }
    // No credential UI or Keychain exists in this shipping target. Startup and
    // expiry can only use DesktopRuntime's attested private-pipe authority.
    func connectRuntime(userInitiated: Bool = false, discardUnknown: Bool = false) {
        guard !smoke, !terminationPending, !attaching,
              (!model.api.authenticated || discardUnknown), !model.pending,
              userInitiated || now() >= nextAttach else { return }
        guard !model.uncertain || discardUnknown else {
            connectionMessage="连接初始化未执行；先前操作结果未知，须明确选择重新初始化连接"; renderIfReady(); return
        }
        guard let runtime=desktop, !runtime.blocksQuit else {
            connectionMessage="连接初始化受阻；组件操作或持久未知状态须先核实，不会自动安装或重放操作"; renderIfReady(); return
        }
        guard let owner=model.beginConnectionInitialization(userConfirmedDiscardUnknown:discardUnknown) else { return }
        connectionOwner=owner
        attaching=true; nextAttach=now().addingTimeInterval(15)
        connectionMessage="正在初始化连接…"; renderIfReady()
        runtime.attach { [weak self, weak runtime] origin,secret,done in
            guard let self=self, self.desktop === runtime, self.connectionOwner == owner, !self.terminationPending else { done(false); return }
            self.runtimeLogin(origin,secret,done)
        }
        // attach may synchronously refuse before invoking login (missing runtime,
        // bundle mismatch, unsafe lifecycle state). Never schedule an auto-loop.
        if runtime.busy != true && connectionOwner == owner {
            attaching=false; connectionOwner=nil; model.finishConnectionInitialization(owner:owner,verified:false)
            connectionMessage="连接初始化失败；组件待初始化，请检查组件后重新初始化连接"; model.startPolling(); renderIfReady()
        }
    }
    @objc func reinitializeConnection() {
        guard !terminationPending, !attaching, !model.pending, desktop?.blocksQuit == false else { return }
        NSApp.activate(ignoringOtherApps:true)
        let alert=NSAlert(); alert.messageText="重新初始化连接？"
        alert.informativeText="仅重新连接本机组件；不重复上次操作、不安装或启停 VPN。丢弃客户端临时未知状态须重新验证当前组件；上次操作结果不追认为成功。磁盘中的历史 UNKNOWN 不会删除或解除。"
        alert.addButton(withTitle:"重新初始化连接");alert.addButton(withTitle:"取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        connectRuntime(userInitiated:true,discardUnknown:true)
    }
    func sessionExpired() {
        guard !expiryAttempted, !terminationPending, !model.pending, !model.uncertain, !model.initializingConnection else { return }
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
        guard !terminationPending, !model.pending, !model.uncertain, !model.initializingConnection else {
            connectionMessage = model.uncertain ? "当前操作结果未知，未开始安装／更新组件；请在完整控制台核实" : "当前操作进行中，未开始安装／更新组件；请等待结果后核实"
            renderIfReady(); return
        }
        // This explicit install click is the only app-owned setup confirmation.
        // Migration inspection is asynchronous, so do not queue a later modal.
        guard confirm("安装／更新 AnyTLS 组件？更新将停止 VPN，保留配置；更新完成后须从菜单恢复 VPN。",risk:false) else { return }
        desktop?.consentMigration={ wasRunning in wasRunning }
        desktop?.initialize(login:runtimeLogin)
    }
    @objc func recoverDesktop() {
        guard !terminationPending, !model.pending, !model.uncertain, desktop?.recoveryAllowed==true else { return }
        guard confirm("上次更新结果未知。本次将新建独立事务并再次请求停止 VPN，可能中断网络，再通过系统授权更新组件；旧 UNKNOWN 将原样保留，不会把上次操作标为成功，也不会自动重试或启动 VPN。继续？",risk:false) else { return }
        guard !terminationPending, !model.pending, !model.uncertain else { return }
        desktop?.recoveryActionAllowed={ [weak self, weak runtime=desktop] in
            guard let self=self, let runtime=runtime else { return false }
            return self.desktop === runtime && !self.terminationPending && !self.model.pending && !self.model.uncertain
        }
        desktop?.recover(login:runtimeLogin)
    }
    @objc func completeDesktopRecovery() {
        guard !terminationPending, !model.pending, !model.uncertain, desktop?.recoveryCompletionAllowed==true else { return }
        guard confirm("检查并继续已确认停止的组件更新？仅完成已授权的更新，不会再次停止、重新授权或启动 VPN。",risk:false) else { return }
        guard !terminationPending, !model.pending, !model.uncertain else { return }
        desktop?.recoveryActionAllowed={ [weak self, weak runtime=desktop] in
            guard let self=self, let runtime=runtime else { return false }
            return self.desktop === runtime && !self.terminationPending && !self.model.pending && !self.model.uncertain
        }
        desktop?.completeRecovery(login:runtimeLogin)
    }
    @objc func retryDesktopAuthorization() { guard !terminationPending, !model.pending, !model.uncertain else { return }; desktop?.retryAuthorization(login:runtimeLogin) }
    private func runtimeLogin(_ origin: String, _ secret: String, _ completion: @escaping (Bool)->Void) {
        guard let endpoint=try? LocalEndpoint(origin), !model.pending,
              !model.uncertain || model.initializingConnection else { completion(false); return }
        let owner=connectionOwner, runtime=desktop
        func current()->Bool { self.connectionOwner == owner && self.desktop === runtime }
        // Bootstrap application secret stays in memory/private-pipe authority.
        model.stopPolling(); model.api.reset(endpoint:endpoint)
        // Own completion before login: API generation changes intentionally drop
        // callbacks, including a 401 during proof. They must not strand attach.
        var finished=false, epoch=self.model.api.generation
        func finish(_ value: Bool) {
            guard !finished else { return }; finished=true
            guard current() else { completion(false); return }
            let fresh=value && self.model.api.generation == epoch
            self.attaching=false
            if let owner=owner {
                self.connectionOwner=nil
                self.model.finishConnectionInitialization(owner:owner,verified:fresh)
            } else if !fresh && self.model.api.generation == epoch { self.model.api.reset(); self.model.clearObservations() }
            let verified=fresh && self.model.api.authenticated && !self.model.initializingConnection
            self.connectionMessage=verified ? "连接初始化完成；本机组件已连接" : "连接初始化失败；请检查组件后重新初始化连接"
            if verified { self.expiryAttempted=false }
            self.model.startPolling(); if verified { self.model.refresh() }
            self.renderIfReady(); completion(verified)
        }
        model.api.login(password:secret) { ok in
            guard current(), self.model.api.generation == epoch else { finish(false); return }
            guard ok else { finish(false); return }
            var verifyingReadiness=false
            func observations(_ remaining: Int) {
                guard !finished, current(), self.model.api.generation == epoch else { return }
                if self.model.connectionObservationsReady {
                    guard !verifyingReadiness else { return }; verifyingReadiness=true
                    let tag=self.model.etag
                    runtime?.verifyConnectionReadiness { ready in
                        guard current(), self.model.api.generation == epoch else { return }
                        finish(ready && tag == self.model.etag && self.model.connectionObservationsReady)
                    }
                    return
                }
                guard remaining>0 else { finish(false); return }
                DispatchQueue.main.asyncAfter(deadline:.now()+0.1) { observations(remaining-1) }
            }
            func read(_ remaining: Int) {
                guard !finished, current(), self.model.api.generation == epoch else { return }
                guard remaining>0 else { finish(false); return }
                let sent=self.model.api.request("/status") { result in
                    guard current(), self.model.api.generation == epoch else { finish(false); return }
                    if case .success(let reply)=result, reply.status==200,
                       ServiceStatus.parse(reply.body) != nil, runtime?.validConsoleMetadata(reply.body)==true {
                        if owner != nil { self.model.refresh(); observations(100) } else { finish(true) }
                    } else { finish(false) }
                }
                if !sent { DispatchQueue.main.asyncAfter(deadline:.now()+0.25) { read(remaining-1) } }
            }
            read(32)
        }
        epoch=model.api.generation // login synchronously resets its session.
        DispatchQueue.main.asyncAfter(deadline:.now()+12) { finish(false) }
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
