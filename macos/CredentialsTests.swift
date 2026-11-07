import AppKit
import Security

final class CredentialHTTP: URLProtocol {
    static var status=200
    static var calls: [URLRequest]=[]
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.calls.append(request)
        let login=request.url!.path.hasSuffix("/login")
        let body: [String:Any] = login ? ["csrf":String(repeating:"t",count:43),"expiresIn":3600] : [:]
        client?.urlProtocol(self,didReceive:HTTPURLResponse(url:request.url!,statusCode:login ? Self.status : 200,httpVersion:nil,headerFields:nil)!,cacheStoragePolicy:.notAllowed)
        client?.urlProtocol(self,didLoad:try! JSONSerialization.data(withJSONObject:body)); client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
final class DeniedDeleteStore: CredentialStore {
    override func delete(_ endpoint: LocalEndpoint) throws { throw CredentialFailure(status:errSecInteractionNotAllowed) }
}

@main struct CredentialTests {
    static var checks: [String]=[]
    static func check(_ ok: Bool, _ name: String) {
        guard ok else { print("FAIL: "+name); exit(1) }; checks.append(name); print("PASS: "+name)
    }
    static func wait(_ ready: () -> Bool) {
        let end=Date().addingTimeInterval(9)
        while !ready() && Date()<end { RunLoop.main.run(until:Date().addingTimeInterval(0.02)) }
        check(ready(),"async completed")
    }
    static func client() -> MenuModel {
        MenuModel(api:APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:49173"),configuration:{ let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[CredentialHTTP.self]; return c }),connectivityMonitor:nil)
    }
    static func main() throws {
        let app=PasteApplication.shared; app.setActivationPolicy(.accessory); app.finishLaunching(); installEditMenu()
        // Background failure presentation is covered through production AppDelegate
        // and actual AppKit controls in FocusTests, not an alert-dedup state helper.
        let out=URL(fileURLWithPath:CommandLine.arguments[1]); try FileManager.default.createDirectory(at:out,withIntermediateDirectories:true)
        let path=out.appendingPathComponent("fixture-"+UUID().uuidString+".keychain").path
        let key="OWNED_SYNTHETIC_KEYCHAIN_ONLY", secret="  SYNTHETIC_粘贴_🔑_e\u{301}  "
        var kc: SecKeychain?
        let created=key.withCString { SecKeychainCreate(path,UInt32(key.utf8.count),$0,false,nil,&kc) }
        check(created == errSecSuccess,"owned private keychain created without changing search list")
        let store=CredentialStore(keychain:kc!)
        let endpoint=try LocalEndpoint("http://127.0.0.1:49173"), other=try LocalEndpoint("http://localhost:49174")
        check(try store.read(endpoint) == nil,"initial private keychain not found")
        try store.save(secret,endpoint:endpoint)
        check(try store.read(endpoint) == secret,"actual private keychain exact Unicode read")
        check(try CredentialStore(keychain:kc!).read(endpoint) == secret,"new store instance reads persisted item")
        check(try store.read(other) == nil,"endpoint isolated")
        try store.save("UPDATED_SYNTHETIC",endpoint:endpoint)
        check(try store.read(endpoint) == "UPDATED_SYNTHETIC","actual private keychain update")
        let suite="org.anytls.menubar.fixture."+UUID().uuidString
        let defaults=UserDefaults(suiteName:suite)!; defer { defaults.removePersistentDomain(forName:suite) }
        let memory=RememberedCredentials(defaults:defaults,store:store)
        check(memory.remember,"remember defaults ON")
        try memory.connected(endpoint:endpoint,secret:secret,remember:true)
        check(try RememberedCredentials(defaults:UserDefaults(suiteName:suite)!,store:store).restored()?.1 == secret,"relaunch preferences and private keychain restore")
        check(defaults.persistentDomain(forName:suite)?.count == 2,"defaults contains only two nonsecret preferences")
        defaults.set("http://remote.invalid",forKey:"lastEndpoint")
        check(try memory.restored() == nil,"remote endpoint rejected before credential lookup")
        defaults.set(endpoint.origin,forKey:"lastEndpoint")
        let ui=AppDelegate(model:client(),credentials:memory); ui.showSettings()
        let field=ui.password!, window=field.window!
        let board=NSPasteboard(name:NSPasteboard.Name("org.anytls.fixture."+UUID().uuidString)); defer { board.releaseGlobally() }
        board.setString(secret,forType:.string); field.pasteboard={ board }
        func prepare() { field.stringValue=""; window.makeKeyAndOrderFront(nil); app.activate(ignoringOtherApps:true); RunLoop.main.run(until:Date().addingTimeInterval(0.15)); window.makeKey(); window.makeFirstResponder(field) }
        func exact() -> Bool { (field.currentEditor()?.string ?? field.stringValue) == secret }
        prepare(); ui.pasteButton.performClick(nil)
        check(exact(),"explicit paste button inserts exact Unicode into actual secure editor")
        check((field.cell as? NSSecureTextFieldCell)?.echosBullets == true,"native secure cell masks password")
        prepare()
        let event=NSEvent.keyEvent(with:.keyDown,location:.zero,modifierFlags:.command,timestamp:0,windowNumber:window.windowNumber,context:nil,characters:"v",charactersIgnoringModifiers:"v",isARepeat:false,keyCode:9)!
        app.sendEvent(event)
        check(exact(),"NSApp sendEvent CmdV pastes private fixture into production window")
        for (key,code) in [("c",UInt16(8)),("x",UInt16(7))] {
            let blocked=NSEvent.keyEvent(with:.keyDown,location:.zero,modifierFlags:.command,timestamp:0,windowNumber:window.windowNumber,context:nil,characters:key,charactersIgnoringModifiers:key,isARepeat:false,keyCode:code)!
            app.sendEvent(blocked)
            check(exact() && board.string(forType:.string) == secret,"secure command \(key) never exports or cuts password")
        }
        prepare()
        let right=NSEvent.mouseEvent(with:.rightMouseDown,location:field.convert(NSPoint(x:10,y:10),to:nil),modifierFlags:[],timestamp:0,windowNumber:window.windowNumber,context:nil,eventNumber:1,clickCount:1,pressure:1)!
        let context=(window as! PasteWindow).passwordContextMenu(for:right)!
        check(context.items.count == 1 && context.items[0].title == "粘贴","production window right-click hit test provides only paste")
        context.performActionForItem(at:0)
        check(exact(),"native context menu action inserts exact Unicode")
        check(board.string(forType:.string) == secret,"private pasteboard unchanged; general clipboard never accessed by fixture")
        window.makeFirstResponder(nil)
        field.stringValue=secret; ui.login()
        check(!field.isEnabled && !ui.address.isEnabled,"login disables editing while in flight")
        wait { field.isEnabled }
        check(ui.model.api.authenticated && (try? store.read(endpoint)) == secret,"successful mocked HTTP login saves actual keychain")
        let restoredUI=AppDelegate(model:client(),credentials:RememberedCredentials(defaults:defaults,store:store)); restoredUI.showSettings()
        CredentialHTTP.calls=[]; restoredUI.restoreOnce(); wait { restoredUI.password.isEnabled }
        restoredUI.restoreOnce(); RunLoop.main.run(until:Date().addingTimeInterval(0.1))
        check(CredentialHTTP.calls.filter { $0.url!.path.hasSuffix("/login") }.count == 1,"auto-login once per launch")
        check(!CredentialHTTP.calls.contains { $0.url!.path.contains("/service/") || $0.url!.path.contains("/selection") },"auto-login never starts reloads or mutates VPN")
        for status in [401,429] {
            CredentialHTTP.status=status; let failed=AppDelegate(model:client(),credentials:memory); failed.showSettings(); CredentialHTTP.calls=[]; failed.restoreOnce(); wait { failed.password.isEnabled }; failed.restoreOnce()
            check(CredentialHTTP.calls.filter { $0.url!.path.hasSuffix("/login") }.count == 1 && !failed.model.api.authenticated,"HTTP \(status) no auto retry")
            check((try? store.read(endpoint)) == secret,"failed authentication does not overwrite saved password")
        }
        CredentialHTTP.status=200
        ui.remember.state = .off; ui.rememberChanged()
        check(try store.read(endpoint) == nil,"uncheck deletes only current endpoint item")
        check(try !memory.remember && memory.restored() == nil,"uncheck disables next-launch auto-login")
        try store.save(secret,endpoint:other); try store.save(secret,endpoint:endpoint)
        ui.forgetSaved(); check(try store.read(endpoint) == nil,"forget deletes exact item")
        check(try store.read(other) == secret,"forget preserves other endpoint")
        try store.delete(endpoint); check(try store.read(endpoint) == nil,"delete notfound idempotent")
        // Lock only our newly created keychain; noninteractive queries must fail, never prompt.
        try store.save(secret,endpoint:endpoint)
        check(SecKeychainLock(kc!) == errSecSuccess,"owned fixture keychain locked")
        do { _=try store.read(endpoint); check(false,"locked read must fail") } catch { check(true,"locked keychain read reports unavailable not missing") }
        ui.remember.state = .on; field.stringValue=secret; ui.login(); wait { field.isEnabled }
        check(ui.model.api.authenticated && ui.feedback.stringValue.contains("未保存"),"login success plus keychain failure is visibly not saved")
        ui.credentials=RememberedCredentials(defaults:defaults,store:DeniedDeleteStore(keychain:kc!))
        ui.forgetSaved(); check(ui.feedback.stringValue.contains("删除密码失败") && !memory.remember,"injected denied forget does not falsely claim deletion; auto-login off")
        _=key.withCString { SecKeychainUnlock(kc!,UInt32(key.utf8.count),$0,true) }
        try store.delete(endpoint); try store.delete(other)
        check(SecKeychainDelete(kc!) == errSecSuccess,"only owned fixture keychain deleted")
        window.makeFirstResponder(nil); field.stringValue=""
        let view=window.contentView!; window.appearance=NSAppearance(named:.aqua); view.displayIfNeeded()
        let rep=view.bitmapImageRepForCachingDisplay(in:view.bounds)!; view.cacheDisplay(in:view.bounds,to:rep)
        try rep.representation(using:.png,properties:[:])!.write(to:out.appendingPathComponent("credentials-ui.png"))
        try JSONSerialization.data(withJSONObject:["checks":checks,"count":checks.count,"privateKeychain":true,"generalPasteboardAccessed":false,"realNetworkRequests":0],options:[.prettyPrinted,.sortedKeys]).write(to:out.appendingPathComponent("credential-checks.json"))
        print("CREDENTIAL_TESTS_OK checks=\(checks.count)")
    }
}
