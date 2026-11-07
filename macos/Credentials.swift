import AppKit
import Security

// A single exact endpoint/account item; never enumerate the user's keychain.
struct CredentialFailure: Error { let status: OSStatus }
class CredentialStore {
    static let service = "org.anytls.menubar.candidate.credentials"
    let keychain: SecKeychain?
    init(keychain: SecKeychain? = nil) { self.keychain=keychain }
    private func query(_ endpoint: LocalEndpoint) -> [String:Any] {
        var q: [String:Any] = [kSecClass as String:kSecClassGenericPassword,
            kSecAttrService as String:Self.service, kSecAttrAccount as String:endpoint.origin+"|admin",
            kSecAttrSynchronizable as String:false, kSecUseAuthenticationUI as String:kSecUseAuthenticationUIFail]
        if let keychain=keychain { q[kSecMatchSearchList as String]=[keychain] }
        return q
    }
    func read(_ endpoint: LocalEndpoint) throws -> String? {
        var q=query(endpoint); q[kSecReturnData as String]=true; q[kSecMatchLimit as String]=kSecMatchLimitOne
        var value: CFTypeRef?; let status=SecItemCopyMatching(q as CFDictionary,&value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw CredentialFailure(status:status) }
        guard let data=value as? Data, let text=String(data:data,encoding:.utf8) else { throw CredentialFailure(status:errSecDecode) }
        return text
    }
    func save(_ secret: String, endpoint: LocalEndpoint) throws {
        let data=Data(secret.utf8)
        let status=SecItemUpdate(query(endpoint) as CFDictionary,[kSecValueData as String:data] as CFDictionary)
        if status == errSecItemNotFound {
            var q=query(endpoint); q.removeValue(forKey:kSecMatchSearchList as String)
            q[kSecValueData as String]=data
            q[kSecAttrAccessible as String]=kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            if let keychain=keychain { q[kSecUseKeychain as String]=keychain }
            let added=SecItemAdd(q as CFDictionary,nil)
            guard added == errSecSuccess else { throw CredentialFailure(status:added) }; return
        }
        guard status == errSecSuccess else { throw CredentialFailure(status:status) }
    }
    func delete(_ endpoint: LocalEndpoint) throws {
        let status=SecItemDelete(query(endpoint) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw CredentialFailure(status:status) }
    }
}

// Only these two non-secret preferences go into this app's defaults namespace.
final class RememberedCredentials {
    let defaults: UserDefaults
    let store: CredentialStore
    init(defaults: UserDefaults = .standard, store: CredentialStore = CredentialStore()) { self.defaults=defaults; self.store=store }
    var remember: Bool { defaults.object(forKey:"rememberPassword") == nil ? true : defaults.bool(forKey:"rememberPassword") }
    var endpoint: LocalEndpoint? { defaults.string(forKey:"lastEndpoint").flatMap { try? LocalEndpoint($0) } }
    func restored() throws -> (LocalEndpoint,String)? {
        guard remember, let endpoint=endpoint, let secret=try store.read(endpoint) else { return nil }
        return (endpoint,secret)
    }
    // Call only after a successful authenticated response.
    func connected(endpoint: LocalEndpoint, secret: String, remember: Bool) throws {
        if remember { try store.save(secret,endpoint:endpoint) } else { try store.delete(endpoint) }
        defaults.set(endpoint.origin,forKey:"lastEndpoint"); defaults.set(remember,forKey:"rememberPassword")
    }
    func forget(_ endpoint: LocalEndpoint) throws {
        // Disable auto-login even if a locked keychain prevents deletion; report the deletion failure.
        defaults.set(false,forKey:"rememberPassword")
        try store.delete(endpoint)
    }
}

// The three paste entry points share the actual secure field-editor insertion.
// Injection is solely for isolated native fixtures: production always uses .general.
final class PasteSecureField: NSSecureTextField, NSMenuItemValidation, NSTextViewDelegate {
    var pasteboard: () -> NSPasteboard = { .general }
    @objc func paste(_ sender: Any?) {
        guard isEnabled, let window=window else { return }
        window.makeFirstResponder(self)
        guard let editor=currentEditor(), let text=pasteboard().string(forType:.string) else { return }
        editor.insertText(text)
    }
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command,
           event.charactersIgnoringModifiers?.lowercased() == "v" { paste(nil); return true }
        return super.performKeyEquivalent(with:event)
    }
    func pasteMenu() -> NSMenu {
        let menu=NSMenu(); let row=NSMenuItem(title:"粘贴",action:#selector(paste(_:)),keyEquivalent:"v")
        row.target=self; menu.addItem(row); return menu
    }
    override func menu(for event: NSEvent) -> NSMenu? { pasteMenu() }
    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool { isEnabled && menuItem.action == #selector(paste(_:)) }
}

final class PasteApplication: NSApplication {
    override func sendEvent(_ event: NSEvent) {
        if event.type == .keyDown, event.modifierFlags.contains(.command),
           let window=event.window as? PasteWindow,
           let editor=window.firstResponder as? NSTextView, editor.delegate is PasteSecureField,
           ["v","c","x"].contains(event.charactersIgnoringModifiers?.lowercased() ?? ""),
           window.performKeyEquivalent(with:event) { return }
        super.sendEvent(event)
    }
}

final class PasteWindow: NSWindow {
    func passwordContextMenu(for event: NSEvent) -> NSMenu? {
        guard let root=contentView else { return nil }
        for case let field as PasteSecureField in root.subviews {
            if field.bounds.contains(field.convert(event.locationInWindow,from:nil)) { return field.pasteMenu() }
        }
        return nil
    }
    override func sendEvent(_ event: NSEvent) {
        if event.type == .rightMouseDown, let menu=passwordContextMenu(for:event), let root=contentView {
            NSMenu.popUpContextMenu(menu,with:event,for:root); return
        }
        super.sendEvent(event)
    }
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if let editor=firstResponder as? NSTextView, let field=editor.delegate as? PasteSecureField,
           event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command {
            switch event.charactersIgnoringModifiers?.lowercased() {
            case "v": field.paste(nil); return true
            case "c", "x": return true // Never export a secret.
            default: break
            }
        }
        return super.performKeyEquivalent(with:event)
    }
}

func installEditMenu() {
    let main=NSMenu(), appItem=NSMenuItem(), editItem=NSMenuItem()
    main.addItem(appItem); let appMenu=NSMenu(); appItem.submenu=appMenu
    let quit=NSMenuItem(title:"退出 AnyTLS 菜单栏",action:#selector(NSApplication.terminate(_:)),keyEquivalent:"q"); appMenu.addItem(quit)
    main.addItem(editItem); let edit=NSMenu(title:"编辑"); editItem.submenu=edit
    for (title,action,key) in [("撤销","undo:","z"),("剪切","cut:","x"),("复制","copy:","c"),("粘贴","paste:","v"),("全选","selectAll:","a")] {
        edit.addItem(NSMenuItem(title:title,action:NSSelectorFromString(action),keyEquivalent:key))
    }
    NSApp.mainMenu=main
}
