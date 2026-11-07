import Foundation

// Immutable authority: never carry a quit across a new login or endpoint.
struct QuitAuthContext: Equatable {
    let endpoint: LocalEndpoint
    let generation: Int
}
enum QuitOutcome: Equatable {
    case stopped, blocked, unknown
}
protocol QuitDriver: AnyObject {
    var quitContext: QuitAuthContext? { get }
    func beginQuit(context: QuitAuthContext, completion: @escaping (QuitOutcome) -> Void)
    func abandonQuit(context: QuitAuthContext)
}

// All normal NSApplication termination routes must return .terminateLater and
// call start { NSApp.reply(toApplicationShouldTerminate: $0) }. No NSApp access
// here: closing settings is not termination; force-kill cannot be intercepted.
final class QuitCoordinator {
    enum State: Equatable { case idle, stopping, blocked, ready }
    private(set) var state: State = .idle
    private(set) var message = ""
    var onChange: (() -> Void)?
    private let driver: QuitDriver
    private let deadline: TimeInterval
    private var attempt: UUID?
    private var reply: ((Bool) -> Void)?
    init(model: MenuModel, deadline: TimeInterval = 250) {
        self.driver=model; self.deadline=deadline
    }
    init(driver: QuitDriver, deadline: TimeInterval = 250) {
        self.driver=driver; self.deadline=deadline
    }
    func start(completion: @escaping (Bool) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        // NSApplication has one outstanding termination decision, not one per
        // Cmd-Q. Repeated requests coalesce without a second stop or reply.
        guard state != .stopping else { return }
        guard state != .ready else { completion(true); return }
        guard let context=driver.quitContext else {
            state = .blocked; message="无法确认 VPN 已停止；请连接本机控制台后重试退出"
            onChange?(); completion(false); return
        }
        let id=UUID(); attempt=id; reply=completion; state = .stopping
        message="正在停止 VPN，确认后退出…"; onChange?()
        driver.beginQuit(context:context) { [weak self] outcome in
            guard let self=self, self.attempt == id, self.state == .stopping else { return }
            self.finish(outcome)
        }
        DispatchQueue.main.asyncAfter(deadline: .now()+deadline) { [weak self] in
            guard let self=self, self.attempt == id, self.state == .stopping else { return }
            self.driver.abandonQuit(context:context)
            self.finish(.unknown)
        }
    }
    private func finish(_ outcome: QuitOutcome) {
        dispatchPrecondition(condition: .onQueue(.main))
        attempt=nil
        state = outcome == .stopped ? .ready : .blocked
        message = outcome == .stopped ? "VPN 已确认停止" : (outcome == .unknown ? "停止结果未知；不会退出或重试，请打开控制台核实" : "未能停止 VPN；请检查连接或控制台后重试退出")
        let completion=reply; reply=nil
        onChange?(); completion?(outcome == .stopped)
    }
}

extension MenuModel: QuitDriver {}
