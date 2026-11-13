import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum ConnectivityState: Equatable { case idle, checking, online, offline }
enum ConnectivityReason: String { case empty204 = "EMPTY_204", checksFailed = "CHECKS_FAILED" }
struct ConnectivityObservation: Equatable {
    let finishedAt: TimeInterval
    let reason: ConnectivityReason
}

// Main-queue owned. This checks OS-routed HTTPS, not a particular node/exit.
// Call check() while authenticated/running; cancel() on service/session changes.
final class ConnectivityMonitor {
    private var storedState: ConnectivityState = .idle
    private var validUntil: TimeInterval?
    // A read must not publish stale proof, mutate state, or synchronously render.
    // The timer still advances stored state and proactively notifies observers.
    var state: ConnectivityState {
        guard storedState == .online else { return storedState }
        guard let until = validUntil, now() < until else { return .idle }
        return .online
    }
    var onChange: ((ConnectivityState) -> Void)?
    private static let endpoints = [
        URL(string: "https://www.gstatic.com/generate_204")!,
        URL(string: "https://cp.cloudflare.com/generate_204")!
    ]
    private let configuration: () -> URLSessionConfiguration
    private let now: () -> TimeInterval
    private var generation: UInt64 = 0
    private var session: URLSession?
    private var delegate: ConnectivityDelegate?
    private var lastFinished: TimeInterval?
    private(set) var observation: ConnectivityObservation?
    private var retryInterval: TimeInterval = 30
    private var deadline: TimeInterval = 0
    private var remaining = 0
    private var expiry: DispatchWorkItem?

    init(configuration: @escaping () -> URLSessionConfiguration = { .ephemeral },
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.configuration = configuration
        self.now = now
    }

    func check(force: Bool = false) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard session == nil else { return } // force never overlaps an owned batch.
        if !force, let last = lastFinished, now() - last < retryInterval { return }
        expiry?.cancel(); expiry = nil
        generation &+= 1
        let owner = generation
        deadline = now() + 5
        remaining = Self.endpoints.count
        let config = configuration()
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        config.urlCredentialStorage = nil
        config.connectionProxyDictionary = [:] // Do not inherit an HTTP/system proxy.
        config.httpAdditionalHeaders = nil
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 5
        #if os(macOS)
        config.waitsForConnectivity = false
        #endif
        let receiver = ConnectivityDelegate { [weak self] success in
            guard let self = self, self.generation == owner, self.session != nil else { return }
            guard self.now() < self.deadline else { self.finish(.offline); return }
            self.remaining -= 1
            if success { self.finish(.online) }
            else if self.remaining == 0 { self.finish(.offline) }
        }
        let batch = URLSession(configuration: config, delegate: receiver, delegateQueue: .main)
        delegate = receiver
        session = batch
        let tasks = Self.endpoints.map { url -> URLSessionDataTask in
            var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 5)
            request.httpMethod = "GET"
            request.httpShouldHandleCookies = false
            let task = batch.dataTask(with: request)
            receiver.register(task: task, url: url)
            return task
        }
        setState(.checking)
        guard generation == owner, session === batch else { return }
        tasks.forEach { $0.resume() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            guard let self = self, self.generation == owner, self.session != nil else { return }
            self.finish(.offline)
        }
    }

    // Also clears a completed proof, and allows an immediate new service generation.
    func cancel() {
        dispatchPrecondition(condition: .onQueue(.main))
        generation &+= 1
        expiry?.cancel(); expiry = nil
        session?.invalidateAndCancel(); session = nil; delegate = nil
        remaining = 0; lastFinished = nil; observation = nil
        setState(.idle)
    }

    func reset() { cancel() }

    private func finish(_ result: ConnectivityState) {
        generation &+= 1
        session?.invalidateAndCancel(); session = nil; delegate = nil
        remaining = 0
        let finished = now()
        lastFinished = finished
        observation = ConnectivityObservation(finishedAt:finished,reason:result == .online ? .empty204 : .checksFailed)
        validUntil = result == .online ? finished + 45 : nil
        retryInterval = result == .offline ? 15 : 30
        if result == .online {
            let owner = generation
            let work = DispatchWorkItem { [weak self] in
                guard let self = self, self.generation == owner, self.storedState == .online else { return }
                self.expiry = nil
                self.setState(.idle) // Never retain a successful proof beyond 45 seconds.
            }
            expiry = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 45, execute: work)
        }
        setState(result)
    }

    private func setState(_ value: ConnectivityState) {
        if value != .online { validUntil = nil }
        guard storedState != value else { return }
        storedState = value; onChange?(value)
    }

    deinit { expiry?.cancel(); session?.invalidateAndCancel() }
}

// Serial main-queue callbacks; no response body is accumulated. Any delivered
// byte fails the strict empty-body requirement immediately (stronger than 1 KiB).
private final class ConnectivityDelegate: NSObject, URLSessionDataDelegate {
    private struct Probe { let url: URL; var valid = false; var failed = false }
    private var probes: [Int: Probe] = [:]
    private let completed: (Bool) -> Void
    init(completed: @escaping (Bool) -> Void) { self.completed = completed }
    func register(task: URLSessionTask, url: URL) { probes[task.taskIdentifier] = Probe(url: url) }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard var probe = probes[dataTask.taskIdentifier] else { completionHandler(.cancel); return }
        guard let http = response as? HTTPURLResponse, http.url == probe.url,
              http.statusCode == 204, response.expectedContentLength <= 0,
              http.value(forHTTPHeaderField: "Transfer-Encoding") == nil else {
            probe.failed = true; probes[dataTask.taskIdentifier] = probe
            completionHandler(.cancel); return
        }
        probe.valid = true; probes[dataTask.taskIdentifier] = probe
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard !data.isEmpty, var probe = probes[dataTask.taskIdentifier] else { return }
        probe.failed = true; probes[dataTask.taskIdentifier] = probe
        dataTask.cancel()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let probe = probes.removeValue(forKey: task.taskIdentifier) else { return }
        completed(error == nil && probe.valid && !probe.failed)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        if var probe = probes[task.taskIdentifier] { probe.failed = true; probes[task.taskIdentifier] = probe }
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // System certificate/hostname validation only; never accept custom trust or credentials.
        #if os(macOS)
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil); return
        }
        #endif
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
