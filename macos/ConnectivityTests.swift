import Foundation
#if canImport(Darwin)
import Darwin
#endif
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

private final class ConnectivityFixture: URLProtocol {
    enum Reply { case empty, status(Int), body, length, redirect, tls, hang, stalledBody, late }
    static let lock = NSLock()
    static var replies: [Reply] = []
    static var requests: [URLRequest] = []
    private var stopped = false
    private let stateLock = NSLock()
    override class func canInit(with request: URLRequest) -> Bool { true } // Never WAN.
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    static func prepare(_ plan: [Reply]) { lock.lock(); replies = plan; requests = []; lock.unlock() }
    static var count: Int { lock.lock(); defer { lock.unlock() }; return requests.count }
    override func startLoading() {
        Self.lock.lock()
        let index = Self.requests.count
        Self.requests.append(request)
        let reply = index < Self.replies.count ? Self.replies[index] : .tls
        Self.lock.unlock()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.04) { [self] in
            stateLock.lock(); let cancelled = stopped; stateLock.unlock()
            if cancelled { return }
            let url = request.url!
            func response(_ status: Int, _ headers: [String: String] = [:]) {
                client?.urlProtocol(self, didReceive: HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!, cacheStoragePolicy: .notAllowed)
            }
            switch reply {
            case .hang: return
            case .stalledBody: response(204); return
            case .tls: client?.urlProtocol(self, didFailWithError: URLError(.serverCertificateUntrusted))
            case .redirect:
                let other = URLRequest(url: URL(string: "https://captive.invalid/login")!)
                client?.urlProtocol(self, wasRedirectedTo: other, redirectResponse: HTTPURLResponse(url: url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": other.url!.absoluteString])!)
                client?.urlProtocolDidFinishLoading(self)
            case .status(let status):
                response(status); client?.urlProtocolDidFinishLoading(self)
            case .empty:
                response(204); client?.urlProtocolDidFinishLoading(self)
            case .length:
                response(204, ["Content-Length": "2048"]); client?.urlProtocolDidFinishLoading(self)
            case .body:
                response(204)
                client?.urlProtocol(self, didLoad: Data(repeating: 65, count: 1024))
                client?.urlProtocolDidFinishLoading(self)
            case .late:
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [self] in
                    stateLock.lock(); let cancelled = stopped; stateLock.unlock()
                    if !cancelled { response(204); client?.urlProtocolDidFinishLoading(self) }
                }
            }
        }
    }
    override func stopLoading() { stateLock.lock(); stopped = true; stateLock.unlock() }
}

@main private enum ConnectivityTests {
    static var assertions = 0
    static func expect(_ value: @autoclosure () -> Bool, _ name: String) {
        guard value() else { fatalError("FAIL: \(name)") }
        assertions += 1; print("PASS: \(name)")
    }
    static func pump(_ seconds: TimeInterval) {
        let end = Date().addingTimeInterval(seconds)
        while Date() < end { _ = RunLoop.main.run(mode: .default, before: min(end, Date().addingTimeInterval(0.01))) }
    }
    static func wait(_ monitor: ConnectivityMonitor, timeout: TimeInterval = 1) {
        let end = Date().addingTimeInterval(timeout)
        while monitor.state == .checking && Date() < end { pump(0.01) }
        expect(monitor.state != .checking, "batch completion bounded")
    }
    static func make(_ replies: [ConnectivityFixture.Reply]) -> ConnectivityMonitor {
        ConnectivityFixture.prepare(replies)
        return ConnectivityMonitor(configuration: {
            let config = URLSessionConfiguration.ephemeral
            config.protocolClasses = [ConnectivityFixture.self]
            return config
        })
    }
    static func main() {
        #if canImport(Darwin)
        setbuf(stdout, nil)
        #endif
        let started = ProcessInfo.processInfo.systemUptime
        var events: [ConnectivityState] = []
        let success = make([.empty, .tls])
        success.onChange = { state in
            expect(Thread.isMainThread, "main-queue change callback")
            events.append(state)
        }
        success.check()
        expect(success.state == .checking, "checking is synchronous")
        for _ in 0..<50 { success.check(force: true) }
        wait(success)
        expect(success.state == .online, "one empty 204 succeeds despite other TLS failure")
        expect(ConnectivityFixture.count == 2, "force coalesces to exactly two requests")
        expect(events == [.checking, .online], "clean success state sequence")
        let requests = ConnectivityFixture.requests
        expect(Set(requests.compactMap { $0.url?.absoluteString }) == Set(["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"]), "fixed exact HTTPS endpoints only")
        expect(requests.allSatisfy { $0.httpMethod == "GET" && $0.timeoutInterval == 5 && !$0.httpShouldHandleCookies }, "bounded GET with cookies off")
        expect(requests.allSatisfy { $0.value(forHTTPHeaderField: "Authorization") == nil && $0.value(forHTTPHeaderField: "Origin") == nil && $0.value(forHTTPHeaderField: "X-CSRF-Token") == nil && $0.url?.query == nil }, "no credentials Origin CSRF or URL parameters")
        success.check(); pump(0.06)
        expect(ConnectivityFixture.count == 2, "normal success cadence throttled")
        success.cancel()
        expect(success.state == .idle, "cancel clears proof")
        pump(0.1)
        expect(success.state == .idle, "cancel rejects late callbacks")

        let badPlans: [(String, [ConnectivityFixture.Reply])] = [
            ("200 captive portal rejected", [.status(200), .status(200)]),
            ("302 redirect rejected without follow", [.redirect, .redirect]),
            ("TLS certificate failures rejected", [.tls, .tls]),
            ("204 nonempty bodies rejected", [.body, .body]),
            ("204 advertised body rejected at headers", [.length, .length]),
            ("two HTTP failures rejected", [.status(500), .status(503)])
        ]
        for (name, plan) in badPlans {
            let monitor = make(plan); monitor.check(); wait(monitor)
            expect(monitor.state == .offline, name)
            pump(0.03)
            expect(ConnectivityFixture.count == 2, "\(name): only two fixed requests")
            monitor.cancel()
        }

        let cancelled = make([.late, .late])
        cancelled.check(); pump(0.08); cancelled.cancel()
        ConnectivityFixture.prepare([.status(200), .status(200)])
        cancelled.check(force: true); wait(cancelled); pump(0.4)
        expect(cancelled.state == .offline, "older-generation success cannot overwrite newer failure")
        cancelled.reset()
        expect(cancelled.state == .idle, "reset matches cancel")

        var offset: TimeInterval = 0
        ConnectivityFixture.prepare([.status(500), .status(500)])
        let throttled = ConnectivityMonitor(configuration: {
            let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [ConnectivityFixture.self]; return config
        }, now: { ProcessInfo.processInfo.systemUptime + offset })
        throttled.check(); wait(throttled)
        offset += 14; throttled.check(); pump(0.03)
        expect(ConnectivityFixture.count == 2, "failure backoff rejects early retry")
        offset += 2; throttled.check(); wait(throttled)
        expect(ConnectivityFixture.count == 4, "failure retry allowed after fifteen seconds")
        throttled.cancel()

        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [ConnectivityFixture.self]
        config.connectionProxyDictionary = ["HTTPEnable": 1]
        config.httpAdditionalHeaders = ["Authorization": "fixture-only"]
        ConnectivityFixture.prepare([.hang, .stalledBody])
        let timeout = ConnectivityMonitor(configuration: { config })
        timeout.check()
        expect(config.urlCache == nil && config.httpCookieStorage == nil && config.urlCredentialStorage == nil, "cache cookie credential stores disabled")
        expect(config.connectionProxyDictionary?.isEmpty == true && config.httpAdditionalHeaders == nil, "inherited proxies and headers disabled")
        expect(config.timeoutIntervalForRequest == 5 && config.timeoutIntervalForResource == 5, "production deadline configuration")
        let t = ProcessInfo.processInfo.systemUptime
        wait(timeout, timeout: 5.7)
        let elapsed = ProcessInfo.processInfo.systemUptime - t
        expect(timeout.state == .offline && elapsed <= 5.6, "absolute five-second deadline includes stalled body")
        expect(ConnectivityFixture.count == 2, "deadline makes no retries")
        timeout.cancel()

        let freshness = make([.empty, .empty]); freshness.check(); wait(freshness)
        expect(freshness.state == .online, "fresh proof available")
        pump(45.1)
        expect(freshness.state == .idle, "online proof expires after forty-five seconds without new checks")
        expect(ConnectivityFixture.count == 2, "expiry never starts lifecycle or network retries")
        freshness.cancel()
        print("CONNECTIVITY_TESTS_PASS assertions=\(assertions) elapsed=\(ProcessInfo.processInfo.systemUptime - started)")
    }
}
