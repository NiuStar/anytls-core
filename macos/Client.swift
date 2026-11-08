import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct APIReply { let status: Int; let body: [String: Any] }
final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
// All client state and completions are owned by the main queue. No credentials on disk.
final class APIClient {
    private(set) var endpoint: LocalEndpoint
    private(set) var generation = 0
    private(set) var csrf = ""
    private(set) var expires: Date?
    var onExpired: (() -> Void)?
    private var session: URLSession!
    private let redirect = NoRedirect()
    private let configuration: () -> URLSessionConfiguration
    private var owners: [String: UUID] = [:]
    init(endpoint: LocalEndpoint, configuration: @escaping () -> URLSessionConfiguration = { .ephemeral }) {
        self.endpoint=endpoint; self.configuration=configuration; newSession()
    }
    private func newSession() {
        let config=configuration()
        config.urlCache=nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest=6; config.timeoutIntervalForResource=190
        // Ephemeral configuration has an isolated, memory-only cookie store.
        config.httpCookieAcceptPolicy = .always; config.httpShouldSetCookies=true
        config.connectionProxyDictionary=[:]
        session=URLSession(configuration:config,delegate:redirect,delegateQueue:nil)
    }
    var authenticated: Bool { !csrf.isEmpty && (expires.map { $0 > Date() } ?? false) }
    func reset(endpoint: LocalEndpoint? = nil) {
        dispatchPrecondition(condition:.onQueue(.main))
        generation += 1; csrf=""; expires=nil; owners.removeAll()
        session.configuration.httpCookieStorage?.removeCookies(since:.distantPast)
        session.invalidateAndCancel()
        if let endpoint=endpoint { self.endpoint=endpoint }
        newSession()
    }
    func expireIfNeeded() {
        if !csrf.isEmpty && !authenticated { reset(); onExpired?() }
    }
    func login(password: String, completion: @escaping (Bool) -> Void) {
        reset(); let epoch=generation
        request("/login",method:"POST",body:["username":"admin","password":password],allowUnauthenticated:true) { [weak self] result in
            guard let self=self, self.generation == epoch else { return }
            if case .success(let r)=result, r.status == 200, let token=r.body["csrf"] as? String,
               token.range(of:#"^[A-Za-z0-9_-]{43}$"#,options:.regularExpression) != nil,
               let seconds=r.body["expiresIn"] as? Int, seconds > 0, seconds <= 28800 {
                self.csrf=token; self.expires=Date().addingTimeInterval(TimeInterval(seconds)); completion(true)
            } else { self.reset(); completion(false) }
        }
    }
    @discardableResult
    func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, etag: String? = nil,
                 allowUnauthenticated: Bool = false, completion: @escaping (Result<APIReply, Error>) -> Void) -> Bool {
        dispatchPrecondition(condition:.onQueue(.main))
        guard owners[path] == nil else { return false }
        guard allowUnauthenticated || authenticated else { completion(.failure(ClientError.unauthenticated)); return false }
        let owner=UUID(), epoch=generation
        owners[path]=owner
        var request=URLRequest(url:URL(string:endpoint.origin+"/api/v1"+path)!)
        request.httpMethod=method; request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue(endpoint.origin,forHTTPHeaderField:"Origin")
        request.setValue(endpoint.origin,forHTTPHeaderField:"X-AnyTLS-Origin")
        request.setValue("same-origin",forHTTPHeaderField:"Sec-Fetch-Site")
        request.setValue("application/json",forHTTPHeaderField:"Accept")
        if method != "GET" { request.setValue(csrf,forHTTPHeaderField:"X-CSRF-Token") }
        if let etag=etag { request.setValue(etag,forHTTPHeaderField:"If-Match") }
        if let body=body { request.httpBody=try? JSONSerialization.data(withJSONObject:body); request.setValue("application/json",forHTTPHeaderField:"Content-Type") }
        if method != "GET" && path != "/login" { request.timeoutInterval=185 }
        let task=session.dataTask(with:request) { [weak self] data,response,error in
            DispatchQueue.main.async {
                guard let self=self, self.generation == epoch, self.owners[path] == owner else { return }
                self.owners.removeValue(forKey:path)
                guard error == nil, let response=response as? HTTPURLResponse, let data=data, data.count <= 2*1024*1024,
                      let json=(try? JSONSerialization.jsonObject(with:data)) as? [String:Any] else { completion(.failure(ClientError.transport)); return }
                if response.statusCode == 401 && path != "/login" {
                    // The generation check above precedes clearing this session.
                    self.reset(); self.onExpired?(); completion(.failure(ClientError.unauthenticated)); return
                }
                completion(.success(APIReply(status:response.statusCode,body:json)))
            }
        }
        task.resume()
        let deadline: TimeInterval = method == "GET" || path == "/login" ? 7 : 188
        DispatchQueue.main.asyncAfter(deadline:.now()+deadline) { [weak self, weak task] in
            guard let self=self, self.generation == epoch, self.owners[path] == owner else { return }
            self.owners.removeValue(forKey:path); task?.cancel()
            completion(.failure(ClientError.transport))
        }
        return true
    }
}

final class MenuModel {
    let api: APIClient
    let connectivityMonitor: ConnectivityMonitor?
    private var cachedConnectivity: ConnectivityState = .idle
    private(set) var connectivity: ConnectivityState {
        get {
            // Render reads must validate the cached positive against its monitor.
            guard cachedConnectivity == .online else { return cachedConnectivity }
            return connectivityMonitor?.state == .online ? .online : .idle
        }
        set { cachedConnectivity = newValue }
    }
    private var forceConnectivity=false
    private var sleeping=false
    private var trafficIdentity: String?
    var onChange: (() -> Void)?
    private(set) var status: ServiceStatus?
    private(set) var nodes: [Node] = []
    private(set) var etag = ""
    private(set) var traffic: TrafficRate?
    private(set) var helperAvailable = false
    private(set) var pending = false
    private(set) var uncertain = false
    private(set) var message = "未连接本机控制台"
    private(set) var operationID: String?
    private var pendingPath = "", pendingName: String?
    private var quitOwner: UUID?
    var quitContext: QuitAuthContext? {
        api.authenticated ? QuitAuthContext(endpoint:api.endpoint,generation:api.generation) : nil
    }
    private func ownsQuit(_ context: QuitAuthContext, _ owner: UUID) -> Bool {
        quitOwner == owner && quitContext == context
    }
    // Reserve the same mutation owner before fresh reads. Polling is read-only;
    // login and all menu mutations stay excluded for the entire quit operation.
    func beginQuit(context: QuitAuthContext, completion: @escaping (QuitOutcome) -> Void) {
        dispatchPrecondition(condition:.onQueue(.main))
        guard quitContext == context, !pending, !uncertain, quitOwner == nil else {
            completion(uncertain ? .unknown : .blocked); return
        }
        let owner=UUID(); quitOwner=owner; pending=true; cancelConnectivity()
        message="正在核实并停止 VPN…"; onChange?()
        func finish(_ outcome: QuitOutcome) {
            guard self.quitOwner == owner else { return }
            self.quitOwner=nil; self.pending=false
            if outcome == .unknown { self.uncertain=true }
            self.message = outcome == .stopped ? "VPN 已停止" : (outcome == .unknown ? "停止结果未知；请打开控制台核实" : "退出已取消；无法确认 VPN 已停止")
            self.onChange?(); completion(outcome)
        }
        let readSent=api.request("/status") { [weak self] result in
            guard let self=self, self.ownsQuit(context,owner) else { return }
            guard case .success(let r)=result, r.status == 200, ServiceStatus.parse(r.body) != nil else { finish(.blocked); return }
            let helperSent=self.api.request("/helper/status") { [weak self] result in
                guard let self=self, self.ownsQuit(context,owner) else { return }
                guard case .success(let r)=result, r.status == 200, jsonBool(r.body["available"]) == true else { finish(.blocked); return }
                // Always STOP, even when loaded/running are false: protected DNS
                // snapshots may still require privileged restoration/cleanup.
                self.observationGeneration += 1; self.clearObservations()
                let sent=self.api.request("/service/stop",method:"POST",body:["confirm_insecure":false]) { [weak self] result in
                    guard let self=self, self.ownsQuit(context,owner) else { return }
                    guard case .success(let r)=result else { finish(.unknown); return }
                    let verdict=mutationVerdict(path:"/service/stop",status:r.status,body:r.body)
                    guard verdict == .serviceSucceeded else { finish(verdict == .rejected ? .blocked : .unknown); return }
                    // Acknowledgement owns this STOP. Readback verifies its effect,
                    // but never substitutes for a lost or ambiguous acknowledgement.
                    let verified=self.api.request("/status") { [weak self] result in
                        guard let self=self, self.ownsQuit(context,owner) else { return }
                        guard case .success(let r)=result, r.status == 200,
                              let s=ServiceStatus.parse(r.body), !s.loaded, !s.running else { finish(.unknown); return }
                        finish(.stopped)
                    }
                    if !verified { finish(.unknown) }
                }
                if !sent { finish(.unknown) }
            }
            if !helperSent { finish(.blocked) }
        }
        if !readSent { finish(.blocked) }
    }
    // Own watchdog covers API generation reset/401 callbacks that are deliberately
    // fenced by APIClient. Never clear unknown authority or replay a timed-out STOP.
    func abandonQuit(context: QuitAuthContext) {
        dispatchPrecondition(condition:.onQueue(.main))
        guard quitOwner != nil else { return }
        quitOwner=nil; pending=false; uncertain=true; observationGeneration += 1
        clearObservations(); message="停止结果未知；请打开控制台核实"; onChange?()
    }
    private var statusAt: Date?
    private var nodesAt: Date?
    private var timer: Timer?
    private var tickCount = 0
    private var observationGeneration = 0
    init(api: APIClient, connectivityMonitor: ConnectivityMonitor? = ConnectivityMonitor()) {
        self.api=api; self.connectivityMonitor=connectivityMonitor

        api.onExpired={ [weak self] in
            guard let self=self else { return }
            if self.pending { self.pending=false; self.uncertain=true }
            self.clearObservations(); self.message=self.uncertain ? "会话已失效；先前操作结果未知，请打开控制台核实" : "本机会话已过期；正在重新验证组件，失败后可稍后刷新状态"
            self.onChange?()
        }
    }
    var canMutate: Bool { api.authenticated && !pending && !uncertain && quitOwner == nil && status != nil && helperAvailable }
    private func cancelConnectivity() {
        connectivityMonitor?.onChange=nil; connectivityMonitor?.cancel(); connectivity = .idle
    }
    private func checkConnectivity(force: Bool = false) {
        guard !sleeping, api.authenticated, !pending, !uncertain, status?.running == true,
              let at=statusAt, Date().timeIntervalSince(at)<=15 else { cancelConnectivity(); return }
        let epoch=api.generation, observation=observationGeneration
        connectivityMonitor?.onChange={ [weak self] state in
            guard let self=self, self.api.generation == epoch, self.observationGeneration == observation,
                  !self.sleeping, self.api.authenticated, !self.pending, !self.uncertain,
                  self.status?.running == true, let at=self.statusAt, Date().timeIntervalSince(at)<=15 else { return }
            self.connectivity=state; self.onChange?()
        }
        connectivityMonitor?.check(force:force)
    }
    func environmentChanged(sleeping: Bool = false) {
        self.sleeping=sleeping; observationGeneration += 1; clearObservations(); forceConnectivity=true
        if !sleeping && api.authenticated { refresh() }
        onChange?()
    }
    func clearObservations() { cancelConnectivity(); status=nil; statusAt=nil; nodes=[]; nodesAt=nil; etag=""; traffic=nil; trafficIdentity=nil; helperAvailable=false }
    func login(endpoint: LocalEndpoint, password: String, completion: @escaping (Bool) -> Void) {
        // Never discard an unresolved command simply by changing session/endpoint.
        if pending || quitOwner != nil || (uncertain && endpoint != api.endpoint) { completion(false); return }
        api.reset(endpoint:endpoint); clearObservations(); message="正在连接…"; onChange?()
        api.login(password:password) { [weak self] ok in
            guard let self=self else { return }
            self.message=ok ? (self.uncertain ? "先前操作结果未知；请打开控制台核实" : "已连接本机控制台") : "连接失败；检查端口与应用专用密码"
            if ok { self.refresh() }; self.onChange?(); completion(ok)
        }
    }
    func startPolling() {
        guard timer == nil else { return }
        timer=Timer(timeInterval:0.25,repeats:true) { [weak self] _ in self?.tick() }
        RunLoop.main.add(timer!,forMode:.common)
    }
    func stopPolling() { timer?.invalidate(); timer=nil; cancelConnectivity() }
    func tick() {
        api.expireIfNeeded()
        if let t=traffic, !t.fresh() { traffic=nil }
        if let at=statusAt, Date().timeIntervalSince(at)>15 { status=nil; helperAvailable=false; cancelConnectivity() }
        if let at=nodesAt, Date().timeIntervalSince(at)>15 { nodes=[]; etag="" }
        guard api.authenticated && !sleeping else { traffic=nil; cancelConnectivity(); onChange?(); return }
        readTraffic(); tickCount += 1
        if tickCount % 20 == 0 { refresh() }
        if status?.running == true && !pending && !uncertain { checkConnectivity() }
        onChange?()
    }
    func refresh() {
        guard api.authenticated else { return }
        let epoch=api.generation, observation=observationGeneration
        api.request("/status") { [weak self] result in
            guard let self=self, self.api.generation == epoch, self.observationGeneration == observation else { return }
            if case .success(let r)=result, r.status == 200 { self.status=ServiceStatus.parse(r.body); self.statusAt=Date() }
            else { self.status=nil; self.statusAt=nil }
            if self.status?.running == true && !self.pending && !self.uncertain {
                self.checkConnectivity(force:self.forceConnectivity); self.forceConnectivity=false
            } else { self.cancelConnectivity() }
            self.onChange?()
        }
        api.request("/helper/status") { [weak self] result in
            guard let self=self, self.api.generation == epoch, self.observationGeneration == observation else { return }
            if case .success(let r)=result { self.helperAvailable = r.status == 200 && jsonBool(r.body["available"]) == true }
            else { self.helperAvailable=false }; self.onChange?()
        }
        api.request("/nodes") { [weak self] result in
            guard let self=self, self.api.generation == epoch, self.observationGeneration == observation else { return }
            self.nodes=[]; self.etag=""
            if case .success(let r)=result, r.status == 200, let list=r.body["nodes"] as? [Any],
               let etag=r.body["etag"] as? String, etag.range(of:#"^\"[a-f0-9]{64}\"$"#,options:.regularExpression) != nil {
                let parsed=list.compactMap(Node.parse)
                if parsed.count == list.count { self.nodes=parsed; self.etag=etag; self.nodesAt=Date() }
            }
            self.onChange?()
        }
        readTraffic()
    }
    private func readTraffic() {
        let observation=observationGeneration
        api.request("/traffic") { [weak self] result in
            guard let self=self, self.observationGeneration == observation else { return }
            if case .success(let r)=result, r.status == 200 { self.traffic=TrafficRate.parse(r.body) } else { self.traffic=nil }
            if let identity=self.traffic?.runtimeIdentity {
                if let old=self.trafficIdentity, old != identity {
                    self.cancelConnectivity(); self.status=nil; self.statusAt=nil; self.forceConnectivity=true
                    self.trafficIdentity=identity; self.refresh(); return
                }
                self.trafficIdentity=identity
            }
            self.onChange?()
        }
    }
    func mutate(path: String, name: String? = nil, consent: Bool) {
        guard canMutate, ["/service/start","/service/stop","/service/reload","/nodes/selection"].contains(path),
              let at=statusAt, Date().timeIntervalSince(at)<=15 else { return }
        if path == "/nodes/selection" && (etag.isEmpty || !nodes.contains(where: { $0.name == name && $0.selectable })) { return }
        if path == "/service/start" && (status?.running != false || status?.loaded != false) { return }
        if path == "/service/reload" && status?.running != true { return }
        if path == "/service/stop" && status?.loaded != true && status?.running != true { return }
        cancelConnectivity()
        operationID=nil; observationGeneration += 1; status=nil; traffic=nil
        pending=true; pendingPath=path; pendingName=name; message="正在执行；不会自动重试…"; onChange?()
        var body: [String: Any] = ["confirm_insecure":consent]
        if let name=name { body["name"]=name }
        let sent=api.request(path,method:"POST",body:body,etag:path == "/nodes/selection" ? etag : nil) { [weak self] result in
            guard let self=self else { return }
            self.pending=false; self.observationGeneration += 1; self.clearObservations()
            var verdict: MutationVerdict = .unknown
            var failureReason: String?
            if case .success(let r)=result {
                verdict=mutationVerdict(path:path,status:r.status,body:r.body)
                failureReason=knownMutationFailureReason(path:path,status:r.status,body:r.body)
                if let ref=r.body["startup_operation"] as? [String: Any], ref["timeline_schema"] as? Int == 1, hex(ref["operation_id"],32) { self.operationID=ref["operation_id"] as? String }
            }
            self.uncertain = verdict == .unknown
            switch verdict {
            case .serviceSucceeded: self.message=path == "/service/stop" ? "VPN 已停止" : "VPN 已启动"
            case .savedStopped: self.message="启动节点已保存；VPN 未运行，下次启动生效"
            case .applied: self.message="启动节点已保存并应用；将重新读取状态"
            case .unchanged: self.message="选择未变化；没有重新连接"
            case .rejected:
                if failureReason == "SYSTEM_PROXY_ACTIVE" {
                    self.message="启动失败：系统代理仍启用；请先手动关闭系统代理，再明确选择启动。未自动重试"
                } else {
                    self.message=failureReason == nil ? "请求被拒绝；请刷新或打开控制台检查" : "VPN 操作已失败；清理已核实。请打开控制台检查；未自动重试"
                }
            case .unknown: self.message="操作结果未知；已锁定操作，不自动重试。打开控制台核实"
            }
            self.forceConnectivity = verdict == .applied || (verdict == .serviceSucceeded && path != "/service/stop")
            self.refresh(); self.onChange?()
        }
        if !sent { pending=false; uncertain=true; message="操作状态未知；请打开控制台核实"; onChange?() }
    }
    // Deliberately no 'running means success' reconciliation. A lost response with
    // no operation identity cannot be safely replayed; the full console owns recovery.
}
