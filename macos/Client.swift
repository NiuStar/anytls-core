import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct APIReply { let status: Int; let body: [String: Any]; let etag: String? }
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
    private var tasks: [String: URLSessionDataTask] = [:]
    // One slot covers transport AND decoding, including work abandoned by reset
    // or deadline. Do not queue a successor behind a still-running Foundation parse.
    private var trafficSlot: UUID?
    private let trafficDecoder = DispatchQueue(label:"anytls.traffic.decode",qos:.userInitiated)
    var requestsInFlight: Int { owners.count }
    func cancelProbe() {
        for key in owners.keys.filter({ $0 == "/nodes/probe" || $0.hasPrefix("/nodes/probe#") }) {
            owners.removeValue(forKey:key); tasks.removeValue(forKey:key)?.cancel()
        }
    }
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
        generation += 1; csrf=""; expires=nil; owners.removeAll(); tasks.removeAll()
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
    // Traffic alone crosses this boundary: immutable Data in, value-only rate out.
    // Credentials, JSON object graphs, session and UI state never enter the worker.
    @discardableResult
    func requestTraffic(now: @escaping () -> Date = Date.init, completion: @escaping (Result<TrafficRate?, Error>) -> Void) -> Bool {
        dispatchPrecondition(condition:.onQueue(.main))
        let key="/traffic"
        guard owners[key] == nil, trafficSlot == nil else { return false }
        guard authenticated else { completion(.failure(ClientError.unauthenticated)); return false }
        let owner=UUID(), epoch=generation
        owners[key]=owner; trafficSlot=owner
        var request=URLRequest(url:URL(string:endpoint.origin+"/api/v1/traffic")!)
        request.httpMethod="GET"; request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue(endpoint.origin,forHTTPHeaderField:"Origin")
        request.setValue(endpoint.origin,forHTTPHeaderField:"X-AnyTLS-Origin")
        request.setValue("same-origin",forHTTPHeaderField:"Sec-Fetch-Site")
        request.setValue("application/json",forHTTPHeaderField:"Accept")
        let task=session.dataTask(with:request) { [weak self] data,response,error in
            DispatchQueue.main.async {
                guard let self=self else { return }
                guard self.generation == epoch, self.owners[key] == owner else {
                    if self.trafficSlot == owner { self.trafficSlot=nil }; return
                }
                // This remains a post-buffer bound, not a receive-time memory cap.
                guard error == nil, let response=response as? HTTPURLResponse, let data=data, data.count <= 2*1024*1024 else {
                    self.owners.removeValue(forKey:key); self.tasks.removeValue(forKey:key)
                    if self.trafficSlot == owner { self.trafficSlot=nil }
                    completion(.failure(ClientError.transport)); return
                }
                let status=response.statusCode, parseNow=now()
                self.trafficDecoder.async { [weak self] in
                    precondition(!Thread.isMainThread)
                    let decoded: (Bool, TrafficRate?) = autoreleasepool {
                        guard let json=(try? JSONSerialization.jsonObject(with:data)) as? [String:Any] else { return (false,nil) }
                        return (true,status == 200 ? TrafficRate.parse(json,now:parseNow) : nil)
                    }
                    DispatchQueue.main.async {
                        guard let self=self else { return }
                        dispatchPrecondition(condition:.onQueue(.main))
                        if self.trafficSlot == owner { self.trafficSlot=nil }
                        guard self.generation == epoch, self.owners[key] == owner else { return }
                        self.owners.removeValue(forKey:key); self.tasks.removeValue(forKey:key)
                        guard decoded.0 else { completion(.failure(ClientError.transport)); return }
                        if status == 401 {
                            self.reset(); self.onExpired?(); completion(.failure(ClientError.unauthenticated)); return
                        }
                        completion(.success(decoded.1))
                    }
                }
            }
        }
        tasks[key]=task; task.resume()
        // The original total GET deadline also owns the worker phase. An expired
        // job keeps its slot until completion; it cannot delete a successor owner.
        DispatchQueue.main.asyncAfter(deadline:.now()+7) { [weak self, weak task] in
            guard let self=self, self.generation == epoch, self.owners[key] == owner else { return }
            self.owners.removeValue(forKey:key); self.tasks.removeValue(forKey:key); task?.cancel()
            completion(.failure(ClientError.transport))
        }
        return true
    }
    @discardableResult
    func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, etag: String? = nil,
                 requestIdentity: String? = nil, allowUnauthenticated: Bool = false, completion: @escaping (Result<APIReply, Error>) -> Void) -> Bool {
        dispatchPrecondition(condition:.onQueue(.main))
        let key = path == "/nodes/probe" ? path+"#"+(requestIdentity ?? "single") : path
        guard owners[key] == nil, path != "/traffic" || trafficSlot == nil else { return false }
        guard allowUnauthenticated || authenticated else { completion(.failure(ClientError.unauthenticated)); return false }
        let owner=UUID(), epoch=generation
        owners[key]=owner
        var request=URLRequest(url:URL(string:endpoint.origin+"/api/v1"+path)!)
        request.httpMethod=method; request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue(endpoint.origin,forHTTPHeaderField:"Origin")
        request.setValue(endpoint.origin,forHTTPHeaderField:"X-AnyTLS-Origin")
        request.setValue("same-origin",forHTTPHeaderField:"Sec-Fetch-Site")
        request.setValue("application/json",forHTTPHeaderField:"Accept")
        if method != "GET" { request.setValue(csrf,forHTTPHeaderField:"X-CSRF-Token") }
        if let etag=etag { request.setValue(etag,forHTTPHeaderField:"If-Match") }
        if let body=body { request.httpBody=try? JSONSerialization.data(withJSONObject:body); request.setValue("application/json",forHTTPHeaderField:"Content-Type") }
        if method != "GET" && path != "/login" { request.timeoutInterval = path == "/nodes/probe" ? 11 : 185 }
        let task=session.dataTask(with:request) { [weak self] data,response,error in
            DispatchQueue.main.async {
                guard let self=self, self.generation == epoch, self.owners[key] == owner else { return }
                self.owners.removeValue(forKey:key); self.tasks.removeValue(forKey:key)
                guard error == nil, let response=response as? HTTPURLResponse, let data=data, data.count <= 2*1024*1024,
                      let json=(try? JSONSerialization.jsonObject(with:data)) as? [String:Any] else { completion(.failure(ClientError.transport)); return }
                if response.statusCode == 401 && path != "/login" {
                    // The generation check above precedes clearing this session.
                    self.reset(); self.onExpired?(); completion(.failure(ClientError.unauthenticated)); return
                }
                completion(.success(APIReply(status:response.statusCode,body:json,etag:response.value(forHTTPHeaderField:"ETag"))))
            }
        }
        tasks[key]=task; task.resume()
        let deadline: TimeInterval = path == "/nodes/probe" ? 12 : (method == "GET" || path == "/login" ? 7 : 188)
        DispatchQueue.main.asyncAfter(deadline:.now()+deadline) { [weak self, weak task] in
            guard let self=self, self.generation == epoch, self.owners[key] == owner else { return }
            self.owners.removeValue(forKey:key); self.tasks.removeValue(forKey:key); task?.cancel()
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
    var connectivityObservation: ConnectivityObservation? { connectivityMonitor?.observation }
    private var forceConnectivity=false
    private var sleeping=false
    private var trafficIdentity: String?
    var onChange: (() -> Void)?
    private var observedStatus: ServiceStatus?
    private(set) var status: ServiceStatus? {
        get { guard statusGeneration == api.generation, let at=statusAt, now().timeIntervalSince(at)<=15 else { return nil }; return observedStatus }
        set { observedStatus=newValue }
    }
    private(set) var nodes: [Node] = []
    private(set) var etag = ""
    private struct RetainedLatency {
        let label: String
        let checkedAt: Date?
        let completedAt: Date
        let etag: String
    }
    // One completed batch per endpoint; ordinary cancellation does not evict it.
    private var latencySamples: [String:[String:RetainedLatency]] = [:]

    private var activeProbeNames = Set<String>()
    private(set) var probeCompleted = 0
    private(set) var probeTotal = 0
    static let probeConcurrency = 6
    private var latencyGeneration = -1
    private var probeOwner: UUID?
    private(set) var probing = false
    private var probeQueue: [String] = []
    var canProbe: Bool {
        !initializingConnection && api.authenticated && !sleeping && !pending && !uncertain && quitOwner == nil && !etag.isEmpty && !nodes.isEmpty && nodesGeneration == api.generation &&
        (nodesAt.map { now().timeIntervalSince($0)<=15 } ?? false)
    }
    func latencyLabel(_ name: String) -> String {
        if probing && latencyGeneration == api.generation && activeProbeNames.contains(name) { return "测试中…" }
        if let retained=latencySamples[api.endpoint.origin]?[name] {
            return retained.label+(!etag.isEmpty && retained.etag != etag ? " · 旧配置/上次" : " · 上次")
        }
        return "—"
    }
    func latencyTooltip(_ name: String) -> String? {
        guard let retained=latencySamples[api.endpoint.origin]?[name] else { return nil }
        let time=ISO8601DateFormatter().string(from:retained.checkedAt ?? retained.completedAt)
        return "上次 TCP 测试："+time+(retained.checkedAt == nil ? "；请求结束，未取得有效测量样本。" : "；非实时结果。")+(etag.isEmpty || retained.etag == etag ? "" : "配置已改变；保留旧配置数值，重新测试后替换。")
    }
    private func cancelProbes() {
        probeOwner=nil; probing=false; probeQueue=[]; activeProbeNames=[]; latencyGeneration = -1; api.cancelProbe()
    }
    func probeNodes() {
        guard canProbe, !probing else { return }
        cancelProbes()
        latencySamples[api.endpoint.origin]=[:]
        latencyGeneration=api.generation; probeOwner=UUID(); probing=true
        var seen=Set<String>()
        probeQueue=nodes.map { $0.name }.filter { seen.insert($0).inserted }
        probeTotal=probeQueue.count; probeCompleted=0
        probeNext()
    }
    private func probeNext() {
        guard let owner=probeOwner, canProbe, latencyGeneration == api.generation else { cancelProbes(); changed(); return }
        while !probeQueue.isEmpty && activeProbeNames.count < Self.probeConcurrency {
            let name=probeQueue.removeFirst(), tag=etag, epoch=api.generation, origin=api.endpoint.origin
            activeProbeNames.insert(name)
            let sent=api.request("/nodes/probe",method:"POST",body:["name":name,"mode":"tcp_direct","confirm_insecure":false],etag:tag,requestIdentity:owner.uuidString+":"+name) { [weak self] result in
                guard let self=self, self.probeOwner == owner, self.api.generation == epoch, self.etag == tag, self.canProbe else { return }
                if case .success(let r)=result, r.status == 412 { self.cancelProbes(); self.changed(); self.refresh(); return }
                let sample: NodeLatency?
                if case .success(let r)=result, r.status == 200, let parsed=NodeLatency.parse(r.body,name:name,etag:tag) { sample=parsed } else { sample=nil }
                self.latencySamples[origin,default:[:]][name]=RetainedLatency(label:sample?.label ?? "不可用",checkedAt:sample?.checkedAt,completedAt:Date(),etag:tag)
                self.activeProbeNames.remove(name); self.probeCompleted += 1
                self.probeNext()
            }
            if !sent, probeOwner == owner {
                latencySamples[origin,default:[:]][name]=RetainedLatency(label:"不可用",checkedAt:nil,completedAt:Date(),etag:tag)
                cancelProbes(); changed(); return
            }
        }
        if probeQueue.isEmpty && activeProbeNames.isEmpty { probing=false; probeOwner=nil }
        changed()
    }
    private(set) var traffic: TrafficRate?
    private(set) var helperAvailable = false
    private(set) var pending = false
    private(set) var uncertain = false
    private(set) var message = "未连接本机控制台"
    private(set) var operationID: String?
    private var diagnosticRecord: (Int, SafeFailureDiagnostic)?
    var failureDiagnostic: SafeFailureDiagnostic? {
        guard let record=diagnosticRecord, record.0 == api.generation else { return nil }
        return record.1
    }
    private var pendingPath = "", pendingName: String?
    private struct SelectionRecovery {
        let operation: SelectionOperation, etag: String, changed: Bool, generation: Int
    }
    private var selectionRecovery: SelectionRecovery?
    private var selectionReadOwner: UUID?
    // The only reconciliation authority is the exact owned helper tuple. Status,
    // node checkmarks and NO_CHANGE cannot stand in for the lost ACK.
    var selectionReadPending: Bool { selectionReadOwner != nil }
    func recoverSelectionReadback() {
        guard uncertain, !pending, !initializingConnection, quitOwner == nil, api.authenticated,
              let recovery=selectionRecovery, recovery.generation == api.generation, selectionReadOwner == nil else { return }
        let owner=UUID(); selectionReadOwner=owner
        let sent=api.request(recovery.operation.readbackPath) { [weak self] result in
            guard let self=self, self.selectionReadOwner == owner else { return }
            self.selectionReadOwner=nil
            guard self.api.generation == recovery.generation, self.uncertain,
                  case .success(let reply)=result, reply.status == 200,
                  mutationVerdict(path:"/nodes/selection",status:reply.status,body:reply.body) == .applied,
                  reply.body["apply_status"] as? String == "HOT_APPLIED",
                  SelectionOperation.parse(reply.body["selection_operation"]) == recovery.operation,
                  reply.etag == recovery.etag, reply.body["etag"] as? String == recovery.etag,
                  jsonBool(reply.body["changed"]) == recovery.changed else { return }
            self.selectionRecovery=nil; self.uncertain=false
            self.message=selectionConnectionPolicy(reply.body)!; self.forceConnectivity=true
            self.changed()
        }
        if !sent { selectionReadOwner=nil }
    }
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
        guard !initializingConnection, quitContext == context, !pending, !uncertain, quitOwner == nil else {
            completion(uncertain ? .unknown : .blocked); return
        }
        let owner=UUID(); quitOwner=owner; pending=true; cancelConnectivity(); cancelProbes()
        message="正在核实并停止 VPN…"; changed()
        func finish(_ outcome: QuitOutcome) {
            guard self.quitOwner == owner else { return }
            self.quitOwner=nil; self.pending=false
            if outcome == .unknown { self.uncertain=true }
            self.message = outcome == .stopped ? "VPN 已停止" : (outcome == .unknown ? "停止结果未知；请打开控制台核实" : "退出已取消；无法确认 VPN 已停止")
            self.changed(); completion(outcome)
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
        clearObservations(); message="停止结果未知；请打开控制台核实"; changed()
    }
    private var statusAt: Date?
    private var nodesAt: Date?
    private var statusGeneration = -1, helperGeneration = -1, nodesGeneration = -1
    private(set) var pollingTimer: Timer?
    var now: () -> Date = Date.init
    private var menuOpen=false
    var pollingInterval: TimeInterval { sleeping || !api.authenticated ? 5 : (menuOpen ? 0.25 : (status?.running == true || pending ? 1 : 5)) }
    private(set) var expiryTimer: Timer?
    private var scheduledInterval: TimeInterval = 0
    private var pollingGeneration = -1
    private var nextStatus=Date.distantPast, nextConfiguration=Date.distantPast
    private var helperAt: Date?
    private var lastPresentation: [String] = []
    private func changed() {
        if pollingTimer != nil && scheduledInterval != pollingInterval { installPollingTimer() }
        if pollingTimer != nil { scheduleExpiry() }
        var presentation: [String] = [String(api.generation),String(api.authenticated),String(describing:status?.loaded),String(describing:status?.running),
            String(helperAvailable),etag,String(pending),String(uncertain),message,String(initializingConnection),String(describing:connectivity),
            String(probing),String(probeCompleted),String(probeTotal)]
        presentation += [String(describing:connectivityObservation),failureDiagnostic?.summary ?? ""]
        presentation += nodes.flatMap { [$0.name,String($0.selected),String($0.selectable),String($0.skipVerify),String($0.needsSync),latencyLabel($0.name)] }
        presentation += [traffic.map { "\($0.runtimeIdentity):\($0.upload):\($0.download):\($0.duration):\($0.totalUpload):\($0.totalDownload)" } ?? "—"]
        guard presentation != lastPresentation else { return }
        lastPresentation=presentation; onChange?()
    }
    func setMenuOpen(_ open: Bool) { menuOpen=open; if pollingTimer != nil && scheduledInterval != pollingInterval { installPollingTimer() }; tick() }
    private var observationGeneration = 0
    init(api: APIClient, connectivityMonitor: ConnectivityMonitor? = ConnectivityMonitor()) {
        self.api=api; self.connectivityMonitor=connectivityMonitor

        api.onExpired={ [weak self] in
            guard let self=self else { return }
            if self.pending { self.pending=false; self.uncertain=true }
            self.clearObservations(); self.message=self.uncertain ? "会话已失效；先前操作结果未知，请打开控制台核实" : "本机会话已过期；正在重新验证组件，失败后可稍后刷新状态"
            self.changed()
        }
    }
    private var connectionInitializationOwner: UUID?
    private var discardClientUnknown=false
    var initializingConnection: Bool { connectionInitializationOwner != nil }
    var connectionObservationsReady: Bool {
        api.authenticated && status != nil && helperAvailable && !etag.isEmpty &&
        statusGeneration == api.generation && helperGeneration == api.generation && nodesGeneration == api.generation &&
        (statusAt.map { now().timeIntervalSince($0)<=15 } ?? false) &&
        (nodesAt.map { now().timeIntervalSince($0)<=15 } ?? false) &&
        (helperAt.map { now().timeIntervalSince($0)<=15 } ?? false)
    }
    @discardableResult
    func beginConnectionInitialization(userConfirmedDiscardUnknown: Bool = false) -> UUID? {
        guard !initializingConnection, !pending, quitOwner == nil, !uncertain || userConfirmedDiscardUnknown else { return nil }
        let owner=UUID(); connectionInitializationOwner=owner
        discardClientUnknown=uncertain && userConfirmedDiscardUnknown
        stopPolling(); observationGeneration += 1; api.reset(); clearObservations()
        message="正在初始化连接；不重复上次操作…"; changed(); return owner
    }
    func finishConnectionInitialization(owner: UUID, verified: Bool) {
        guard connectionInitializationOwner == owner else { return }
        let ready=verified && connectionObservationsReady
        connectionInitializationOwner=nil
        if ready && discardClientUnknown { uncertain=false; operationID=nil; selectionRecovery=nil; selectionReadOwner=nil }
        discardClientUnknown=false
        if !ready { api.reset(); observationGeneration += 1; clearObservations() }
        message=ready ? "连接初始化完成；上次操作结果不追认为成功" : "连接初始化失败；可显式重试，先前未知结果保持锁定"
        changed()
    }
    var canMutate: Bool { !initializingConnection && !sleeping && api.authenticated && !pending && !uncertain && quitOwner == nil && status != nil && helperAvailable &&
        statusGeneration == api.generation && helperGeneration == api.generation &&
        (statusAt.map { now().timeIntervalSince($0)<=15 } ?? false) && (helperAt.map { now().timeIntervalSince($0)<=15 } ?? false) }
    private func cancelConnectivity() {
        connectivityMonitor?.onChange=nil; connectivityMonitor?.cancel(); connectivity = .idle
    }
    private func checkConnectivity(force: Bool = false) {
        guard !sleeping, api.authenticated, !pending, !uncertain, status?.running == true,
              let at=statusAt, now().timeIntervalSince(at)<=15 else { cancelConnectivity(); return }
        let epoch=api.generation, observation=observationGeneration
        connectivityMonitor?.onChange={ [weak self] state in
            guard let self=self, self.api.generation == epoch, self.observationGeneration == observation,
                  !self.sleeping, self.api.authenticated, !self.pending, !self.uncertain,
                  self.status?.running == true, let at=self.statusAt, self.now().timeIntervalSince(at)<=15 else { return }
            self.connectivity=state; self.changed()
        }
        connectivityMonitor?.check(force:force)
    }
    func environmentChanged(sleeping: Bool = false) {
        self.sleeping=sleeping; observationGeneration += 1; clearObservations(); forceConnectivity=true
        if !sleeping && api.authenticated { refresh() }
        changed()
    }
    func clearObservations() { nextStatus = .distantPast; nextConfiguration = .distantPast; helperAt=nil; cancelProbes(); cancelConnectivity(); status=nil; statusAt=nil; nodes=[]; nodesAt=nil; etag=""; traffic=nil; trafficIdentity=nil; helperAvailable=false }
    func login(endpoint: LocalEndpoint, password: String, completion: @escaping (Bool) -> Void) {
        // Never discard an unresolved command simply by changing session/endpoint.
        if initializingConnection || pending || quitOwner != nil || (uncertain && endpoint != api.endpoint) { completion(false); return }
        api.reset(endpoint:endpoint); clearObservations(); message="正在连接…"; changed()
        api.login(password:password) { [weak self] ok in
            guard let self=self else { return }
            self.message=ok ? (self.uncertain ? "先前操作结果未知；请打开控制台核实" : "已连接本机控制台") : "连接失败；检查端口与应用专用密码"
            if ok { self.refresh() }; self.changed(); completion(ok)
        }
    }
    func startPolling() {
        guard pollingTimer == nil else { return }; installPollingTimer()
    }
    private func installPollingTimer() {
        pollingTimer?.invalidate(); scheduledInterval=pollingInterval
        let t=Timer(timeInterval:scheduledInterval,repeats:true) { [weak self] _ in self?.tick() }
        t.tolerance=min(0.1,scheduledInterval/10); pollingTimer=t
        RunLoop.main.add(t,forMode:.common)
    }
    private func scheduleExpiry() {
        expiryTimer?.invalidate(); expiryTimer=nil
        let deadlines=([statusAt,helperAt,nodesAt,traffic?.sampledAt].compactMap { $0 }).map { $0.addingTimeInterval(15.001) }.filter { $0 > now() }
        guard let deadline=deadlines.min() else { return }
        let t=Timer(timeInterval:deadline.timeIntervalSince(now()),repeats:false) { [weak self] _ in self?.expireObservations(); self?.changed() }
        expiryTimer=t; RunLoop.main.add(t,forMode:.common)
    }
    func stopPolling() { expiryTimer?.invalidate(); expiryTimer=nil; pollingTimer?.invalidate(); pollingTimer=nil; cancelConnectivity(); cancelProbes() }
    private func expireObservations() {
        if let t=traffic, !t.fresh(now()) { traffic=nil }
        if let at=statusAt, now().timeIntervalSince(at)>15 { status=nil; helperAvailable=false; cancelConnectivity() }
        if let at=helperAt, now().timeIntervalSince(at)>15 { helperAvailable=false }
        if let at=nodesAt, now().timeIntervalSince(at)>15 { cancelProbes(); nodes=[]; nodesAt=nil; etag="" }
        if latencyGeneration != api.generation && latencyGeneration != -1 { cancelProbes() }
    }
    func tick() {
        api.expireIfNeeded()
        if pollingGeneration != api.generation { observationGeneration += 1; clearObservations(); pollingGeneration=api.generation }
        expireObservations()
        guard api.authenticated && !sleeping else { traffic=nil; cancelConnectivity(); changed(); return }
        readTraffic()
        if now() >= nextStatus { refresh(configuration:now() >= nextConfiguration) }
        if status?.running == true && !pending && !uncertain { checkConnectivity() }
        changed()
    }
    func refresh(configuration: Bool = true) {
        guard api.authenticated && !sleeping else { return }
        pollingGeneration=api.generation
        recoverSelectionReadback()
        nextStatus=now().addingTimeInterval(5)
        if configuration { nextConfiguration=now().addingTimeInterval(10) }
        let epoch=api.generation, observation=observationGeneration
        api.request("/status") { [weak self] result in
            guard let self=self, self.api.generation == epoch, self.observationGeneration == observation else { return }
            let old=self.status
            if case .success(let r)=result, r.status == 200 { self.status=ServiceStatus.parse(r.body); self.statusAt=self.now(); self.statusGeneration=epoch }
            else { self.status=nil; self.statusAt=nil }
            if self.status?.running == true && !self.pending && !self.uncertain {
                self.checkConnectivity(force:self.forceConnectivity); self.forceConnectivity=false
            } else { self.cancelConnectivity() }
            if !configuration && (old?.running != self.status?.running || old?.loaded != self.status?.loaded) { self.refresh() }
            self.changed()
        }
        if configuration {
            api.request("/helper/status") { [weak self] result in
                guard let self=self, self.api.generation == epoch, self.observationGeneration == observation else { return }
                if case .success(let r)=result { self.helperAvailable = r.status == 200 && jsonBool(r.body["available"]) == true; self.helperGeneration=epoch; self.helperAt=self.now() }
                else { self.helperAvailable=false; self.helperAt=nil }; self.changed()
            }
            api.request("/nodes") { [weak self] result in
                guard let self=self, self.api.generation == epoch, self.observationGeneration == observation else { return }
                var nextNodes: [Node] = [], nextTag=""
                if case .success(let r)=result, r.status == 200, let list=r.body["nodes"] as? [Any],
                   let etag=r.body["etag"] as? String, etag.range(of:#"^\"[a-f0-9]{64}\"$"#,options:.regularExpression) != nil {
                    let parsed=list.compactMap(Node.parse)
                    if parsed.count == list.count && Set(parsed.map { $0.name }).count == parsed.count { nextNodes=parsed; nextTag=etag }
                }
                if nextTag != self.etag || nextNodes.map({ $0.name }) != self.nodes.map({ $0.name }) { self.cancelProbes() }
                self.nodes=nextNodes; self.etag=nextTag; self.nodesAt=nextTag.isEmpty ? nil : self.now(); self.nodesGeneration=epoch
                self.changed()
            }
        }
        readTraffic()
    }
    private func readTraffic() {
        let observation=observationGeneration, epoch=api.generation
        api.requestTraffic(now:now) { [weak self] result in
            guard let self=self, self.api.generation == epoch, self.observationGeneration == observation else { return }
            if case .success(let rate)=result, let rate=rate, rate.fresh(self.now()) { self.traffic=rate } else { self.traffic=nil }
            if let identity=self.traffic?.runtimeIdentity {
                if let old=self.trafficIdentity, old != identity {
                    self.observationGeneration += 1; self.clearObservations(); self.forceConnectivity=true
                    self.trafficIdentity=identity; self.refresh(); return
                }
                self.trafficIdentity=identity
            }
            self.changed()
        }
    }
    func mutate(path: String, name: String? = nil, consent: Bool) {
        guard canMutate, ["/service/start","/service/stop","/service/reload","/nodes/selection"].contains(path),
              let at=statusAt, now().timeIntervalSince(at)<=15 else { return }
        if path == "/nodes/selection" && (!canProbe || etag.isEmpty || !nodes.contains(where: { $0.name == name && $0.selectable })) { return }
        if path == "/service/start" && (status?.running != false || status?.loaded != false) { return }
        if path == "/service/reload" && status?.running != true { return }
        if path == "/service/stop" && status?.loaded != true && status?.running != true { return }
        cancelConnectivity(); cancelProbes()
        operationID=nil; diagnosticRecord=nil; observationGeneration += 1; status=nil; traffic=nil
        pending=true; pendingPath=path; pendingName=name; message="正在执行；不会自动重试…"; changed()
        var body: [String: Any] = ["confirm_insecure":consent]
        if let name=name { body["name"]=name }
        let epoch=api.generation
        selectionRecovery=nil; selectionReadOwner=nil
        let sent=api.request(path,method:"POST",body:body,etag:path == "/nodes/selection" ? etag : nil) { [weak self] result in
            guard let self=self, self.api.generation == epoch else { return }
            self.pending=false; self.observationGeneration += 1; self.clearObservations()
            self.diagnosticRecord=(epoch,SafeFailureDiagnostic(operation:nil,reason:nil,knownFailure:false))
            var verdict: MutationVerdict = .unknown
            var failureReason: String?
            var connectionPolicy: String?
            if case .success(let r)=result {
                verdict=mutationVerdict(path:path,status:r.status,body:r.body)
                if path == "/nodes/selection", r.body["apply_status"] as? String == "HOT_APPLIED",
                   (SelectionOperation.parse(r.body["selection_operation"])?.node != name || r.etag != (r.body["etag"] as? String)) { verdict = .unknown }
                if path == "/nodes/selection", r.status == 200, validHotSelection(r.body),
                   r.body["apply_status"] as? String == "SWITCH_UNKNOWN", jsonBool(r.body["applied"]) == false,
                   jsonBool(r.body["pendingReload"]) == true, jsonBool(r.body["pendingKnown"]) == false,
                   jsonBool(r.body["readback_requires_owned_lease"]) == false,
                   let operation=SelectionOperation.parse(r.body["selection_operation"]), operation.node == name,
                   let tag=r.body["etag"] as? String, r.etag == tag, let changed=jsonBool(r.body["changed"]) {
                    self.selectionRecovery=SelectionRecovery(operation:operation,etag:tag,changed:changed,generation:epoch)
                }
                failureReason=knownMutationFailureReason(path:path,status:r.status,body:r.body)
                if r.body["apply_status"] as? String == "HOT_APPLIED" { connectionPolicy=selectionConnectionPolicy(r.body) }
                self.operationID=SafeFailureDiagnostic.reference(r.body["startup_operation"])
                if verdict == .unknown || verdict == .rejected {
                    self.diagnosticRecord=(epoch,SafeFailureDiagnostic.parse(path:path,status:r.status,body:r.body))
                } else { self.diagnosticRecord=nil }
            }
            self.uncertain = verdict == .unknown
            switch verdict {
            case .serviceSucceeded: self.message=path == "/service/stop" ? "VPN 已停止" : "VPN 本地已就绪；外网等待独立验证"
            case .savedStopped: self.message="启动节点已保存；VPN 未运行，下次启动生效"
            case .applied: self.message=connectionPolicy ?? "启动节点已保存并应用；将重新读取状态"
            case .reloadRequired: self.message="配置已保存；当前核心或配置不支持热切换，VPN 未重启。请显式重新应用"
            case .unchanged: self.message="选择未变化；没有重新连接"
            case .rejected:
                if failureReason == "SYSTEM_PROXY_ACTIVE" {
                    self.message="启动失败：系统代理仍启用（SYSTEM_PROXY_ACTIVE）；请先手动关闭系统代理，再明确选择启动。未自动重试"
                } else {
                    self.message=failureReason == nil ? "请求被拒绝；请刷新或打开控制台检查" : "VPN 操作已失败："+(self.failureDiagnostic?.explanation ?? "已验证失败")+"；清理已核实，未自动重试"
                }
            case .unknown: self.message="操作结果未知；已锁定操作，不自动重试。打开控制台核实"
            }
            self.forceConnectivity = verdict == .applied || (verdict == .serviceSucceeded && path != "/service/stop")
            self.refresh(); self.changed()
        }
        if !sent { pending=false; uncertain=true; message="操作状态未知；请打开控制台核实"; changed() }
    }
    // Lost responses without an owned tuple remain locked; no mutation replay.
}

#if FOCUS_TESTS
// Test-only deterministic model stimulus; production API/parser remains unchanged.
extension MenuModel {
    func fixtureSeed(count: Int) {
        now={Date(timeIntervalSince1970:1_800_000_000)}
        status=ServiceStatus(loaded:true,running:true);statusAt=now();helperAt=now();nodesAt=now()
        statusGeneration=api.generation;helperGeneration=api.generation;nodesGeneration=api.generation
        pollingGeneration=api.generation; helperAvailable=true;pending=false;uncertain=false;sleeping=false
        nodes=(0..<count).map { Node(name:"fixture-\($0)",selectable:true,selected:$0==0,skipVerify:false,needsSync:false) }
        etag="\""+String(repeating:"a",count:64)+"\""
        nextStatus=now().addingTimeInterval(1000);nextConfiguration=nextStatus
    }
    func fixtureClockAdvance() { let t=now().addingTimeInterval(0.1);now={t} }
    func fixtureTraffic(_ i:Int) {
        traffic=TrafficRate(runtimeIdentity:"fixture",sampledAt:Date(),upload:UInt64(i*100),download:UInt64(i*200),duration:1_000_000_000,totalUpload:UInt64(i*1000),totalDownload:UInt64(i*2000));changed()
    }
    func fixtureStructure(_ field:String) {
        let n=nodes[0]
        if field=="order" { nodes.reverse() }
        else if field=="etag" { etag="\""+String(repeating:"b",count:64)+"\"" }
        else if field=="generation" { api.reset() }
        else { nodes[0]=Node(name:field=="name" ? "renamed" : n.name,selectable:field=="selectable" ? !n.selectable : n.selectable,selected:field=="selected" ? !n.selected : n.selected,skipVerify:field=="skipVerify" ? !n.skipVerify : n.skipVerify,needsSync:field=="needsSync" ? !n.needsSync : n.needsSync) }
    }
    func fixtureLatency(_ seconds:Double) {
        latencySamples[api.endpoint.origin]=[nodes[0].name:RetainedLatency(label:"12 ms",checkedAt:Date(timeIntervalSince1970:seconds),completedAt:Date(timeIntervalSince1970:seconds),etag:etag)]
    }
    func fixtureFeedback() {
        message="fixture feedback changed"
        diagnosticRecord=(api.generation,SafeFailureDiagnostic(operation:nil,reason:"STOP_FAILED",knownFailure:true))
    }
    func fixtureSafety(_ state:String) {
        switch state {
        case "expiry":let t=now().addingTimeInterval(16);now={t}
        case "recovered":statusAt=now();nodesAt=now();helperAt=now()
        case "helperOff":helperAvailable=false
        case "helperOn":helperAvailable=true
        case "pending":pending=true
        case "unknown":uncertain=true
        case "free":pending=false;uncertain=false
        case "sleep":sleeping=true
        case "wake":sleeping=false
        case "noauth":api.reset()
        default:break
        }
    }
}
#endif
