import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class MockProtocol: URLProtocol {
    typealias Handler = (URLRequest, MockProtocol) -> Void
    private static let handlerLock=NSLock()
    private static var storedHandler: Handler?
    static var handler: Handler? {
        get { handlerLock.lock(); defer { handlerLock.unlock() }; return storedHandler }
        set { handlerLock.lock(); storedHandler=newValue; handlerLock.unlock() }
    }
    private static var recordedCalls: [URLRequest] = []
    static var calls: [URLRequest] {
        dispatchPrecondition(condition:.onQueue(.main)); return recordedCalls
    }
    private let capturedHandler: Handler?
    override init(request: URLRequest, cachedResponse: CachedURLResponse?, client: URLProtocolClient?) {
        capturedHandler=Self.handler
        super.init(request:request,cachedResponse:cachedResponse,client:client)
    }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let handler=capturedHandler
        DispatchQueue.main.async {
            dispatchPrecondition(condition:.onQueue(.main))
            Self.recordedCalls.append(self.request); handler?(self.request,self)
        }
    }
    override func stopLoading() {}
    func reply(_ status: Int, _ body: [String: Any], headers: [String:String] = [:]) {
        dispatchPrecondition(condition:.onQueue(.main))
        client?.urlProtocol(self,didReceive:HTTPURLResponse(url:request.url!,statusCode:status,httpVersion:"HTTP/1.1",headerFields:headers)!,cacheStoragePolicy:.notAllowed)
        client?.urlProtocol(self,didLoad:try! JSONSerialization.data(withJSONObject:body)); client?.urlProtocolDidFinishLoading(self)
    }
    func fail() {
        dispatchPrecondition(condition:.onQueue(.main))
        client?.urlProtocol(self,didFailWithError:URLError(.networkConnectionLost))
    }
}
@main struct Tests {
    static var checks: [String] = []
    static func check(_ condition: @autoclosure () -> Bool, _ name: String) {
        guard condition() else { fputs("FAIL: \(name)\n",stderr); exit(1) }; checks.append(name)
    }
    static func wait(_ condition: () -> Bool, timeout: TimeInterval = 15) {
        let end=Date().addingTimeInterval(timeout)
        while !condition() && Date()<end { _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.01)) }
        check(condition(),"asynchronous completion")
    }
    // A visible status is not a completion barrier for its three sibling reads.
    // Admit a sentinel only after each actual API owner releases, then require
    // all four real completion callbacks before changing handler/phase/reset.
    static var drainedRefreshes=0
    static func pumpUntil(_ condition: () -> Bool) {
        let end=Date().addingTimeInterval(15)
        while !condition() && Date()<end { _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.01)) }
        guard condition() else { fputs("FAIL: fixture completion barrier\n",stderr); exit(1) }
    }
    static func drainRefresh(_ api: APIClient) {
        var admitted=Set<String>(), completed=Set<String>()
        let paths=["/status","/helper/status","/nodes","/traffic"]
        pumpUntil {
            for path in paths where !admitted.contains(path) {
                if api.request(path,completion:{ result in
                    guard case .success=result else { fputs("FAIL: fixture sentinel response\n",stderr); exit(1) }
                    completed.insert(path)
                }) { admitted.insert(path) }
            }
            return completed == Set(paths)
        }
        drainedRefreshes += 1
    }
    static func fixture(now: Date) -> [String: Any] {
        let date=ISO8601DateFormatter().string(from:now)
        let sha=String(repeating:"a",count:64), id=String(repeating:"b",count:32)
        return ["traffic_schema":1,"availability":"OBSERVED","snapshot":["traffic_schema":1,"source":"SDK_ROUTED_PAYLOAD","state":"RUNNING","sampled_at":date,"elapsed_ns":"5000000000","upload_bytes":"18446744073709551615","download_bytes":"9007199254740993","saturated":false,"header":["schema_version":1,"config_identity":sha,"instance_id":id,"generation":id,"manifest_id":sha,"runtime_sha256":sha,"created_at":date,"previous_binding":NSNull()],"rate":["start_ns":"0","end_ns":"5000000000","upload_bytes":"6000","download_bytes":"47500"],"history":[]] as [String:Any]]
    }
    static func mockClient() -> APIClient {
        APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:18089"),configuration:{ let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[MockProtocol.self]; return c })
    }
    static let token=String(repeating:"x",count:43)
    static func authenticate(_ api: APIClient) {
        MockProtocol.handler={ _,p in p.reply(200,["csrf":token,"expiresIn":28800]) }
        var done=false, ok=false; api.login(password:"SYNTHETIC_FIXTURE_ONLY") { ok=$0; done=true }; wait { done }; check(ok,"manual login")
    }
    static func unit() {
        for value in ["http://127.0.0.1:18089","http://localhost:1","http://[::1]:65535"] { check((try? LocalEndpoint(value)) != nil,"loopback accepted \(value)") }
        for value in ["https://127.0.0.1","http://example.com","http://127.0.0.1/","http://127.0.0.1:0","http://127.0.0.1:65536","http://a@127.0.0.1","http://127.0.0.1#x","http://127.0.0.1?x","http://127.1","http://2130706433"," http://localhost","http://localhost.","http://127.0.0.1/%2f"] { check((try? LocalEndpoint(value)) == nil,"unsafe endpoint rejected") }
        for value in ["01","-1","1.0","1e3","18446744073709551616",""] { check(canonicalUInt(value) == nil,"noncanonical uint rejected") }
        check(canonicalUInt("18446744073709551615") == UInt64.max,"uint64 max exact")
        check(canonicalUInt(9007199254740993 as UInt64) == nil,"numeric JSON uint rejected")
        let now=Date(); let dto=fixture(now:now)
        let t=TrafficRate.parse(dto,now:now); check(t != nil,"strict traffic accepted")
        check(t?.totalDownload == 9007199254740993,"above 2^53 exact")
        check(TrafficRate.label(t!.upload,t!.duration) == "1.2KB/s","interval duration upload")
        check(TrafficRate.label(t!.download,t!.duration) == "9.5KB/s","interval duration download")
        check(TrafficRate.parse(dto,now:now.addingTimeInterval(16)) == nil,"stale traffic hidden")
        check(TrafficRate.parse(dto,now:now.addingTimeInterval(-1)) == nil,"future traffic hidden")
        var booleanSchema=dto; booleanSchema["traffic_schema"]=true
        check(TrafficRate.parse(booleanSchema,now:now) == nil,"boolean schema is not integer one")
        for (key,value) in [("saturated",true as Any),("source","DEVICE_COUNTER" as Any),("elapsed_ns","9223372036854775808" as Any),("upload_bytes",6000 as Any),("header",[:] as [String:Any])] {
            var bad=dto; var s=bad["snapshot"] as! [String:Any]; s[key]=value; bad["snapshot"]=s
            check(TrafficRate.parse(bad,now:now) == nil,"traffic invalid \(key)")
        }
        var bad=dto; var s=bad["snapshot"] as! [String:Any]; var r=s["rate"] as! [String:Any]; r["end_ns"]="5000000001"; s["rate"]=r; bad["snapshot"]=s
        check(TrafficRate.parse(bad,now:now) == nil,"rate end after elapsed rejected")
        check(mutationVerdict(path:"/service/start",status:200,body:["ok":true]) == .unknown,"HTTP200 not success alone")
        check(mutationVerdict(path:"/service/start",status:202,body:["ok":true,"loaded":true,"running":true]) == .unknown,"HTTP202 unknown")
        check(mutationVerdict(path:"/nodes/selection",status:200,body:["ok":true,"saved":true,"apply_status":"SAVED_STOPPED"]) == .savedStopped,"saved stopped distinct")
        check(mutationVerdict(path:"/nodes/selection",status:200,body:["ok":true,"saved":true,"applied":true,"apply_status":"APPLIED"]) == .applied,"applied distinct")
        check(mutationVerdict(path:"/service/stop",status:200,body:["ok":true,"loaded":true,"running":false]) == .unknown,"stop loaded not confirmed")
        let redirect=NoRedirect(), redirectSession=URLSession(configuration:.ephemeral)
        let redirectTask=redirectSession.dataTask(with:URL(string:"http://127.0.0.1:1")!)
        var redirectChecked=false
        redirect.urlSession(redirectSession,task:redirectTask,willPerformHTTPRedirection:HTTPURLResponse(url:URL(string:"http://127.0.0.1:1")!,statusCode:302,httpVersion:nil,headerFields:nil)!,newRequest:URLRequest(url:URL(string:"https://example.com")!)) { request in check(request == nil,"redirect delegate denies cross-origin redirect"); redirectChecked=true }
        check(redirectChecked,"redirect completion invoked"); redirectTask.cancel(); redirectSession.invalidateAndCancel()
        let api=mockClient(); authenticate(api)
        var held: MockProtocol?; var completions=0
        MockProtocol.handler={ req,p in
            check(req.value(forHTTPHeaderField:"Origin") == "http://127.0.0.1:18089","mandatory Origin")
            check(req.value(forHTTPHeaderField:"X-AnyTLS-Origin") == "http://127.0.0.1:18089","traffic application origin")
            check(req.value(forHTTPHeaderField:"Sec-Fetch-Site") == "same-origin","traffic fetch metadata")
            held=p
        }
        check(api.request("/traffic") { _ in completions += 1 },"first request accepted")
        check(!api.request("/traffic") { _ in completions += 1 },"overlap dropped without task")
        wait { held != nil }; held?.reply(200,dto); wait { completions == 1 }
        held=nil; var slowDone=false
        let slowStart=Date()
        check(api.request("/traffic") { result in if case .failure=result { slowDone=true } },"slow body request accepted")
        wait { held != nil }
        check(!api.request("/traffic") { _ in },"slow body overlap suppressed")
        wait({ slowDone },timeout:9)
        check(Date().timeIntervalSince(slowStart)<9,"absolute read deadline cancels stalled body")
        var mutationDone=false
        MockProtocol.handler={ req,p in
            check(req.value(forHTTPHeaderField:"X-CSRF-Token") == token,"CSRF applied")
            check(req.value(forHTTPHeaderField:"If-Match") == "\""+String(repeating:"a",count:64)+"\"","ETag literal preserved")
            p.reply(200,["ok":true]); }
        api.request("/nodes/selection",method:"POST",body:["name":"node","confirm_insecure":false],etag:"\""+String(repeating:"a",count:64)+"\"") { _ in mutationDone=true }; wait { mutationDone }
        // Delay an old 401 until a new manual login has established another generation.
        held=nil
        MockProtocol.handler={ _,p in held=p }
        var oldCompletion=false
        api.request("/status") { _ in oldCompletion=true }; wait { held != nil }
        let old=held!; authenticate(api); old.reply(401,["error":"AUTH_REQUIRED"])
        _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.1))
        check(api.authenticated && !oldCompletion,"stale 401 cannot clear new session")
        var expired=false; api.onExpired={ expired=true }
        MockProtocol.handler={ _,p in p.reply(401,["error":"AUTH_REQUIRED"]) }
        api.request("/status") { _ in }; wait { expired }
        check(api.csrf.isEmpty && !api.authenticated,"expiry clears CSRF")
        let model=MenuModel(api:mockClient(),connectivityMonitor:nil); authenticate(model.api)
        let tag="\""+String(repeating:"a",count:64)+"\""
        MockProtocol.handler={ req,p in
            switch req.url!.path {
            case "/api/v1/status": p.reply(200,["availability":"AVAILABLE","loaded":false,"running":false])
            case "/api/v1/helper/status": p.reply(200,["available":true])
            case "/api/v1/nodes": p.reply(200,["etag":tag,"nodes":[["name":"node","selectable":true,"selected":false,"skipVerify":false]]])
            case "/api/v1/traffic": p.reply(503,["traffic_schema":1,"availability":"UNAVAILABLE","snapshot":NSNull()])
            default: p.fail()
            }
        }
        model.refresh(); wait { model.canMutate && model.nodes.count == 1 }
        drainRefresh(model.api)
        let before=MockProtocol.calls.count
        model.mutate(path:"/service/start",consent:false)
        wait { model.uncertain }
        model.mutate(path:"/service/start",consent:true)
        model.refresh(); wait { model.status != nil }
        check(model.uncertain && !model.canMutate,"disconnect remains locked after plain status")
        let mutations=MockProtocol.calls.dropFirst(before).filter { $0.httpMethod == "POST" }
        check(mutations.count == 1,"no automatic mutation retry")
        check(model.traffic == nil,"unavailable not zero")
        drainRefresh(model.api)
        api.reset(); model.api.reset()
        // Shared production model + monitor integration; all HTTP and HTTPS intercepted.
        let probe=ConnectivityMonitor(configuration:{ let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[MockProtocol.self]; return c })
        let linked=MenuModel(api:mockClient(),connectivityMonitor:probe); authenticate(linked.api)
        var running=true, good=true
        MockProtocol.handler={ req,p in
            if req.url!.scheme == "https" {
                p.client?.urlProtocol(p,didReceive:HTTPURLResponse(url:req.url!,statusCode:good ? 204 : 503,httpVersion:nil,headerFields:nil)!,cacheStoragePolicy:.notAllowed)
                p.client?.urlProtocolDidFinishLoading(p); return
            }
            if req.url!.path.hasSuffix("/status") && !req.url!.path.contains("helper") { p.reply(200,["availability":"AVAILABLE","loaded":running,"running":running]) }
            else if req.url!.path.contains("helper") { p.reply(200,["available":true]) }
            else if req.httpMethod == "POST" { p.fail() }
            else { p.reply(200,[:]) }
        }
        linked.refresh(); wait { linked.connectivity == .online }
        check(linked.status?.running == true,"fresh running status triggers actual monitor")
        drainRefresh(linked.api)
        running=false; linked.refresh(); wait { linked.status?.running == false }
        check(linked.connectivity == .idle,"stopped status clears connectivity proof")
        drainRefresh(linked.api)
        good=false; running=true; linked.refresh(); wait { linked.connectivity == .offline }
        check(linked.status?.running == true,"network failure does not pretend service stopped")
        drainRefresh(linked.api)
        linked.environmentChanged(sleeping:true)
        check(linked.connectivity == .idle && linked.status == nil,"sleep invalidates connectivity and running observation")
        good=true; linked.environmentChanged(); wait { linked.connectivity == .online }
        check(linked.status?.running == true,"wake rechecks only after fresh running readback")
        wait { linked.canMutate }
        drainRefresh(linked.api)
        let obsolete=probe.onChange
        linked.mutate(path:"/service/reload",consent:true); wait { linked.uncertain }
        obsolete?(.online)
        check(linked.uncertain && linked.connectivity == .idle,"late network success never unlocks unknown mutation")
        linked.refresh(); wait { linked.status != nil }
        check(linked.uncertain && linked.connectivity == .idle,"fresh running after unknown does not restart connectivity or unlock")
        drainRefresh(linked.api)
        linked.clearObservations(); check(linked.connectivity == .idle,"session observations clear cancels probe")
        linked.stopPolling(); linked.api.reset()
        let request=URLRequest(url:URL(string:"http://127.0.0.1:18089/capture-regression")!)
        let beforeCapture=MockProtocol.calls.count
        var heldCapture: MockProtocol?, wrongHandler=false, onMain=false
        MockProtocol.handler={ _,p in onMain=Thread.isMainThread; heldCapture=p }
        let instance=MockProtocol(request:request,cachedResponse:nil,client:nil)
        MockProtocol.handler={ _,_ in wrongHandler=true }
        let started=DispatchSemaphore(value:0)
        DispatchQueue.global().async { instance.startLoading(); started.signal() }
        guard started.wait(timeout:.now()+15) == .success else { fatalError("fixture start barrier") }
        pumpUntil { heldCapture != nil || wrongHandler }
        check(heldCapture === instance && !wrongHandler,"fixture handler captured at protocol initialization")
        heldCapture?.reply(200,[:])
        check(onMain && Thread.isMainThread && MockProtocol.calls.count == beforeCapture+1 && MockProtocol.calls.last?.url == request.url,"fixture handler calls and held delivery are main-owned")
        check(drainedRefreshes == 7,"fixture prior four-path completions drained before phase changes")
        MockProtocol.handler=nil

    }
    static func integration() {
        let input=FileHandle.standardInput.readDataToEndOfFile()
        guard let args=(try? JSONSerialization.jsonObject(with:input)) as? [String:Any], let origin=args["origin"] as? String,
              let password=args["password"] as? String, let endpoint=try? LocalEndpoint(origin), endpoint.url.port != 18089 else { fputs("integration requires isolated nonproduction loopback port\n",stderr); exit(2) }
        let api=APIClient(endpoint:endpoint)
        var done=false, ok=false; api.login(password:password) { ok=$0; done=true }; wait { done }; check(ok,"actual Go handler login cookie session")
        func request(_ path: String, method: String = "GET", body: [String:Any]? = nil, etag: String? = nil) -> APIReply {
            var result: Result<APIReply,Error>?
            api.request(path,method:method,body:body,etag:etag) { result=$0 }; wait({ result != nil },timeout:30)
            guard case .success(let r)=result! else { fputs("fixture request failed\n",stderr); exit(1) }; return r
        }
        let state=request("/status"); check(state.status == 200 && ServiceStatus.parse(state.body)?.running == false,"actual stopped status")
        func nodes() -> (String,[Node]) {
            let r=request("/nodes"); guard let tag=r.body["etag"] as? String, let raw=r.body["nodes"] as? [Any] else { exit(1) }
            let nodes=raw.compactMap(Node.parse).filter { $0.selectable }; check(nodes.count >= 2,"actual selectable node DTO"); return (tag,nodes)
        }
        let (tag,list)=nodes()
        let first=list.first(where: { !$0.selected }) ?? list[0]
        let saved=request("/nodes/selection",method:"POST",body:["name":first.name,"confirm_insecure":false],etag:tag)
        check(mutationVerdict(path:"/nodes/selection",status:saved.status,body:saved.body) == .savedStopped,"actual node saved stopped")
        let start=request("/service/start",method:"POST",body:["confirm_insecure":false])
        check(mutationVerdict(path:"/service/start",status:start.status,body:start.body) == .serviceSucceeded,"actual service start receipt")
        check(ServiceStatus.parse(request("/status").body)?.running == true,"actual running status readback")
        let traffic=request("/traffic")
        check(traffic.status == 200 && TrafficRate.parse(traffic.body) != nil,"actual authenticated traffic headers and strict DTO")
        check(canonicalUInt((traffic.body["snapshot"] as? [String:Any])?["upload_bytes"]) == 9007199254740993,"actual handler UInt64 above 2^53 preserved")
        // A separate private fixture session intentionally omits only the application
        // origin header. Production APIClient always supplies all required headers.
        let negative=URLSession(configuration:.ephemeral,delegate:NoRedirect(),delegateQueue:nil)
        func raw(_ path: String, login: Bool) -> Int {
            var req=URLRequest(url:URL(string:origin+"/api/v1"+path)!)
            req.setValue(origin,forHTTPHeaderField:"Origin"); req.setValue("same-origin",forHTTPHeaderField:"Sec-Fetch-Site")
            if login { req.httpMethod="POST"; req.setValue("application/json",forHTTPHeaderField:"Content-Type"); req.httpBody=try! JSONSerialization.data(withJSONObject:["username":"admin","password":password]) }
            var status: Int?
            negative.dataTask(with:req) { _,response,_ in DispatchQueue.main.async { status=(response as? HTTPURLResponse)?.statusCode ?? -1 } }.resume()
            wait { status != nil }; return status!
        }
        check(raw("/login",login:true) == 200,"negative fixture private login")
        check(raw("/traffic",login:false) == 403,"actual handler rejects missing application origin")
        negative.invalidateAndCancel()
        let (nextTag,next)=nodes(); check(next.contains { $0.name == first.name && $0.selected },"actual stopped selection persisted")
        let other=next.first(where: { $0.name != first.name })!
        let applied=request("/nodes/selection",method:"POST",body:["name":other.name,"confirm_insecure":false],etag:nextTag)
        check(mutationVerdict(path:"/nodes/selection",status:applied.status,body:applied.body) == .applied,"actual running selection auto apply only")
        check(nodes().1.contains { $0.name == other.name && $0.selected },"actual applied selection readback")
        let stop=request("/service/stop",method:"POST",body:["confirm_insecure":false])
        check(mutationVerdict(path:"/service/stop",status:stop.status,body:stop.body) == .serviceSucceeded,"actual stop receipt")
        check(ServiceStatus.parse(request("/status").body)?.running == false,"actual stopped readback")
        api.reset()
        if let evidence=args["evidence"] as? String { try? output().write(toFile:evidence+"/swift-checks.json",atomically:true,encoding:.utf8) }
    }
    static func freshnessComposition() {
        var clock: TimeInterval = 2000
        let monitor=ConnectivityMonitor(configuration:{ let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[MockProtocol.self]; return c },now:{ clock })
        let model=MenuModel(api:mockClient(),connectivityMonitor:monitor)
        authenticate(model.api)
        MockProtocol.handler={ req,p in
            if req.url!.scheme == "https" {
                p.client?.urlProtocol(p,didReceive:HTTPURLResponse(url:req.url!,statusCode:204,httpVersion:nil,headerFields:nil)!,cacheStoragePolicy:.notAllowed)
                p.client?.urlProtocolDidFinishLoading(p)
            } else if req.url!.path == "/api/v1/status" { p.reply(200,["availability":"AVAILABLE","loaded":true,"running":true]) }
            else if req.url!.path.contains("helper") { p.reply(200,["available":true]) }
            else { p.reply(200,[:]) }
        }
        model.refresh(); wait { model.connectivity == .online }; drainRefresh(model.api)
        check(model.status?.running == true && monitor.state == .online,"freshness composition real MenuModel URLProtocol positive")
        var renders=0
        model.onChange={ renders += 1; _ = model.connectivity }
        let requests=MockProtocol.calls.count
        clock=2044.999
        check(model.connectivity == .online,"MenuModel cached online fresh at 44.999 seconds")
        clock=2045
        check(model.connectivity == .idle,"MenuModel renderer read hides cached online at exact 45 seconds")
        clock=2045.001
        check(model.connectivity == .idle,"MenuModel renderer read hides cached online after 45 seconds")
        check(renders == 0,"MenuModel freshness getter cannot recursively render")
        check(MockProtocol.calls.count == requests && !model.pending && !model.uncertain,"MenuModel freshness reads dispatch no requests or mutation")
        model.clearObservations()
        clock=2000
        check(model.connectivity == .idle && monitor.state == .idle,"session cancellation cannot resurrect expired online proof")
        model.stopPolling(); model.api.reset(); MockProtocol.handler=nil
    }
    static func output() -> String { String(data:try! JSONSerialization.data(withJSONObject:["status":"PASS","checks":checks],options:[.prettyPrinted,.sortedKeys]),encoding:.utf8)! }
    static func main() {
        if CommandLine.arguments.contains("--integration") {
            integration(); print(String(data:try! JSONSerialization.data(withJSONObject:["ok":true,"checks":checks.count]),encoding:.utf8)!)
        } else { unit(); checks.append(contentsOf:KnownFailureTests.run()); freshnessComposition(); print(output()) }
    }
}
