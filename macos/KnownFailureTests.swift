import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// Offline regression: every URLSession request is intercepted; no helper or VPN.
final class FailureProtocol: URLProtocol {
    typealias Handler = (URLRequest, FailureProtocol) -> Void
    private static let handlerLock=NSLock()
    private static var storedHandler: Handler?
    static var handler: Handler? {
        get { handlerLock.lock(); defer { handlerLock.unlock() }; return storedHandler }
        set { handlerLock.lock(); storedHandler=newValue; handlerLock.unlock() }
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
            handler?(self.request,self)
        }
    }
    override func stopLoading() {}
    func reply(_ status: Int, _ body: [String:Any], etag: String? = nil) {
        let headers=(etag ?? (body["etag"] as? String)).map { ["ETag":$0] }
        client?.urlProtocol(self,didReceive:HTTPURLResponse(url:request.url!,statusCode:status,httpVersion:nil,headerFields:headers)!,cacheStoragePolicy:.notAllowed)
        client?.urlProtocol(self,didLoad:try! JSONSerialization.data(withJSONObject:body))
        client?.urlProtocolDidFinishLoading(self)
    }
}
// Direct protocol client: no URLSession task or network is needed for capture coverage.
private final class FailureProtocolClient: NSObject, URLProtocolClient {
    var calls=[String]()
    var mainOwned=true
    private func record(_ call: String) { mainOwned = mainOwned && Thread.isMainThread; calls.append(call) }
    func urlProtocol(_ p: URLProtocol, wasRedirectedTo request: URLRequest, redirectResponse: URLResponse) { record("redirect") }
    func urlProtocol(_ p: URLProtocol, cachedResponseIsValid cachedResponse: CachedURLResponse) { record("cache") }
    func urlProtocol(_ p: URLProtocol, didReceive response: URLResponse, cacheStoragePolicy policy: URLCache.StoragePolicy) { record("response") }
    func urlProtocol(_ p: URLProtocol, didLoad data: Data) { record("data") }
    func urlProtocolDidFinishLoading(_ p: URLProtocol) { record("finish") }
    func urlProtocol(_ p: URLProtocol, didFailWithError error: Error) { record("error") }
    func urlProtocol(_ p: URLProtocol, didReceive challenge: URLAuthenticationChallenge) { record("challenge") }
    func urlProtocol(_ p: URLProtocol, didCancel challenge: URLAuthenticationChallenge) { record("cancel") }
}
struct KnownFailureTests {
    static var checks=[String]()
    static func check(_ ok: @autoclosure () -> Bool, _ label: String) {
        guard ok() else { fputs("FAIL: \(label)\n",stderr); exit(1) }
        checks.append(label)
    }
    static func wait(_ label: String, _ condition: () -> Bool) {
        let end=Date().addingTimeInterval(5)
        while !condition() && Date()<end { _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.01)) }
        check(condition(),label)
    }
    static var diagnostic: [String:Any] {
        ["schema":1,"operation":"START","outcome":"FAILED","stage":"PROXY","reason":"SYSTEM_PROXY_ACTIVE","rollback":"NOT_ATTEMPTED","restoration":"NOT_ATTEMPTED","cleanup":"VERIFIED","receipt":"WRITTEN","job":"UNLOADED","tun":"NOT_OBSERVED"]
    }
    static func body(_ d: [String:Any]? = nil) -> [String:Any] {
        ["error":"START_FAILED","diagnostics":d ?? diagnostic,"startup_operation":["timeline_schema":1,"availability":"AVAILABLE","operation_id":String(repeating:"a",count:32)]]
    }
    static func client() -> APIClient {
        APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:18089"),configuration:{ let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[FailureProtocol.self]; return c })
    }
    static func run() -> [String] {
        checks=[]
        let hot: [String:Any] = ["ok":true,"saved":true,"changed":true,"applied":true,"apply_status":"HOT_APPLIED","pendingReload":false,"pendingKnown":true,"etag":"\""+String(repeating:"a",count:64)+"\"","startup_operation":NSNull(),"connection_policy":"EXISTING_CONNECTIONS_RETAIN_OLD_EXIT","selection_operation":["operation":String(repeating:"a",count:32),"generation":String(repeating:"b",count:32),"revision":7,"node":"node"],"readback_requires_owned_lease":false]
        check(mutationVerdict(path:"/nodes/selection",status:200,body:hot) == .applied,"HOT_APPLIED exact tuple admitted")
        for (key,value) in [("saved",false as Any),("changed",1),("applied",false),("applied",1),("pendingReload",true),("pendingKnown",false),("etag","bad"),("startup_operation",[:]),("connection_policy","DROP_EXISTING"),("foreign",true)] {
            var b=hot;b[key]=value
            check(mutationVerdict(path:"/nodes/selection",status:200,body:b) == .unknown,"HOT_APPLIED poison \(key)=\(value)")
        }
        for key in hot.keys.sorted() {
            var b=hot;b.removeValue(forKey:key)
            check(mutationVerdict(path:"/nodes/selection",status:200,body:b) == .unknown,"HOT_APPLIED missing \(key)")
        }
        var reloadRequired=hot;reloadRequired["apply_status"]="RELOAD_REQUIRED";reloadRequired["applied"]=false;reloadRequired["pendingReload"]=true
        check(mutationVerdict(path:"/nodes/selection",status:200,body:reloadRequired) == .reloadRequired,"RELOAD_REQUIRED visible not sticky unknown")
        reloadRequired["applied"]=true
        check(mutationVerdict(path:"/nodes/selection",status:200,body:reloadRequired) == .unknown,"RELOAD_REQUIRED cannot also claim applied")
        let local: [String:Any] = ["schema":1,"operation":"START","outcome":"SUCCEEDED","stage":"LOCAL_READY","reason":"INTERNET_UNVERIFIED","rollback":"NOT_ATTEMPTED","restoration":"NOT_ATTEMPTED","cleanup":"NOT_ATTEMPTED","receipt":"WRITTEN","job":"RUNNING","tun":"TUN"]
        check(mutationVerdict(path:"/service/start",status:200,body:["ok":true,"loaded":true,"running":true,"diagnostics":local]) == .serviceSucceeded,"local readiness accepted without internet claim")
        for (key,value) in [("reason","NONE"),("job","UNKNOWN"),("tun","NOT_TUN"),("outcome","FAILED"),("receipt","FAILED"),("operation","STOP"),("cleanup","POISON"),("rollback","POISON")] {
            var d=local; d[key]=value
            check(mutationVerdict(path:"/service/start",status:200,body:["ok":true,"loaded":true,"running":true,"diagnostics":d]) == .unknown,"HTTP200 poisoned local readiness \(key) rejected")
        }
        // Exercise actual selection callback, including sticky unknown ownership.
        for kind in ["hot","reload","unknown"] {
            let model=MenuModel(api:client(),connectivityMonitor:nil)
            var posts=0, reads=Set<String>(), response=hot
            if kind == "reload" { response["apply_status"]="RELOAD_REQUIRED";response["applied"]=false;response["pendingReload"]=true }
            if kind == "unknown" { response["apply_status"]="SWITCH_UNKNOWN";response["applied"]=false;response["pendingReload"]=true;response["selection_operation"]=NSNull();response["readback_requires_owned_lease"]=true }
            FailureProtocol.handler={ req,p in
                let path=req.url!.path
                if path.hasSuffix("/login") { p.reply(200,["csrf":String(repeating:"x",count:43),"expiresIn":28800]);return }
                if req.httpMethod == "POST" { posts += 1;p.reply(200,response);return }
                reads.insert(path)
                if path.hasSuffix("/status") && !path.contains("helper") { p.reply(200,["availability":"AVAILABLE","loaded":true,"running":true]) }
                else if path.contains("helper") { p.reply(200,["available":true]) }
                else if path.hasSuffix("/nodes") { p.reply(200,["etag":"\""+String(repeating:"a",count:64)+"\"","nodes":[["name":"node","selectable":true,"selected":true,"skipVerify":false]]]) }
                else { p.reply(503,[:]) }
            }
            var logged=false;model.api.login(password:"SYNTHETIC_FIXTURE_ONLY") { logged=$0 }
            wait("selection \(kind) authenticated") { logged }
            model.refresh();wait("selection \(kind) initial reads") { model.canMutate && reads.count == 4 }
            drain(model.api);reads.removeAll()
            model.mutate(path:"/nodes/selection",name:"node",consent:false)
            wait("selection \(kind) callback refresh") { posts == 1 && !model.pending && model.status != nil && reads.count == 4 }
            drain(model.api)
            check(model.uncertain == (kind == "unknown") && model.canMutate == (kind != "unknown"),"selection \(kind) mutation ownership")
            check(kind == "hot" ? model.message.contains("已有连接保留原出口") : kind == "reload" ? model.message.contains("VPN 未重启") : model.message.contains("已锁定"),"selection \(kind) visible exact result")
            if kind == "unknown" {
                response["apply_status"]="NO_CHANGE";response["changed"]=false
                model.refresh();drain(model.api)
                model.mutate(path:"/nodes/selection",name:"node",consent:false)
                check(posts == 1 && model.uncertain && !model.canMutate,"NO_CHANGE cannot clear unknown or send another selection")
            }
            model.api.reset()
        }
        check(mutationVerdict(path:"/nodes/selection",status:409,body:["error":"SWITCH_UNKNOWN","readback_requires_owned_lease":true]) == .unknown,"server unknown lease rejection retains client lock")
        selectionRecoveryTests(hot)
        let proxyFailure=body()
        check(mutationVerdict(path:"/service/start",status:503,body:proxyFailure) == .rejected,"503 typed PROXY FAILED is known unsuccessful, not UNKNOWN")
        for (key,value) in [("schema",true as Any),("schema",2 as Any),("operation","STOP"),("outcome","UNKNOWN"),("outcome","CANCELLED"),("outcome","SUCCEEDED"),("stage","UNKNOWN"),("stage","DNS"),("reason","SECRET_BACKEND_TEXT"),("rollback","FAILED"),("restoration","UNKNOWN"),("cleanup","FAILED"),("cleanup","NOT_ATTEMPTED"),("receipt","FAILED"),("job","RUNNING"),("tun","TUN")] {
            var d=diagnostic; d[key]=value
            check(mutationVerdict(path:"/service/start",status:503,body:body(d)) == .unknown,"negative diagnostic \(key)=\(value)")
        }
        for key in diagnostic.keys.sorted() {
            var d=diagnostic; d.removeValue(forKey:key)
            check(mutationVerdict(path:"/service/start",status:503,body:body(d)) == .unknown,"missing diagnostic \(key)")
        }
        var extra=diagnostic; extra["private_message"]="SECRET_BACKEND_TEXT"
        check(mutationVerdict(path:"/service/start",status:503,body:body(extra)) == .unknown,"unknown diagnostic member rejected")
        for status in [200,202,500,502,504] {
            check(mutationVerdict(path:"/service/start",status:status,body:proxyFailure) == .unknown,"status \(status) not promoted")
        }
        for path in ["/service/stop","/service/reload","/nodes/selection","/other"] {
            check(mutationVerdict(path:path,status:503,body:proxyFailure) == .unknown,"action mismatch \(path)")
        }
        for key in ["diagnostics","startup_operation"] {
            var b=proxyFailure; b.removeValue(forKey:key)
            check(mutationVerdict(path:"/service/start",status:503,body:b) == .unknown,"missing response \(key)")
        }
        for (key,value) in [("timeline_schema",true as Any),("availability","UNAVAILABLE"),("operation_id",String(repeating:"A",count:32)),("operation_id","short")] {
            var b=proxyFailure; var ref=b["startup_operation"] as! [String:Any]; ref[key]=value; b["startup_operation"]=ref
            check(mutationVerdict(path:"/service/start",status:503,body:b) == .unknown,"negative reference \(key)=\(value)")
        }
        for code in ["STARTUP_UNKNOWN","SECRET_BACKEND_TEXT"] {
            var b=proxyFailure; b["error"]=code
            check(mutationVerdict(path:"/service/start",status:503,body:b) == .unknown,"error code \(code) not trusted")
        }
        var partial=proxyFailure; partial["ok"]=true; partial["saved"]=true; partial["apply_status"]="FAILED"
        check(mutationVerdict(path:"/nodes/selection",status:200,body:partial) == .unknown,"saved-but-apply-failed is not rejected or saved success")

        // Real APIClient -> MenuModel callback, not a separate verdict reimplementation.
        for kind in ["known","lost","pending","malformed"] {
            let api=client(), model=MenuModel(api:client(),connectivityMonitor:nil)
            // Use only the model-owned API; all values are synthetic fixture credentials.
            api.reset()
            var posts=0, reads=Set<String>(), resultKind=kind
            FailureProtocol.handler={ req,p in
                let path=req.url!.path
                if path == "/api/v1/login" { p.reply(200,["csrf":String(repeating:"x",count:43),"expiresIn":28800]); return }
                if req.httpMethod == "POST" {
                    posts += 1
                    check(req.value(forHTTPHeaderField:"Origin") == "http://127.0.0.1:18089","\(kind) mutation Origin")
                    check(req.value(forHTTPHeaderField:"X-CSRF-Token") == String(repeating:"x",count:43),"\(kind) mutation CSRF")
                    if resultKind == "lost" { p.client?.urlProtocol(p,didFailWithError:URLError(.networkConnectionLost)) }
                    else { p.reply(resultKind == "pending" ? 202 : 503,resultKind == "malformed" ? ["error":"START_FAILED","diagnostics":[:]] : proxyFailure) }
                    return
                }
                reads.insert(path)
                if path == "/api/v1/status" { p.reply(200,["availability":"AVAILABLE","loaded":false,"running":false]) }
                else if path == "/api/v1/helper/status" { p.reply(200,["available":true]) }
                else if path == "/api/v1/nodes" { p.reply(200,["etag":"\""+String(repeating:"b",count:64)+"\"","nodes":[]]) }
                else { p.reply(503,["availability":"UNAVAILABLE"]) }
            }
            var logged=false
            model.api.login(password:"SYNTHETIC_FIXTURE_ONLY") { logged=$0 }
            wait("\(kind) authenticated") { logged }
            model.refresh(); wait("\(kind) initial reads complete") { model.canMutate && reads.count == 4 }
            // Admit read sentinels after each original API owner releases.
            drain(model.api); reads.removeAll()
            model.mutate(path:"/service/start",consent:false)
            wait("\(kind) actual mutation callback and refresh") { posts == 1 && !model.pending && model.status != nil && reads.count == 4 }
            drain(model.api)
            if kind == "known" {
                check(!model.uncertain && model.canMutate,"known FAILED does not leave UNKNOWN UI lock")
                check(model.message.contains("系统代理") && !model.message.contains("未知"),"known FAILED has allowlisted Chinese system-proxy cause")
                check(model.operationID == String(repeating:"a",count:32),"known FAILED retains operation identity")
            } else {
                check(model.uncertain && !model.canMutate,"\(kind) remains locked after refresh")
                model.mutate(path:"/service/start",consent:false)
            }
            check(posts == 1,"\(kind) no automatic retry or STOP replay")
            resultKind="known"; model.refresh(); drain(model.api)
            check(model.uncertain == (kind != "known"),"\(kind) plain refresh cannot clear historical uncertainty")
            model.api.reset()
        }
        // The shared verdict must block Quit, never acknowledge STOP or issue readback/replay.
        let qapi=client(), quitModel=MenuModel(api:client(),connectivityMonitor:nil)
        qapi.reset(); var stops=0, statusReads=0
        var stopDiagnostic=diagnostic; stopDiagnostic["operation"]="STOP"; stopDiagnostic["stage"]="STOP"; stopDiagnostic["reason"]="STOP_FAILED"
        var stopBody=body(stopDiagnostic); stopBody["error"]="STOP_FAILED"
        FailureProtocol.handler={ req,p in
            if req.url!.path.hasSuffix("/login") { p.reply(200,["csrf":String(repeating:"x",count:43),"expiresIn":28800]) }
            else if req.url!.path.hasSuffix("/service/stop") { stops += 1; p.reply(503,stopBody) }
            else if req.url!.path.contains("helper") { p.reply(200,["available":true]) }
            else { statusReads += 1; p.reply(200,["availability":"AVAILABLE","loaded":true,"running":true]) }
        }
        var logged=false; quitModel.api.login(password:"SYNTHETIC_FIXTURE_ONLY") { logged=$0 }; wait("quit authenticated") { logged }
        var outcome: QuitOutcome?
        quitModel.beginQuit(context:quitModel.quitContext!) { outcome=$0 }
        wait("quit failure callback") { outcome != nil }
        check(outcome == .blocked && !quitModel.uncertain && !quitModel.pending,"known STOP failure blocks Quit, never success or UNKNOWN")
        check(stops == 1 && statusReads == 1,"failed Quit has one STOP, no success readback or replay")
        quitModel.api.reset()
        // Append after all 97 prior checks; establish A before publishing B, then start late.
        let request=URLRequest(url:URL(string:"http://127.0.0.1:18089/failure-capture-regression")!)
        let recorder=FailureProtocolClient()
        var held: FailureProtocol?, wrongHandler=false, onMain=false
        FailureProtocol.handler={ _,p in onMain=Thread.isMainThread; held=p }
        let instance=FailureProtocol(request:request,cachedResponse:nil,client:recorder)
        FailureProtocol.handler={ _,_ in wrongHandler=true }
        let started=DispatchSemaphore(value:0)
        DispatchQueue.global().async { instance.startLoading(); started.signal() }
        guard started.wait(timeout:.now()+15) == .success else { fatalError("failure fixture start barrier") }
        let end=Date().addingTimeInterval(5)
        while held == nil && !wrongHandler && Date()<end { _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.01)) }
        check(held === instance && !wrongHandler,"failure fixture handler captured at protocol initialization")
        check(onMain && Thread.isMainThread && recorder.calls.isEmpty,"failure fixture held handler delivery is main-owned")
        held?.reply(200,[:])
        check(recorder.mainOwned && recorder.calls == ["response","data","finish"],"failure fixture direct client receives one main-owned response body finish")
        FailureProtocol.handler=nil
        return checks
    }
    static func selectionRecoveryTests(_ template: [String:Any]) {
        let began=checks.count
        let node="节点 +&?#/名", tag=template["etag"] as! String
        var hot=template
        var tuple=template["selection_operation"] as! [String:Any]
        tuple["node"]=node; tuple["revision"]=NSNumber(value:UInt64.max)
        hot["selection_operation"]=tuple
        for value in ["0","9007199254740993","18446744073709551615"] {
            let raw="{\"operation\":\""+String(repeating:"a",count:32)+"\",\"generation\":\""+String(repeating:"b",count:32)+"\",\"revision\":"+value+",\"node\":\"node\"}"
            let parsed=try! JSONSerialization.jsonObject(with:Data(raw.utf8))
            check(SelectionOperation.parse(parsed)?.revision == UInt64(value),"selection UInt64 wire exact \(value)")
        }
        for value in [true as Any,-1,1.5,"7",NSNumber(value:Double(7))] {
            var bad=tuple;bad["revision"]=value
            check(SelectionOperation.parse(bad) == nil,"selection revision rejects \(value)")
        }
        var same=hot;same["changed"]=false
        check(mutationVerdict(path:"/nodes/selection",status:200,body:same) == .applied,"same-selection HOT ACK admitted without extra POST")
        let cases=["good","same","etag","header","operation","generation","revision","node","pending","known","null","foreign","lease","nochange","status","transport","stale"]
        for kind in cases {
            let model=MenuModel(api:client(),connectivityMonitor:nil)
            var posts=0, gets=0, held: FailureProtocol?, captured: URLRequest?
            var response=hot
            if kind == "same" { response["changed"]=false }
            var unknown=response;unknown["apply_status"]="SWITCH_UNKNOWN";unknown["applied"]=false;unknown["pendingReload"]=true;unknown["pendingKnown"]=false
            FailureProtocol.handler={ req,p in
                let path=req.url!.path
                if path.hasSuffix("/login") { p.reply(200,["csrf":String(repeating:"x",count:43),"expiresIn":28800]);return }
                if req.httpMethod == "POST" { posts += 1;p.reply(200,unknown);return }
                if path.hasSuffix("/selection/readback") { gets += 1;held=p;captured=req;return }
                if path == "/api/v1/status" { p.reply(200,["availability":"AVAILABLE","loaded":true,"running":true]) }
                else if path.contains("helper") { p.reply(200,["available":true]) }
                else if path.hasSuffix("/nodes") { p.reply(200,["etag":tag,"nodes":[["name":node,"selectable":true,"selected":true,"skipVerify":false]]]) }
                else { p.reply(503,[:]) }
            }
            var logged=false;model.api.login(password:"SYNTHETIC_FIXTURE_ONLY") { logged=$0 }
            wait("readback \(kind) authenticated") { logged }
            model.refresh();wait("readback \(kind) initial reads") { model.canMutate };drain(model.api)
            model.mutate(path:"/nodes/selection",name:node,consent:false)
            wait("readback \(kind) held GET") { held != nil && !model.pending };drain(model.api)
            let query=URLComponents(url:captured!.url!,resolvingAgainstBaseURL:false)!.queryItems!
            check(captured!.httpMethod == "GET" && query.count == 4 && query.first(where:{$0.name == "revision"})?.value == String(UInt64.max) && query.first(where:{$0.name == "node"})?.value == node && captured!.url!.absoluteString.contains("%2B"),"readback \(kind) exact encoded UInt64 tuple GET")
            model.mutate(path:"/nodes/selection",name:node,consent:false);model.recoverSelectionReadback()
            check(model.uncertain && !model.canMutate && posts == 1 && gets == 1,"readback \(kind) held lock blocks duplicate dispatch")
            switch kind {
            case "etag": response["etag"]="\""+String(repeating:"c",count:64)+"\""
            case "operation","generation","revision","node":
                var bad=tuple
                if kind == "revision" { bad[kind]=NSNumber(value:UInt64.max-1) }
                else { bad[kind]=kind == "node" ? "foreign" : String(repeating:"c",count:32) }
                response["selection_operation"]=bad
            case "pending": response["pendingReload"]=true
            case "known": response["pendingKnown"]=false
            case "null": response["selection_operation"]=NSNull()
            case "foreign": response["foreign"]=true
            case "lease": response["readback_requires_owned_lease"]=true
            case "nochange": response["apply_status"]="NO_CHANGE";response["changed"]=false
            case "status": response=["availability":"AVAILABLE","loaded":true,"running":true]
            default: break
            }
            if kind == "stale" {
                model.api.reset()
                held!.reply(200,response)
                var settled=false
                DispatchQueue.main.asyncAfter(deadline:.now()+0.05) { settled=true }
                let fence=Date().addingTimeInterval(5)
                while !settled && Date()<fence { _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.01)) }
            } else if kind == "transport" { held!.client?.urlProtocol(held!,didFailWithError:URLError(.networkConnectionLost)) }
            else { held!.reply(200,response,etag:kind == "header" ? "\""+String(repeating:"c",count:64)+"\"" : nil) }
            // Observe actual callback settlement, not a timing-only negative.
            let until=Date().addingTimeInterval(5)
            while model.selectionReadPending && kind != "stale" && Date()<until { _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.01)) }
            check((kind == "stale" || !model.selectionReadPending) && model.uncertain == !(kind == "good" || kind == "same"),"readback \(kind) only exact owned HOT clears unknown")
            check(posts == 1 && gets == 1,"readback \(kind) never POST STOP reload or retry")
            model.api.reset()
        }
        check(checks.count-began == 162,"selection recovery source inventory 162 checks before inventory assertion")
    }
    static func drain(_ api: APIClient) {
        var admitted=Set<String>(), completed=Set<String>()
        wait("four read owners drained") {
            for path in ["/status","/helper/status","/nodes","/traffic"] where !admitted.contains(path) {
                if api.request(path,completion:{ _ in completed.insert(path) }) { admitted.insert(path) }
            }
            return completed.count == 4
        }
    }
}
