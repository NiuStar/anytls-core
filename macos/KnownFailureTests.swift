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
    func reply(_ status: Int, _ body: [String:Any]) {
        client?.urlProtocol(self,didReceive:HTTPURLResponse(url:request.url!,statusCode:status,httpVersion:nil,headerFields:nil)!,cacheStoragePolicy:.notAllowed)
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
