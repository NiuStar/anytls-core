import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class QuitMockProtocol: URLProtocol {
    static var handler: ((URLRequest, QuitMockProtocol) -> Void)?
    static var calls: [URLRequest] = []
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() { Self.calls.append(request); Self.handler?(request,self) }
    override func stopLoading() {}
    func reply(_ status: Int, _ body: [String:Any]) {
        client?.urlProtocol(self,didReceive:HTTPURLResponse(url:request.url!,statusCode:status,httpVersion:nil,headerFields:nil)!,cacheStoragePolicy:.notAllowed)
        client?.urlProtocol(self,didLoad:try! JSONSerialization.data(withJSONObject:body)); client?.urlProtocolDidFinishLoading(self)
    }
    func fail() { client?.urlProtocol(self,didFailWithError:URLError(.networkConnectionLost)) }
}
@main struct QuitTests {
    static var checks: [String] = []
    static func check(_ ok: @autoclosure () -> Bool, _ name: String) {
        guard ok() else { fputs("FAIL: \(name)\n",stderr); exit(1) }; checks.append(name)
    }
    static func wait(_ condition: () -> Bool) {
        let end=Date().addingTimeInterval(4)
        while !condition() && Date()<end { _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.005)) }
        check(condition(),"async completion")
    }
    static let token=String(repeating:"x",count:43)
    static var running=true
    static var stopReply: (QuitMockProtocol) -> Void = { p in running=false; p.reply(200,["ok":true,"loaded":false,"running":false]) }
    static var helper=true
    static func fixture(login: Bool = true) -> MenuModel {
        QuitMockProtocol.calls=[]; helper=true; running=true
        let api=APIClient(endpoint:try! LocalEndpoint("http://127.0.0.1:18089"),configuration:{ let c=URLSessionConfiguration.ephemeral; c.protocolClasses=[QuitMockProtocol.self]; return c })
        if login {
            QuitMockProtocol.handler={ _,p in p.reply(200,["csrf":token,"expiresIn":28800]) }
            var done=false; api.login(password:"SYNTHETIC_ONLY") { check($0,"fixture authenticated"); done=true }; wait { done }
        }
        stopReply={ p in running=false; p.reply(200,["ok":true,"loaded":false,"running":false]) }
        QuitMockProtocol.handler={ req,p in
            check(req.url?.host == "127.0.0.1","loopback fixture only")
            switch req.url!.path {
            case "/api/v1/status": p.reply(200,["availability":"AVAILABLE","loaded":running,"running":running])
            case "/api/v1/helper/status": p.reply(200,["available":helper])
            case "/api/v1/service/stop":
                check(req.httpMethod == "POST","STOP method")
                check(req.value(forHTTPHeaderField:"Origin") == "http://127.0.0.1:18089","STOP Origin")
                check(req.value(forHTTPHeaderField:"X-CSRF-Token") == token,"STOP CSRF")
                stopReply(p)
            case "/api/v1/nodes", "/api/v1/traffic": p.reply(200,[:])
            default: check(false,"fixture route allowlist")
            }
        }
        return MenuModel(api:api,connectivityMonitor:nil)
    }
    static func posts() -> Int { QuitMockProtocol.calls.filter { $0.httpMethod == "POST" && $0.url!.path.hasSuffix("/service/stop") }.count }
    static func run(_ model: MenuModel, deadline: TimeInterval = 2) -> (QuitCoordinator,Bool) {
        let q=QuitCoordinator(model:model,deadline:deadline); var result: Bool?
        q.start { result=$0 }; wait { result != nil }; return (q,result!)
    }
    static func main() {
        do {
            let m=fixture(); let (q,ok)=run(m)
            check(ok && q.state == .ready,"running quit stops then ready")
            check(posts() == 1,"exactly one authenticated stop")
            check(QuitMockProtocol.calls.filter { $0.url!.path == "/api/v1/status" }.count == 2,"fresh status before and after owned acknowledgement")
            m.api.reset()
        }
        do {
            let m=fixture(); running=false; let (q,ok)=run(m)
            check(ok && q.state == .ready && posts() == 1,"already stopped still performs privileged cleanup")
            m.api.reset()
        }
        do {
            let m=fixture(login:false); let (q,ok)=run(m)
            check(!ok && q.state == .blocked && posts() == 0,"unauthenticated cannot exit or STOP")
            m.api.reset()
        }
        do {
            let m=fixture(); helper=false; let (_,ok)=run(m)
            check(!ok && posts() == 0,"helper unavailable blocks without mutation")
            m.api.reset()
        }
        do {
            let m=fixture(); var held: QuitMockProtocol?
            stopReply={ held=$0 }; let q=QuitCoordinator(model:m,deadline:2); var results: [Bool]=[]
            q.start { results.append($0) }; wait { held != nil }
            q.start { _ in check(false,"coalesced quit must not reply twice") }
            m.mutate(path:"/service/reload",consent:false)
            let second=QuitCoordinator(model:m); var rejected: Bool?
            second.start { rejected=$0 }; wait { rejected != nil }
            check(rejected == false && posts() == 1 && m.pending,"pending owner blocks other quit and menu mutation")
            held!.reply(200,["ok":true,"loaded":false,"running":false]); running=false
            wait { results.count == 1 }
            check(results == [true],"repeated termination coalesces one decision")
            m.api.reset()
        }
        do {
            let m=fixture(); stopReply={ p in
                running=false
                p.reply(200,["ok":true,"loaded":false,"running":false,"diagnostics":["schema":1,"operation":"STOP","outcome":"SUCCEEDED","restoration":"VERIFIED","cleanup":"VERIFIED","receipt":"WRITTEN"]])
            }
            let (_,ok)=run(m)
            check(ok && posts() == 1,"verified restoration receipt permits exit")
            m.api.reset()
        }
        for kind in ["transport","pending","falseReceipt","restoration","receipt","malformedDiagnostics","runningReadback"] {
            let m=fixture()
            stopReply={ p in
                switch kind {
                case "transport": p.fail()
                case "pending": p.reply(202,["ok":true,"loaded":false,"running":false])
                case "falseReceipt": p.reply(200,["loaded":false,"running":false])
                case "malformedDiagnostics": p.reply(200,["ok":true,"loaded":false,"running":false,"diagnostics":"invalid"])
                case "restoration", "receipt":
                    p.reply(200,["ok":true,"loaded":false,"running":false,"diagnostics":["schema":1,"operation":"STOP","outcome":"SUCCEEDED","restoration":kind == "restoration" ? "UNKNOWN" : "VERIFIED","cleanup":"VERIFIED","receipt":kind == "receipt" ? "FAILED" : "WRITTEN"]])
                default: p.reply(200,["ok":true,"loaded":false,"running":false])
                }
            }
            let (q,ok)=run(m)
            check(!ok && q.state == .blocked && m.uncertain,"unknown stays blocked: \(kind)")
            m.refresh(); wait { m.status != nil }
            var again: Bool?; q.start { again=$0 }; wait { again != nil }
            check(again == false && posts() == 1 && m.uncertain,"read-only reconciliation never replays STOP: \(kind)")
            m.api.reset()
        }
        do {
            let m=fixture(); stopReply={ $0.reply(403,["error":"REJECTED"]) }; let (q,ok)=run(m)
            check(!ok && q.state == .blocked && !m.uncertain,"explicit rejection cancels termination")
            stopReply={ p in running=false; p.reply(200,["ok":true,"loaded":false,"running":false]) }
            var again: Bool?; q.start { again=$0 }; wait { again != nil }
            check(again == true && posts() == 2,"explicit retry allowed after definite rejection only")
            m.api.reset()
        }
        for mode in ["held","401","reset"] {
            let m=fixture(); var held: QuitMockProtocol?
            stopReply={ p in held=p; if mode == "401" { p.reply(401,["error":"AUTH_REQUIRED"]) } }
            let q=QuitCoordinator(model:m,deadline:0.12); var result: Bool?
            q.start { result=$0 }; wait { held != nil }
            if mode == "reset" { m.api.reset() }
            wait { result != nil }
            check(result == false && q.state == .blocked && m.uncertain && !m.pending,"watchdog fences stalled/expired/reset owner: \(mode)")
            var again: Bool?; q.start { again=$0 }; wait { again != nil }
            check(again == false && posts() == 1,"deadline never blindly retries: \(mode)")
            if mode == "held" {
                running=false; held!.reply(200,["ok":true,"loaded":false,"running":false])
                _=RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.04))
                check(q.state == .blocked && m.uncertain,"late receipt cannot reopen expired quit")
            }
            m.api.reset()
        }
        print(String(data:try! JSONSerialization.data(withJSONObject:["status":"PASS","checks":checks],options:[.prettyPrinted,.sortedKeys]),encoding:.utf8)!)
    }
}
