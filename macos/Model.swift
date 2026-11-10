import Foundation

struct LocalEndpoint: Equatable {
    let url: URL
    let origin: String
    init(_ text: String) throws {
        // Restrict lexical form too: URLComponents otherwise repairs whitespace/escapes.
        guard text.range(of: #"^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]{1,5})?$"#, options: .regularExpression) != nil,
              let c = URLComponents(string: text), let url = c.url,
              c.port == nil || (1...65535).contains(c.port!) else { throw ClientError.endpoint }
        self.url = url; origin = text
    }
}
enum ClientError: Error { case endpoint, invalid, stale, unauthenticated, transport }
func canonicalUInt(_ value: Any?) -> UInt64? {
    guard let s = value as? String, s.range(of: #"^(0|[1-9][0-9]{0,19})$"#, options: .regularExpression) != nil else { return nil }
    return UInt64(s)
}
func hex(_ value: Any?, _ count: Int) -> Bool {
    guard let s = value as? String else { return false }
    return s.utf8.count == count && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
func exact(_ d: [String: Any], _ keys: [String]) -> Bool { Set(d.keys) == Set(keys) }
func utcDate(_ value: Any?) -> Date? {
    guard let s = value as? String, s.range(of: #"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$"#, options: .regularExpression) != nil else { return nil }
    let f = ISO8601DateFormatter(); f.formatOptions = s.contains(".") ? [.withInternetDateTime, .withFractionalSeconds] : [.withInternetDateTime]
    return f.date(from: s)
}
func jsonBool(_ v: Any?) -> Bool? {
    guard let n = v as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }; return n.boolValue
}
import CoreFoundation
func schemaOne(_ value: Any?) -> Bool {
    guard let n=value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return false }
    return n == 1
}
struct TrafficRate {
    let runtimeIdentity: String
    let sampledAt: Date
    let upload: UInt64, download: UInt64, duration: UInt64
    let totalUpload: UInt64, totalDownload: UInt64
    func fresh(_ now: Date = Date()) -> Bool { (0...15).contains(now.timeIntervalSince(sampledAt)) }
    static func label(_ bytes: UInt64, _ duration: UInt64) -> String {
        let rate = Double(bytes) / (Double(duration) / 1_000_000_000)
        if rate >= 1_000_000_000 { return String(format: "%.1fGB/s", rate / 1_000_000_000) }
        if rate >= 1_000_000 { return String(format: "%.1fMB/s", rate / 1_000_000) }
        if rate >= 1_000 { return String(format: "%.1fKB/s", rate / 1_000) }
        return String(format: "%.0fB/s", rate)
    }
    static func parse(_ data: [String: Any], now: Date = Date()) -> TrafficRate? {
        guard exact(data, ["traffic_schema", "availability", "snapshot"]), schemaOne(data["traffic_schema"]),
              data["availability"] as? String == "OBSERVED", let s = data["snapshot"] as? [String: Any],
              exact(s, ["traffic_schema", "header", "source", "state", "sampled_at", "elapsed_ns", "upload_bytes", "download_bytes", "saturated", "rate", "history"]),
              schemaOne(s["traffic_schema"]), s["source"] as? String == "SDK_ROUTED_PAYLOAD", s["state"] as? String == "RUNNING",
              jsonBool(s["saturated"]) == false, let date = utcDate(s["sampled_at"]), (0...15).contains(now.timeIntervalSince(date)),
              let elapsed = canonicalUInt(s["elapsed_ns"]), elapsed <= UInt64(Int64.max),
              let up = canonicalUInt(s["upload_bytes"]), let down = canonicalUInt(s["download_bytes"]),
              let h = s["header"] as? [String: Any],
              exact(h, ["schema_version", "config_identity", "instance_id", "generation", "manifest_id", "runtime_sha256", "created_at", "previous_binding"]),
              schemaOne(h["schema_version"]), hex(h["instance_id"],32), hex(h["generation"],32), hex(h["manifest_id"],64),
              hex(h["config_identity"],64), hex(h["runtime_sha256"],64), utcDate(h["created_at"]) != nil else { return nil }
        if !(h["previous_binding"] is NSNull) {
            guard let p = h["previous_binding"] as? [String: Any], exact(p,["instance_id","generation","manifest_id"]), hex(p["instance_id"],32), hex(p["generation"],32), hex(p["manifest_id"],64) else { return nil }
        }
        struct Interval { let start: UInt64, end: UInt64, up: UInt64, down: UInt64 }
        func interval(_ raw: Any?) -> Interval? {
            guard let i = raw as? [String: Any], exact(i,["start_ns","end_ns","upload_bytes","download_bytes"]),
                  let a = canonicalUInt(i["start_ns"]), let b = canonicalUInt(i["end_ns"]), a < b, b <= elapsed,
                  let u = canonicalUInt(i["upload_bytes"]), u <= up, let d = canonicalUInt(i["download_bytes"]), d <= down else { return nil }
            return Interval(start:a,end:b,up:u,down:d)
        }
        guard let r = interval(s["rate"]), r.end == elapsed, let history = s["history"] as? [Any], history.count <= 1440 else { return nil }
        var end: UInt64 = 0, sumUp: UInt64 = 0, sumDown: UInt64 = 0
        for raw in history {
            guard let i = interval(raw), i.start >= end, i.end-i.start >= 60_000_000_000, elapsed-i.start <= 86_400_000_000_000 else { return nil }
            let (u, uo) = sumUp.addingReportingOverflow(i.up), (d, `do`) = sumDown.addingReportingOverflow(i.down)
            guard !uo, !`do`, u <= up, d <= down else { return nil }
            if r.start >= i.start && r.end <= i.end && (r.up > i.up || r.down > i.down) { return nil }
            sumUp=u; sumDown=d; end=i.end
        }
        return TrafficRate(runtimeIdentity:(h["instance_id"] as! String)+":"+(h["generation"] as! String),sampledAt:date,upload:r.up,download:r.down,duration:r.end-r.start,totalUpload:up,totalDownload:down)
    }
}
struct ServiceStatus {
    let loaded: Bool, running: Bool
    static func parse(_ d: [String: Any]) -> ServiceStatus? {
        guard d["availability"] as? String == "AVAILABLE", let l=jsonBool(d["loaded"]), let r=jsonBool(d["running"]), !r || l else { return nil }
        return ServiceStatus(loaded:l,running:r)
    }
}
// Manual TCP observations are independent of selection and lifecycle authority.
struct NodeLatency {
    let label: String
    let checkedAt: Date
    static func parse(_ d: [String:Any], name: String, etag: String, now: Date = Date()) -> NodeLatency? {
        guard exact(d,["name","mode","status","latency_ms","error","checked_at","risk_insecure","config_etag"]),
              d["name"] as? String == name, d["mode"] as? String == "tcp_direct", d["config_etag"] as? String == etag,
              jsonBool(d["risk_insecure"]) != nil, let at=utcDate(d["checked_at"]),
              (0...15).contains(now.timeIntervalSince(at)), let error=d["error"] as? String else { return nil }
        let label: String
        switch d["status"] as? String {
        case "OK":
            guard error.isEmpty, let ms=d["latency_ms"] as? NSNumber, CFGetTypeID(ms) != CFBooleanGetTypeID(),
                  ms.doubleValue.isFinite, (0...12000).contains(ms.doubleValue) else { return nil }
            label=String(format:"%.0f ms",ms.doubleValue.rounded())
        case "FAILED": guard d["latency_ms"] is NSNull, ["PROBE_FAILED","PROBE_CANCELED"].contains(error) else { return nil }; label="失败"
        case "TIMEOUT": guard d["latency_ms"] is NSNull, error == "PROBE_TIMEOUT" else { return nil }; label="超时"
        case "UNSUPPORTED": guard d["latency_ms"] is NSNull, error == "PROBE_UNSUPPORTED" else { return nil }; label="不支持"
        case "UNAVAILABLE": guard d["latency_ms"] is NSNull, error == "PROBE_DIRECT_UNAVAILABLE" else { return nil }; label="不可用"
        default: return nil
        }
        return NodeLatency(label:label,checkedAt:at)
    }
}
struct Node {
    let name: String, selectable: Bool, selected: Bool, skipVerify: Bool, needsSync: Bool
    static func parse(_ value: Any) -> Node? {
        guard let d=value as? [String: Any], let name=d["name"] as? String, !name.isEmpty, name.utf8.count < 4096,
              let selectable=jsonBool(d["selectable"]), let selected=jsonBool(d["selected"]), let skip=jsonBool(d["skipVerify"]) else { return nil }
        return Node(name:name,selectable:selectable,selected:selected,skipVerify:skip,needsSync:jsonBool(d["selectionNeedsSync"]) ?? false)
    }
}
// Only an invocation-local, action-bound failure ACK with a closed safe cleanup
// can avoid UNKNOWN. A later trace/status read is never a replacement ACK.
func knownMutationFailureReason(path: String, status: Int, body: [String: Any]) -> String? {
    let operations=["/service/start":"START","/service/reload":"RELOAD","/service/stop":"STOP"]
    let reasons=[
        "HELPER_PREFLIGHT":"PREFLIGHT_REJECTED", "JOB":"JOB_STATE_UNAVAILABLE JOB_ALREADY_LOADED JOB_NOT_LOADED",
        "SNAPSHOT":"SNAPSHOT_EXISTS SNAPSHOT_UNAVAILABLE SNAPSHOT_STAGE_FAILED SNAPSHOT_IDENTITY_FAILED",
        "CONFIG":"CONFIG_COMPILE_FAILED", "PROXY":"SYSTEM_PROXY_ACTIVE PROXY_STATE_UNAVAILABLE",
        "SERVER_ROUTE":"SERVER_ROUTE_UNAVAILABLE SERVER_ROUTE_NOT_PHYSICAL SERVER_ROUTE_CHANGED", "PUBLIC_ROUTE":"PUBLIC_ROUTE_UNAVAILABLE",
        "DNS":"DNS_STATE_UNAVAILABLE DNS_EVIDENCE_EMPTY", "BASELINE":"BASELINE_INVALID BASELINE_WRITE_FAILED",
        "PLIST":"PLIST_CREATE_FAILED PLIST_WRITE_FAILED PLIST_INVALID", "BOOTSTRAP":"LAUNCHD_BOOTSTRAP_FAILED",
        "READINESS":"READINESS_JOB_UNAVAILABLE READINESS_ROUTE_UNAVAILABLE READINESS_CHANGED PROCESS_NOT_RUNNING TUN_NOT_READY PROCESS_AND_TUN_NOT_READY READINESS_UNKNOWN",
        "HTTPS":"HTTPS_DNS_FAILED HTTPS_CONNECT_FAILED HTTPS_TIMEOUT HTTPS_TLS_HANDSHAKE_FAILED HTTPS_CERTIFICATE_FAILED HTTPS_HTTP_FAILED HTTPS_EMPTY_RESPONSE HTTPS_RECEIVE_FAILED HTTPS_RESPONSE_INVALID HTTPS_FAILED",
        "STOP":"STOP_FAILED"
    ]
    guard status == 503, let operation=operations[path], exact(body,["error","diagnostics","startup_operation"]),
          let code=body["error"] as? String,
          ["HELPER_UNAVAILABLE","HELPER_CONFIG_MISMATCH","FORBIDDEN","INVALID_REQUEST","BUSY","PREFLIGHT_FAILED","STOP_FAILED","START_FAILED","STATE_FAILED","SERVICE_ACTION_FAILED"].contains(code),
          let ref=body["startup_operation"] as? [String:Any], exact(ref,["timeline_schema","availability","operation_id"]),
          schemaOne(ref["timeline_schema"]), ref["availability"] as? String == "AVAILABLE", hex(ref["operation_id"],32),
          let d=body["diagnostics"] as? [String:Any],
          exact(d,["schema","operation","outcome","stage","reason","rollback","restoration","cleanup","receipt","job","tun"]),
          schemaOne(d["schema"]), d["operation"] as? String == operation, d["outcome"] as? String == "FAILED",
          let stage=d["stage"] as? String, let reason=d["reason"] as? String,
          reasons[stage]?.split(separator:" ").contains(Substring(reason)) == true,
          ["VERIFIED","NOT_ATTEMPTED"].contains(d["rollback"] as? String ?? ""),
          ["VERIFIED","NOT_ATTEMPTED"].contains(d["restoration"] as? String ?? ""),
          d["cleanup"] as? String == "VERIFIED", d["receipt"] as? String == "WRITTEN",
          d["job"] as? String == "UNLOADED", ["NOT_OBSERVED","NOT_TUN"].contains(d["tun"] as? String ?? "") else { return nil }
    return reason
}

enum MutationVerdict: Equatable { case serviceSucceeded, savedStopped, applied, reloadRequired, unchanged, rejected, unknown }

func selectionConnectionPolicy(_ body: [String:Any]) -> String? {
    guard body["connection_policy"] as? String == "EXISTING_CONNECTIONS_RETAIN_OLD_EXIT" else { return nil }
    return "新连接使用新节点；已有连接保留原出口"
}

struct SelectionOperation: Equatable {
    let operation: String, generation: String, revision: UInt64, node: String
    static func parse(_ value: Any?) -> SelectionOperation? {
        guard let d=value as? [String:Any], exact(d,["operation","generation","revision","node"]),
              hex(d["operation"],32), hex(d["generation"],32), let n=d["revision"] as? NSNumber,
              CFGetTypeID(n) != CFBooleanGetTypeID(), !["f","d"].contains(String(cString:n.objCType)),
              let revision=canonicalUInt(n.stringValue), String(revision) == n.stringValue,
              let node=d["node"] as? String, !node.isEmpty, node.utf8.count < 4096 else { return nil }
        return SelectionOperation(operation:d["operation"] as! String,generation:d["generation"] as! String,revision:revision,node:node)
    }
    var readbackPath: String {
        var c=URLComponents(); c.path="/nodes/selection/readback"
        c.queryItems=[URLQueryItem(name:"operation",value:operation),URLQueryItem(name:"generation",value:generation),URLQueryItem(name:"revision",value:String(revision)),URLQueryItem(name:"node",value:node)]
        // URLComponents leaves + literal; Go query parsing treats it as a space.
        return c.string!.replacingOccurrences(of:"+",with:"%2B")
    }
}
func validHotSelection(_ body: [String:Any]) -> Bool {
    guard exact(body,["ok","saved","changed","applied","apply_status","pendingReload","pendingKnown","etag","startup_operation","connection_policy","selection_operation","readback_requires_owned_lease"]),
          jsonBool(body["ok"]) == true, jsonBool(body["saved"]) == true, jsonBool(body["changed"]) != nil,
          jsonBool(body["applied"]) != nil, jsonBool(body["pendingReload"]) != nil,
          jsonBool(body["readback_requires_owned_lease"]) != nil,
          body["selection_operation"] is NSNull || SelectionOperation.parse(body["selection_operation"]) != nil,
          body["startup_operation"] is NSNull, selectionConnectionPolicy(body) != nil,
          let etag=body["etag"] as? String, etag.utf8.count == 66, etag.first == "\"", etag.last == "\"",
          hex(String(etag.dropFirst().dropLast()),64), jsonBool(body["pendingKnown"]) != nil else { return false }
    return true
}
func mutationVerdict(path: String, status: Int, body: [String: Any]) -> MutationVerdict {
    if body["error"] as? String == "SWITCH_UNKNOWN" || body["apply_status"] as? String == "SWITCH_UNKNOWN" { return .unknown }
    if status == 202 || body["error"] as? String == "STARTUP_UNKNOWN" || body["apply_error"] as? String == "STARTUP_UNKNOWN" { return .unknown }
    if let d=body["diagnostics"] as? [String: Any], d["outcome"] as? String == "UNKNOWN" { return .unknown }
    if knownMutationFailureReason(path:path,status:status,body:body) != nil { return .rejected }
    if status != 200 { return (400...499).contains(status) ? .rejected : .unknown }
    guard jsonBool(body["ok"]) == true else { return .unknown }
    if path == "/nodes/selection" {
        guard jsonBool(body["saved"]) == true else { return .unknown }
        switch body["apply_status"] as? String {
        case "SAVED_STOPPED": return .savedStopped
        case "APPLIED": return jsonBool(body["applied"]) == true ? .applied : .unknown
        case "HOT_APPLIED":
            return validHotSelection(body) && SelectionOperation.parse(body["selection_operation"]) != nil && jsonBool(body["readback_requires_owned_lease"]) == false && jsonBool(body["applied"]) == true && jsonBool(body["pendingReload"]) == false && jsonBool(body["pendingKnown"]) == true ? .applied : .unknown
        case "RELOAD_REQUIRED":
            return validHotSelection(body) && jsonBool(body["applied"]) == false && jsonBool(body["pendingReload"]) == true ? .reloadRequired : .unknown
        case "NO_CHANGE": return jsonBool(body["changed"]) == false ? .unchanged : .unknown
        default: return .unknown
        }
    }
    guard let loaded=jsonBool(body["loaded"]), let running=jsonBool(body["running"]) else { return .unknown }
    if path == "/service/stop", body["diagnostics"] != nil {
        // PID absence cannot override a failed restoration/cleanup/receipt.
        guard let d=body["diagnostics"] as? [String:Any],
              schemaOne(d["schema"]), d["operation"] as? String == "STOP",
              d["outcome"] as? String == "SUCCEEDED",
              ["VERIFIED","NOT_ATTEMPTED"].contains(d["restoration"] as? String ?? ""),
              ["VERIFIED","NOT_ATTEMPTED"].contains(d["cleanup"] as? String ?? ""),
              ["WRITTEN","NOT_ATTEMPTED"].contains(d["receipt"] as? String ?? "") else { return .unknown }
    }
    if path != "/service/stop", let d=body["diagnostics"] as? [String:Any] {
        guard exact(d,["schema","operation","outcome","stage","reason","rollback","restoration","cleanup","receipt","job","tun"]),
              schemaOne(d["schema"]), d["operation"] as? String == (path == "/service/start" ? "START" : "RELOAD"),
              d["outcome"] as? String == "SUCCEEDED" else { return .unknown }
        let legacy = d["stage"] as? String == "NONE" && d["reason"] as? String == "NONE"
        let local = d["stage"] as? String == "LOCAL_READY" && d["reason"] as? String == "INTERNET_UNVERIFIED" && d["job"] as? String == "RUNNING" && d["tun"] as? String == "TUN" && d["receipt"] as? String == "WRITTEN" && ["rollback","restoration","cleanup"].allSatisfy { ["NOT_ATTEMPTED","VERIFIED","FAILED","UNKNOWN"].contains(d[$0] as? String ?? "") }
        guard legacy || local else { return .unknown }
    } else if path != "/service/stop", body["diagnostics"] != nil { return .unknown }
    return path == "/service/stop" ? (!loaded && !running ? .serviceSucceeded : .unknown) : (loaded && running ? .serviceSucceeded : .unknown)
}
