# Traffic worker 收尾交接（源码写入已停止）

## 结果与边界

本轮仅修改 traffic 所有权源码/独立测试；未改 `webui.go`、`web_metrics.go`、共享路由、assets，未部署、安装、reload、重启或访问正式 VPN。仅受控 loopback TCP/UDP、临时 Unix socket 和临时磁盘目录。无 commit、无缓存/历史文件清理。完成时磁盘约 5.7GB 可用。

已修复：
- `OpenTrafficLease` gofmt、停止/失败 writer 拒绝新 lease、namespace lock inode/path 回查；读取同时要求 namespace writer 与 exact-instance `traffic.lock` 持锁。
- Reporter 发布失败退出会释放 lease；Stop 立即原子取走并关闭 lease，即使后台文件 I/O 尚未返回也不可继续展示为当前实例。退出顺序保证释放 lease 后才 close(done)。
- 采样不跨 STARTING/UNAVAILABLE 生成 running rate/分钟历史，恢复首样本 rate=null；codec 要求 rate.end_ns=elapsed_ns，OBSERVED 禁止 saturated，所有 canonical decimal/递归字段检查复用 records codec。
- helper 完整校验 header（含 previous_binding）、registration 复查、实例绑定/新鲜度、旧 helper/过大帧/取消 fail closed。
- `getTraffic` 使用父新增的 `w.trafficRequest` seam，nil 时真实 `controlHelperTrafficRequest`；handler 认证/同源/无查询/错误/过期/撤销认证负例已覆盖。

## 真实执行证据

目录 `/home/hermeswebui/.hermes/cache/scratch/r10-traffic-finish-20261104T130858Z/`，历史失败原样保留。

| 日志 | 实际结果 |
| --- | --- |
| `red.log` | 两个新回归预期失败：首个 RUNNING 错算启动区间；rate.end_ns 非当前样本仍接受 |
| `lease-red.log` | 测试夹具误等 StopAdmission worker 退出导致 timeout；已修正夹具，保留失败 |
| `lease-red-2.log` | 停止 writer 可开 lease 的真实 RED；路径替换夹具导致 shutdown 验证失败，已恢复路径后收尾 |
| `components.log` | `internal/trafficstats` + `internal/connectionrecords` 全包 PASS；71 顶层 + 223 子测试，package ok；SHA256 `00515d2379f5623955f493b491040283a914b9fd485de93943e4d208987f5542` |
| `engine.log` | wrapper 参数顺序错误，ENGINE_EXIT=2；不是测试通过 |
| `engine-2.log` | 两顶层 PASS：真实 TCP/UDP exact payload + native unwrap + Flow/close；真实 Box loaded/cancel；package ok；SHA256 `d0a97c7d9cbc6904f1bd64c17ee209e71fa720f9cc1c4341f0351b8f79d0f25a` |
| `root-targeted.log` | 编译发生在 test imports 与测试体写入之间，unused imports，END.rc1；不是通过 |
| `root-targeted-2.log` | 6 顶层 + 23 子测试 PASS，真实 Unix IPC/旧 helper/取消、lease Stop、HTTP handler 正负例；package ok，外层实际 exit0；SHA256 `f911beaa79e62525ee80a372f683341500e62e91b0c4c6c60be293605804f66f` |

engine/root 均使用指定 Go1.27.3、`python3 scripts/go-patched.py --go PATH test -p 1 -tags with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core -run '^TestTraffic' -count 1 -v PACKAGE`。flags 必须在 package 前；GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOFLAGS='' GOMAXPROCS=2。最终 targeted root 命令显式 exit 实际 rc。

注意：root-targeted-2 PASS 后仅调整 `traffic_runtime.go` 两条 defer 的先后顺序（先 releaseLease 后 done）；该最终源码由父冻结后统一回归，不能将之前局部 PASS 当作最终冻结 SHA 的完整验收。

## 父接线与精确 DTO / units

真实接口由父接 `GET /api/v1/traffic`，不要使用陈旧 `/api/traffic`。authenticated ServeHTTP 外层仍由父负责；本 worker 只测 handler，不宣称已验证完整路由/浏览器。

- 成功 HTTP 200 `{traffic_schema:1, availability:"OBSERVED", snapshot:{...}}`；不可观测 HTTP 503 `{traffic_schema:1, availability:"UNAVAILABLE", snapshot:null}`；no-store。认证/同源/查询错误各走原有 401/403/400。
- `snapshot.source="SDK_ROUTED_PAYLOAD"`；仅 ROUTED tracker 可见 payload，不是 NIC/wire/全设备/被拒绝或 DNS 总流量；记录条数不是 bytes。
- `upload_bytes` / `download_bytes`：累计 payload **bytes**，canonical uint64 十进制**字符串**，JS 不得先转 Number 丢失 >2^53 精度。
- `elapsed_ns`：本实例单调 elapsed **nanoseconds** 字符串；`sampled_at` UTC RFC3339Nano 只用于显示/新鲜度，不做 rate 分母。
- `rate`：null 或 `{start_ns,end_ns,upload_bytes,download_bytes}`；这里 bytes 是该实际区间**增量**，不是已算 B/s。B/s = delta_bytes × 1e9 / (end_ns-start_ns)，bits/s 再 ×8；首个 RUNNING、恢复首样本、非运行/饱和均 null。rate.end_ns 必须等于 elapsed_ns。
- `history`：同样 interval DTO 的数组；实际完成分钟区间，最多 1440，最多实际单调跨度24h；不插值、不补零、不跨实例相减。
- `header`：schema_version、config_identity、instance_id、generation、manifest_id、runtime_sha256、created_at、previous_binding；用于实例绑定，不把旧实例 latest 当当前状态。

原生 SDK 已读：sing v0.9.7 counter_conn/packet_conn 原生 read=upload/write=download，保持 unwrap/vectorised/batch/read-waiter；sing-box v1.14.3 ZIP `common/trafficcontrol/tracker.go` Flow forward=Upload/reverse=Download。未改 SDK 缓存。

## 未闭合验收门

1. 父冻结所有 writer 后统一 root full（包含最后 defer 次序）；父真实 authenticated ServeHTTP `/api/v1/traffic` 与浏览器 DTO/units 消费验证。
2. macOS 原生 peer UID、固定 root 路径/权限和已安装 helper 只能原生验收，Linux 替身不代验。
3. 当前已运行旧核心/旧 helper 一律 UNAVAILABLE。必须未来用户明确授权的**新启动**、root registration + staged config + compiled manifest 绑定成功后才可观测；本轮绝不为取流量安装或 reload。
