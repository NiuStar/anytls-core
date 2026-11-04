# R10 metrics contract（后端/前端接线检查点）

## 本轮实现决定

仅实现常驻 WebUI 进程固定 HTTPS 检查与有限历史；**VPN 字节流量未实现，所有流量字段 null + NOT_OBSERVED**。不把 ROUTED 条数、网卡总量、探测传输量当 VPN 流量。

源码审计：sing-box v1.14.3 `common/trafficcontrol/{manager,tracker}.go` 的 Manager 可统计 tracker-visible TCP/UDP/flow，复用 sing bufio counter 的 UnwrapReader/Writer、vectorised/batch/read-waiter 接口而非自行包 Read/Write。`box.go:243` 仅在 Clash/API/PlatformLogWriter 条件下自动注册。当前 engine 用 bare box.New、recordsTracker 原样返回 conn/nil flow，现有 helper 仅接受路由记录与绑定的 DNS 证据，没有可读取的实例绑定 byte snapshot。不能给 WebUI 新建 Box 的流量冒充现有正式 VPN，也不能启用 Clash/API/日志副作用来拿统计。本轮不改 engine/helper 权限或协议；后续 byte 采集需单独实现受验证实例绑定的 SDK Manager 生命周期与有界 IPC。

## owner 接线（webui.go 归后端 owner，不由 telemetry worker 修改）

- webConsole 增加 `metrics *webMetricsController`。
- webuiCommand 中完成 managed identity 验证后、开始 serve 前执行 `w.metrics = startWebMetrics(context.Background(), w.configPath)`，并 `defer w.metrics.Stop()`。
- 已认证 ServeHTTP 分支（与 connections 相同，mutation CSRF 前）增加 `/api/v1/metrics`；调用 `w.metrics.get(w,rw,r)`（nil receiver 安全；方法内仅 GET，其余 405）。不增加匿名/跨源路由。
- `startWebMetrics` 不在 newWebConsole 自动调用，避免测试 constructor 或临时 console 启动外网探测。浏览器打开/关闭不改变采集生命周期。
- 持久化固定为配置同目录 `webui-metrics.json`；私有 0600，有界原子快照。不读写 root/helper 路径；启动错误仅反映 telemetry 状态，不影响 WebUI/VPN。

## GET /api/v1/metrics schema_version=1

要求正常会话和 Host，并要求 `X-AnyTLS-Origin: http://<Host>` + `Sec-Fetch-Site: same-origin`（network listener 兼容缺 Fetch Metadata）；可选 Origin 如存在也必须精确同源。拒绝任何 query（不支持 caller 指定 URL/path/interval）。`Cache-Control: no-store`。

固定响应字段：

- `schema_version:1`, `generated_at` RFC3339Nano UTC。
- `traffic`: `quality:"NOT_OBSERVED"`, `scope:"VPN_TRACKER_NOT_CONNECTED"`, `download_bps:null`, `upload_bps:null`, `recorded_download_bytes:null`, `recorded_upload_bytes:null`, `recorded_seconds:0`。byte 总量未来使用十进制字符串。
- `network`: `scope:"WEBUI_SYSTEM_PATH_HTTPS"`, `target:"https://www.gstatic.com/generate_204"`, `interval_seconds:60`, `timeout_seconds:8`, `quality:"NOT_OBSERVED"|"PARTIAL"`, `state:"NOT_OBSERVED"|"OK"|"FAILED"|"STALE"`, `latest_checked_at:null|string`, `latency_ms:null|number`, `latest_error:null|"HTTPS_FAILED"|"TIMEOUT"`, `attempts`（仅近24h实际完成次数）, `succeeded`, `sample_success_ratio:null|number`（0..1，实际完成为分母）, `availability_24h:null`（永不冒称全日SLA）, `observed_probe_seconds`（近24h真实探测执行区间并集时长，不把一分钟点样本涂成一分钟在线）, `history_status:"MEMORY_ONLY"|"OK"|"UNAVAILABLE"`。
- `window`: `start`, `end`，精确滚动24h；`bins` 恰好288个连续5分钟区间，每个 `{start,end,attempts,succeeded,observed_probe_seconds,download_bytes:null,upload_bytes:null,traffic_quality:"NOT_OBSERVED"}`。无检查区间 attempts=0，但流量始终 null。

最新结果超过128秒为 STALE，旧成功不保持“当前网络可用”。失败 latency=null，不用0填充。检查只证明此 WebUI 进程按系统路由到一个固定 HTTPS 204 端点的本次结果；不证明 VPN 正在运行、所选节点、所有网站或全天可用。采样串行、每分钟一次、8秒网络上限，无重试无重定向无环境代理，标准CA严格TLS，最多1441条历史、文件512KiB。停止/崩溃期间不补样本。

## r2：M1–M3 修订契约

- HTTP `schema_version` 仍为 **1**，不改既有字段类型；新增 `network.clock_status:"OK"|"DISCONTINUITY"`。`history_status` 增加 `PENDING`（最新内存尚未落盘）与 `STOP_TIMEOUT`（关闭期限到期，OS IO 未证明退出），不将排队或超时说成已持久化。
- `Record` 仅修改有界内存并通知容量1的合并队列；单writer复制最多1441条后在锁外 marshal/write/fsync/rename/fsync-directory。GET只复制内存，sampler取消不等待writer。`Store.Close(ctx)` 停止接收新记录并尝试flush，超时返回context错误，writer可在不可中断系统调用返回后自行收尾。controller `Stop() error` 统一1秒取消/join/flush预算，幂等保留首次错误；**超时不是已join全部worker，也不承诺该次内存样本已落盘**。现有defer调用可忽略返回值，状态仍为STOP_TIMEOUT。
- 启动历史load仍是同步有界字节读取；本修订不承诺构造函数对故障文件系统有墙钟上限。运行后读快照与停止没有文件IO锁耦合；不能把1秒停止预算说成OS IO可被强杀。
- 父路径使用逐组件 `O_DIRECTORY|O_NOFOLLOW` + 相对fd `openat`；最终app目录必须为当前euid且无group/other写权限。祖先必须root/当前euid所有，无group/other写权限，明确允许sticky共享祖先（如/tmp）但最终目录不豁免。祖先symlink一律拒绝（包括某些平台常见的`/var`或`/tmp`别名；此时UNAVAILABLE，不自动解析为另一个路径）。不修改目录mode/owner。已打开目录fd固定身份；即使pathname被换成symlink也不把后续保存重定向到外部；temp/open/rename/unlink均相对此fd。每次保存再检查已固定目录权限。
- 文件保持0600、原子替换和512KiB限制；新增磁盘 **history schema_version=2**，保存每样本 `elapsed_ns` 与 `clock_unknown`。读取v1以已验证正常wall interval迁移elapsed；v2严格校验elapsed范围及非unknown行的wall一致性。旧版本程序对v2会UNAVAILABLE，不悄悄按v1重释。
- 在剥离monotonic之前只计算一次elapsed；成功latency只取elapsed，失败仍null。探测内部或前后发生wall/monotonic不一致、重开后顺序倒退时保留真实outcome，标记DISCONTINUITY；unknown行不计入wall coverage（字段0表示可定位覆盖下界，不证明没有执行），completion/bin按实际end墙钟放置，未来end在追平前不入窗口，绝不重写到假时间或用墙钟膨胀latency。所有合法且非unknown的wall区间先按起点排序求并集，再裁切到窗口及各bin；回拨后重叠区间（包括持久化重启后）不重复计coverage，outcome计数不去重。正常序列仍精确裁切覆盖。无法仅从v1或重启后的无monotonic时间恢复历史真实时钟变动，不能承诺完整检测。窗口成功率仍是已纳入窗口的真实完成分母，不是全天SLA。

前端：用 `network.state/latency_ms` 呈现最近检查；比率文案必须是“已记录检查通过率”，不能叫全天可用率。流量卡/曲线维持未记录；图中 gap 不插值。不再以 service running 推断网络可用。
