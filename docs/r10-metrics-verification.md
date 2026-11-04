# R10 telemetry 验证状态

## r2 M1–M3 修订（当前结果，旧r1 HOLD原件未改）

证据目录：`/workspace/anytls-r10-product-review/metrics-r2`；独占scratch：`$TMPDIR/r10-metrics-r2`。不改webui.go、frontend或traffic，不提交共享index，不接触生产/SSH/外网。

- **RED先行**：原审查父目录/单调时间负例在冻结旧代码新副本复跑，`red-parent-clock.log` rc=1。旧M1完整fsync证据保留在metrics-r1；本轮另用旧/新controller原文+对应Store副本，在自有合成child暂停真实fsync syscall entry 1.7秒。最终 `red-controller-real-fsync-final.log` rc=1，同时报告Snapshot被IO阻塞与controller Stop无界；`green-controller-real-fsync-final.log` rc=0，Snapshot在100ms预算内返回，controller在1.2s预算内返回并明确STOP_TIMEOUT。没有改主机时钟、系统磁盘、网络或生产进程。
- **组件**：原9顶层测试保留，仅持久化断言增加显式Close/flush以适应异步合同；新增6顶层回归：慢IO/read/sampler/Close、父目录symlink/group-other写/owner谓词、wall ±1s与重开、目录替换fd固定、两probe间rollback失败不丢、v1迁移/v2非法elapsed。旧审查3顶层负例必要适配（keyed struct、异步flush、拒绝父symlink后允许无落盘）也通过。冻结组件 **18顶层 ×5=90 PASS，0 FAIL**；Linux旧ptrace测试入口×5 SKIP（须旧driver），不把SKIP算PASS；本轮新真实fsync controller独立回归另计 **1 PASS + 1预期RED**。`component-verified.log`、`verified-test-counts.json`；`component-verified-vet.log` rc=0。
- **跨平台**：组件真实Go1.27.3交叉编译Darwin amd64/arm64均rc=0，复用现有x/sys v0.47.0，只在独立临时go.mod加本机replace，不改产品go.mod/go.sum/cache源码。`darwin-*-verified-compile.log`。不是native macOS运行验收。
- **失败尝试诚实保留**：`component-first.log`暴露原同步测试尚未flush与测试制造未来end后重开遭拒，修正夹具后通过；首次Darwin编译失败是旧Linux ptrace负例引用Gettid，加入Linux build constraint后交叉编译通过。首轮controller夹具只等待ctx，不能代表旧sampler阻塞，后续将Record置于同一worker并重跑；retry ptrace child提前退出导致driver超时，最终加release握手后得到上面明确RED/GREEN。初次日志均保留，不用它们替代最终证据。
- **控制器补充**：精确复制共享 `webMetricsController`/`Stop` 与新 `TestR10MetricsControllerStopBoundedAndReportsUnjoinedWorker` 到独占组件夹具（仅移除与该测试无关start/get导入依赖），真实执行1顶层PASS，`controller-unit.log`。最终共享组件15顶层×1全PASS，`shared-component-final.log`。这不是root HTTP集成验收。
- **未执行/父级门禁**：本worker不跑root Go，避免共享cache竞争。新增 `TestR10MetricsControllerStopBoundedAndReportsUnjoinedWorker` 与现有HTTP认证矩阵需父级用 `python3 scripts/go-patched.py --go <Go1.27.3> ... test -p 1 -tags with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core -run '^TestR10Metrics' .` 统一最终根回归。race/full/root vet/native macOS/正式helper/TUN均未由本轮组件PASS代替。
- **明确限制**：单writer被OS不可中断IO阻塞时不会凭空消失，Stop有界返回错误与STOP_TIMEOUT而非谎称join；最新异步内存可能未持久化。启动New同步load不在运行期Stop预算内。路径中的平台symlink别名被保守拒绝，进入UNAVAILABLE。HTTP schema仍1，磁盘schema2读取v1兼容；clock_status与history状态扩展见合同。VPN字节始终未实现。

以下是r1历史记录，不应当视为当前r2根集成或全产品批准。

## 已实现

- `internal/telemetry`：WebUI resident 固定 HTTPS 204 检查；单串行，无页面依赖、重试、代理、重定向，TLS >=1.2 标准 CA 验证；context 取消并等待 worker 退出。
- 近24h实际完成次数/成功分母、最近状态128秒失效、实际执行区间覆盖秒数、288个连续5分钟bin。未知流量恒 null，全天SLA恒 null。
- 固定配置目录普通用户 `webui-metrics.json`，0600，原子替换，最多1441样本/512KiB，拒绝 symlink/非regular/宽权限/错误owner/格式或目标错误/未来历史。历史是 WebUI 观测，不是 core/helper authority。
- `web_metrics.go`：独立 controller/start/Stop 与严格同源认证后 handler，拒绝全部 query；合同 `r10-metrics-contract.md` 定义后端 owner 三处接线，worker 未改共享 webui.go。

## 实际执行

真实工具链 `/home/hermeswebui/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.linux-amd64/bin/go`（`/workspace/toolchains/go/bin/go` 在模块内会 auto 切换，GOTOOLCHAIN=local 时其本体为go1.25.0，不能混称）。

- 9个组件测试通过，最终 `go test ./internal/telemetry -count=5` PASS；`go vet ./internal/telemetry` PASS。真实 loopback HTTPS 204、CA拒绝、302拒绝、环境代理无效、请求deadline、常驻采样/停止join/取消不计失败、持久化重开、错误叶类型、时间窗边界/精确分母/未知流量/快照隔离覆盖。
- 最初编译 skeleton 业务 RED：分母/coverage 与 empty-state 断言按预期失败；实现后GREEN。后加的边界/安全案例为test-after，不冒称全部TDD。
- HTTP全认证＋15项拒绝矩阵及真实HTTP listener 两个顶层测试，在 scratch 独立快照补入合同定义的 field/route 后通过。日志 `/home/hermeswebui/.hermes/cache/scratch/r10-metrics-http-snapshot.log`，真实 patched wrapper rc=0、root/cache 未变。快照 `/home/hermeswebui/.hermes/cache/scratch/r10-metrics-integrated-test`。
- 共享树最终 HTTP 重跑：等待 backend owner 三处接线，**NOT_RUN**；不能用独立快照替代最终接线验收。
- 普通 `go test .` 确认因现有 ACK SDK 扩展 undefined 编译失败；使用仓库 `scripts/go-patched.py` 与精确 Go1.27.3 后 targeted existing test PASS。没有改 go.mod/go.sum 或module cache。
- race：默认无cgo；尝试已有 zig cc 后 race runtime 链接 `__popcountdi2` 缺失，**NOT_RUN**。未安装系统工具；并发stress不冒充race。
- full/vet/build、macOS native、正式helper/TUN：本worker **NOT_RUN**。未SSH、未发外网业务探测、未修改外部DNS或正式VPN。

## 明确未实现

**VPN字节采集/当前速率/字节累计未实现**。不是SDK不可能计量：已审计sing-box Manager 与TCP/UDP counter unwrap/vectorised/batch/read-waiter。缺的是当前 bare Box到既有helper/WebUI的受验证实例绑定 snapshot生命周期与IPC；本轮不擅自启用API/日志/额外Box，不拿另一进程或网卡流量代替。
