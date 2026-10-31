# DoH 恢复与尾延迟调优合同

基线：已发布 `v2026-10-31-01`，commit `19a275d49f7f58aed25a444f5e9a91733970a145`。本轮隔离分支 `perf/doh-recovery-measurements`；实现目录 `/workspace/anytls-doh-recovery-optimization`；证据目录 `/workspace/anytls-doh-recovery-evidence`。

## 本轮顺序

1. 对现有开发Mac只读核查已授权节点配置、选中项、严格TLS/CA/pin可用性及当前网络状态；不导出配置/订阅/密码/完整端点。没有合格材料不猜凭据或选择新节点。
2. 真实AnyTLS→DoH受控协议：同HTTP/2连接一个请求超时对另一在途请求的影响；主动EOF/半断开后的同engine恢复；A/AAAA一路阻塞时另一路结果；分开测缓存命中、已复用连接未命中及冷查询。
3. 保留基线失败或GREEN。只有复现出可靠异常，才提交一项最小修复及同输入同测试新旧对照。若问题需改SDK/认证补丁链，先明确精确修改面，不绕开wrapper或直接修改modcache。
4. 有合格真实节点材料后再做独立loopback采样：固定节点及严格DoH，分开cold/warm；样本量、失败数、尾延迟按实际记录统计。受控回环不代表WAN；当前TUN物理路径不确定时必须标明，curl --noproxy不能当绕TUN。
5. 真正修复后冻结候选，原生full/vet/build、协议和失败关闭门、独立审查；发布与目标机安装另列，不自动切正式VPN。

## 优先检验的假设（非已确诊）

- H1：单请求deadline触发SDK全池Reset，可能连带中止共享连接的健康在途请求。预测：两请求独立context、共享真实TLS连接，A超时后B在自身deadline前被取消/EOF；解除故障后新查询可恢复。需server connection ID及回调/handler事件共同证实。
- H2：半断开/主动EOF后连接回收或重新建连产生可复现长尾。预测：同engine后继cache-miss出现异常等待或失败，不能用重启engine消除现场。
- H3：地址族一路失败影响另一正常解析。预测：同时A/AAAA中健康侧在阻塞侧未完成时无法独立返回。不得禁AAAA掩盖。

优先测试便于否证的H1和H3，再扩主动EOF。正常SDK默认10s预算不为加快测试偷偷缩短生产配置；独立调用context不同预算只用于明确归因的测试。

## 不变边界与验收

- 单可信上游、严格TLS/SNI/CA、固定IP引导、基础AnyTLS detour、TUN端口53前缀均不改；不默认备用、不加通用重试、不改TTL、不返回stale、不全局禁IPv6。
- 观测默认关闭，生产缓存/合并/hijacked/http_status继续NOT_OBSERVED；不凭request减upstream推算。
- 测试需真实请求/应答ID/内容、确定连接身份、受控故障触发及恢复、owned caller/handler/engine join、连接关闭和listener重绑。只有超时报错不算资源关闭成功。
- 同条件新旧对照，响应正确、失败率、恢复时间和耗时分布分列。无异常不称修复或提速，诊断开销优化优先级低于网络恢复。
- native官方wrapper Go1.27.3/canonical tags/CGO0/p2/GOMAX2，私有短root/UID501，源码和依赖精确SHA、生产before/after/fresh；durable尝试journal、共享锁、禁止不确定任务重放。
- 原失败不覆盖，stderr/证据不公开秘密。所有正式helper、LaunchAgent、系统DNS/代理、TUN/VPN配置及运行状态保持不动。
