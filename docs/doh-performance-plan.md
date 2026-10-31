# 可信DoH性能与故障恢复：第一批合同

基线20136d15820fb9cc6b25f3c4e986929b97c4dabe（公开03）。新repo/workspace/anytls-doh-performance branchperf/doh-observability。用户要求按推荐顺序快速推进；批准隔离开发/真实验证，不代表安装、切换、启停正式VPN或发布。

## 本批交付

1. 从锁定SDK与实际wrapper编译链核验缓存、同问题并发合并、DoH连接复用/关闭/超时/恢复。既有机制先测，不包装为新优化。
2. 真实AnyTLS→严格HTTPS DNS回环测请求计数、A/AAAA隔离、TTL和负缓存、并发同问题、连接复用/断连恢复。保持生成detour/final/捕获规则；endpoint/入站/TLS材料仅测试替换。失败关闭/明文trap有正控制；明确普通用户direct53 observer限制。不把测试mixed当Darwin TUN。
3. 固定低基数、O(1)、无完整域名/原始错误/凭据/目标地址的聚合指标。组件通过不是生产集成完成；必须接真实SDK边界并验证启用/停用等价与开销后才可交付运行观测。SDK不可观察缓存命中时显示UNAVAILABLE，不用请求减上游数猜cachehit/coalesced。
4. 只修实际证实的延迟/恢复问题；没有证据不加第二层缓存、不重复singleflight、不改TTL、不默认过期答复。

## 不变边界

- 统一DoH严格SNI/CA、固定IP引导、基础选中AnyTLS detour；不暗退本地明文、不多供应商默认竞速。
- 保A/AAAA，不以丢AAAA或全局禁IPv6代替Google现场问题诊断。内网splitDNS须显式策略且单独授权，默认不增加。
- 本批默认先单上游实测。备用上游只有明确可验证需求及配置合同、总deadline、有限切换和无明文fallback时另批实现。
- 临时路径短且私有，无sudo/正式TUN/LaunchAgent/config/password/systemDNS/proxy变化；所有ownedchildren/listener/engine join核实。原故障原件留存；模型timeout/工具返回0不能代业务通过。

## 验收及速度纪律

- 三路并行：SDK精确接入点审计、真实基线协议、独立固定聚合组件。各自只提交own paths，产品改动commit前后冻结。
- 缓存/复用基线已GREEN即诚实记录，不强造RED；新增行为TDD业务RED→GREEN，不以缺symbol编译错误当RED。
- 优先小而完整可执行切片，不为了完备指标大改SDK/认证patch链；能用导出transport wrapper则先做真实可见上游指标，缓存内部不可见则明确分层限制。
- 确定最终接入后统一full native/vet/build/独立审查，必要真实协议和测量重绑定；未完成门不称修复/提速。发布/目标机现场测试分列。
