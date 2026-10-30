# 统一可信DoH接管：实施与验收方案

## 范围和授权

基线`38da7b463420828ec467cca630e843e391d8d306`；隔离目录`/workspace/anytls-unified-doh-fix`，分支`fix/unified-doh-capture`。用户批准按统一DoH路线推进，不含公开发行、安装、root助手更新、正式配置或VPN停启。开发Mac只作普通用户私有回环测试；不操作172.16.51.184现场。

现场事实：v2026-10-28-01在utun10运行，系统解析目标返回异常A/AAAA，可信DoH返回Cloudflare地址，固定该地址可严格TLS访问；路由记录选节点、目标trace看到HK出口。尚未读取现场实际runtime，不能把源码条件缺口直接断言为现场唯一根因，缓存和排除路由仍需现场验收。

## 产品合同

- TUN覆盖范围内的普通UDP/TCP53查询独立于用户规则和DIRECT/MATCH结果，优先进入统一可信DoH处理；A/AAAA保留完整支持，不通过禁IPv6规避问题。
- DoH沿用固定IP1.1.1.1、SNI cloudflare-dns.com、严格证书验证，通过选定的基础AnyTLS出站anytls-out，不依赖本地DNS引导。该基础节点不一定等于某条业务规则选择的另一节点，文档明确。
- DoH不可用、错误证书、代理认证失败应查询失败而不是转本地明文DNS；只有一个配置的可信DoH时明确报错，不凭空添加备用服务或TLS insecure。框架注册local transport为兼容非TUN无DNS调用不等于TUN可回退，不能草率删除注册破旧API。
- 可信解析不改变业务流量的直连/代理分流；保持原用户规则顺序、原始source_index、source_id、配置/选择/CA绑定和合成规则与SDK一一对应。
- 开启/关闭/启动回滚继承原DNS/路由快照恢复及停止可恢复机制，不增加networksetup/killall或清缓存特权动作。不放松恢复失败警告，不引新stop/start死循环。
- 普通proxy/mixed模式历史上可无DNS且node允许域名，本片不强制改它的启动引导。测试用显式DNS/mixed夹具验证协议路径，不冒充系统TUN实测。
- 缓存中已有错误答案、应用自带DoH/DoT、VPN排除地址/接口不在普通53接管保证内；不能承诺开启后所有应用即刻没有DNS干扰。内网私有域默认不静默回退本地，若需splitDNS须另列显式可信策略与验收。

## 步骤

1. 静态根因核对：SDK dns_mode在Darwin真实行为、protocol嗅探和port53优先级、DoH detour/解析/fallback，绑定实际源码SHA；启停恢复影响只读审查。
2. 测试先行：已有真实compiler入口，普通DOMAIN/MATCH、无用户rules、DIRECT53、GEOIP no-resolve、RULE-SET配置验证TUN统一策略；SDK构造与manifest绑定；原版业务RED后最小实现。
3. 真协议测试：独立回环可信HTTPS DNS服务，经真实AnyTLS detour而非直连替身；UDP/TCP53和A/AAAA请求/回答、querycounter与身份/SNI；本地plaintext陷阱无请求；DoH拒绝/坏证书/上游断连无明文回退，保业务direct规则。只监听测试-owned回环端口，不触正式TUN。
4. 集成：原生format/full/vet/build/version/buildinfo，记录归属、严格TLS及启停恢复回归；独立复核精确冻结候选。旧夹具预期规则数/索引如受合成规则变化影响，须证明旧逻辑期待与新增合同矛盾再最小迁移，不以编译失败冒充业务RED。
5. 现场验收单：发布/安装获授权后才在目标机验证TUN DNS UDP/TCP、A/AAAA、DoH失败关闭、系统缓存与应用行为、stop/rollback恢复。此门未跑明确未覆盖，不以mixed回环或HTTP200替代。

## 完成条件

隔离候选需编译合同RED/GREEN、真实DoH协议和失败无明文回退、manifest/安全/恢复全套、独立审查及产物SHA。正式部署/目标TUN和用户验收独立列出；任何未验证指标保留UNKNOWN/NOT_RUN。证据根`/workspace/anytls-unified-doh-evidence`，旧失败不可覆盖。
