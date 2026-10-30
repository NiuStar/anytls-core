# WebUI静态传输优化合同

基线f683892b04b3e8a61813f59c0a10ad16f87864d4（公开02）。独立repo/workspace/anytls-webui-transfer-optimization；本轮开发/验证，不公开发布、不安装/启停目标机或VPN/helper。

## 已测机会

Python gzip仅可行性测量：index26161→8728B，app97045→29776B，startup20220→7110B，CSS26237→6220B；总169663→51834B。不是已交付HTTP测量，也不代表整机启动/延迟/程序体积收益。

## 范围

- 固定四个embedded公开静态资源，单次生成immutable identity+gzip表示并并发复用，避免每请求ReadFile复制/压缩。仅标准库，不引入依赖、磁盘缓存、第三方构建资源或动态压缩API。
- 只在Accept-Encoding明确允许gzip时选择；正确处理多字段/大小写/q=0/wildcard/identity/不支持情况。Vary: Accept-Encoding；Content-Encoding、Content-Length、原MIME一致。不得对禁止gzip者发送gzip；全部支持表示均拒绝时406且保安全头。
- 现有Cache-Control:no-store、Host/Origin/CSRF/auth、安全响应头、GET-only和固定路径allowlist保持；不新增浏览器长期缓存/ETag/304。API JSON/错误不压缩；不引入敏感响应压缩侧道。
- gzip解压后必须与确切embedded原字节及SHA一致，包括安装不可取消及bootout警告、JS/CSS；不得剔除许可/业务功能或改API。
- 业务测试先同字节baseline RED→候选GREEN，拒绝编译错误冒充RED。identity兼容已有tests；并发/多头/拒绝/错误路径覆盖。

## 验收

1. 精确源码、测试与基线冻结，官方Macwrapperfocused native RED/GREEN。
2. 同测试/请求基线候选真实HTTP读回：body原字节/gzip解压、安全头与不支持编码/Host拒绝/API不压缩。
3. 交错静态请求/handler基准（bytes/request/Bop/allocs/time），机制证明仅一次表示构建；冷启动/额外常驻内存成本单列，不把累计分配当RSS。
4. clean候选完整Mac test/vet/build，独立代码审查与浏览器真实页面验收；失败保留，修改后旧受影响审查失效重跑。最终报告只承诺已测范围。

所有工作局限隔离目录/loopback端口；原正式端口、凭据配置、LaunchAgent、DNS/proxy/routes和VPN状态保持。发布另授权。
