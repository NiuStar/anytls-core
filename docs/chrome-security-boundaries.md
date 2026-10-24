# Chrome 相似度与 TLS 安全边界

## 已完成的真实对照

在 Mac 上使用独立临时 Chrome profile、无代理的自有数字回环 TLS 收集器，对默认候选、显式 Chrome、显式 Go 和实际 Chrome 各取三次首个 ClientHello，共十二份。收集器只读 ClientHello 后关闭，不提供认证服务、不收用户凭据，不访问真实节点，不读取用户浏览器 profile。

安装 Chrome：156.0.8078.47。固定依赖：github.com/metacubex/utls v1.8.7，其 HelloChrome_Auto 实际为 Chrome133 预设。

- 默认候选与实际 Chrome 的非 GREASE 密码套件顺序相同；两者 ALPN offers 均为 h2/http1.1，已观察的密钥交换组／key_share 形状相近。
- 实际 Chrome 多扩展51764，归一化 GREASE 后的签名算法列表还多2308、2309、2310；握手长度不同。原始样本中的2570是GREASE样值，不计固定差异；GREASE值与扩展顺序本来可变化，不能把一次随机值差当固定差异。
- 因此没有“与当前 Chrome 一致”的验收结论，更没有被动／主动检测不可区分或识别率下降的测量。

此处只是首轮 TLS ClientHello 对照，不覆盖 HRR、会话恢复、证书压缩实际路径、HTTP/2 SETTINGS／流控／优先级、QUIC、TLS记录分片、包长／时间序列、连接池或服务器响应。AnyTLS TLS后承载的不是浏览器HTTP业务，不能通过填写ALPN把它变成HTTP/2。

## 识别不等于破解

流量分析可用于分类、关联或阻断，但看到握手指纹不会自动取得TLS会话密钥。TLS安全依赖实际协议实现、协商算法、服务端身份、公钥／证书信任、私钥和终端保护。浏览器样式不替代这些条件，也不能抵御已控制终端／私钥泄漏。

现有公网IP订阅采用pin-only身份，不提供公共CA／主机名／有效期验证；强密码、私密链接、配置0600和可信首次交付仍必要。`skip-cert-verify: true`不提供相同服务器身份保证；本轮不擅自改写已有节点，但不能将其作为“安全已增强”的正控。

## 有界加固候选

新增可选 `tls-min-version`，精确允许1.2或1.3，默认1.2；非法版本与转换坏字段失败关闭，不去掉字段后继续连接。TLS1.3-only是安全取舍，可能拒绝仅支持1.2的服务器，且不等同Chrome默认行为，因为实际Chrome也提供1.2。

关键执行门是**真实握手与零应用载荷**，不是JSON字段存在。Mac 实测已确认：默认 Chrome/uTLS 忽略 `min_version: 1.3`，仍与 TLS1.2-only 端点完成认证回显。因此最终候选只允许 `client-fingerprint: golang` 搭配 `tls-min-version: "1.3"`；默认或显式 uTLS 与1.3组合在连接前拒绝，不改用其他模式、不自动降级。原失败证据保留。

```yaml
client-fingerprint: golang
tls-min-version: "1.3"
```

这条配置偏向实际可执行的版本限制，不追求 Chrome 握手外观。若选择 Chrome 风格预设，应接受当前支持TLS1.2/1.3的兼容行为；不能同时声称可靠TLS1.3-only。任意显式旧指纹的最低版本也不能仅凭配置字段推断，需要单独握手验收。

没有盲目修改TLS扩展、上游加密实现、依赖版本、分片、填充或时序；这些变化可能形成新特征或损害兼容性，不能靠猜测追赶Chrome。
