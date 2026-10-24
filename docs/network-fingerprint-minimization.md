# 网络指纹最小化候选

本候选只处理客户端未指定 `client-fingerprint` 时的默认 TLS 握手。目标是减少默认 Go TLS ClientHello 的明显差异，不承诺“清除全部 sing-box 特征”、不可识别、绕过任何具体检测系统，或与真实 Chrome 完全一致。

## 当前已确认的事实

- 内嵌 sing-box v1.14.3 的 AnyTLS outbound 会把 Settings 中的 `client=` 改写为配置 `client_metadata`；应用未设置该项，因此默认值为空。没有证据表明线上默认发送 `sing-box/版本号`。这是源码结论，实际对端观察以独立测试为准。
- 既有程序只在节点配置显式 `client-fingerprint` 时启用 uTLS；空值原先使用 Go 标准 TLS。
- TLS 握手、对端解密可见的 AnyTLS Settings、加密后的包长／方向／时序，是不同观察面。客户端协议标签、本地日志和二进制构建信息不是线上 ClientHello 字段。

## 最小变更

| 节点 `client-fingerprint` | 候选行为 |
|---|---|
| 未填写或空值 | 使用现有固定依赖的 `chrome` uTLS |
| `chrome`、`firefox`、`safari` 等已有有效值 | 保持显式选择 |
| `golang` | 明确使用 Go 标准 TLS，作为兼容回退 |
| 其他不支持值 | 保持依赖的明确拒绝，不自动改成可用值 |

改变的是运行时编译默认值，不重写现有 YAML，不保存选择，也不自动重连 VPN。默认 uTLS 依赖构建包含 `with_utls`；缺失时应拒绝，不能静默降级。

CA、SPKI 固定公钥和已有跳过校验授权策略保持原样。uTLS 模拟 ClientHello 不能替代证书／公钥认证。

## 明确不做

- 不删除版权、许可证、源码来源或本地诊断身份。
- 不添加伪造的浏览器／引擎版本，不自行修改 SDK 私有反射逻辑。
- 不盲目随机指纹、TCP/TLS 分片、延时或填充，不把“更多随机”当作一定更难识别。
- 不为 AnyTLS 伪造 HTTP 业务，不把 ALPN 声明当作实际实现 HTTP/2。记录测试实际观察的 ALPN，仅称该 TLS 预设的行为。
- 不自动改服务端证书、SNI、监听端口、填充协商或空闲会话策略。

## 验收和交付边界

相同新增行为测试绑定冻结旧源码取得真实 RED，再验证候选 GREEN；完整 suite/vet/build 与缺 uTLS 拒绝分开记录。通过自有 TLS 对端观察真实 ClientHello、实际 AnyTLS Settings 和回显，并保留错误身份零目标载荷检查。Mac 原生在独立回环端口执行，不碰现有 VPN。

这是尚未发布的候选功能说明，不代表已安装程序默认值发生改变。正式发布及生产替换需要单独记录；没有效果测量，不报告识别率下降百分比。
