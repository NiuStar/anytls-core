# TLS 版本策略候选：实际验收结果

状态：隔离候选，未发布、未安装、未切换生产 VPN。目标不是保证流量不可识别或加密不可破解。

## 发现和修正

实际比较默认uTLS与安装Chrome156的十二份首ClientHello：固定依赖仍是Chrome133预设；归一化GREASE后，Chrome156多扩展51764及签名算法2308/2309/2310。密码套件顺序和ALPN offers相同不代表完整浏览器一致，后续HTTP/2、QUIC、记录和时序未证明相同。

初版配置只传递min_version1.3。真实测试发现Chrome/uTLS仍与TLS1.2-only对端完成认证回显，CA和SPKI两个用例失败。保留原始失败，不将字段存在当执行有效。

最终候选拒绝无法可靠执行的组合：

| 配置 | 候选行为 |
|---|---|
| 未指定最低版本 | 默认运行时1.2，保持既有Chrome风格候选 |
| tls-min-version: "1.2" | 保持兼容行为，不声称任意旧uTLS指纹均有可靠版本下限 |
| tls-min-version: "1.3" 且 client-fingerprint: golang | 使用标准Go TLS执行1.3-only |
| tls-min-version: "1.3" 配合默认／Chrome／其他uTLS指纹 | 在证书文件读取和引擎构造前明确拒绝，不改指纹、不重试降级 |
| 非法版本／转换器显式空、null、非字符串字段 | 拒绝；转换移除整个坏节点并清引用，不只去掉安全策略 |

## 实际验证

- 冻结初版与最终版运行相同新政策测试：初版3主／156子业务失败，最终通过，不能用编译失败冒充RED。
- Mac Go1.26.8最终全套：413主、1107子PASS，3SKIP；vet、build通过；无uTLS定向9主／311子PASS。
- Go TLS1.3-only的CA和SPKI正控实际协商TLS1.3并完成64字节认证回显。
- Go TLS1.3-only与TLS1.2-only对端连接时，服务器观察到协议版本拒绝；错误SPKI有实际证书拒绝alert。均不是超时，解密应用字节和目标业务字节为零。
- 默认Chrome＋1.3在构造前拒绝，无引擎运行；不把测试中名称含tls13_echo的预连接拒绝分支误计成Chrome实际TLS1.3成功。
- Chrome默认兼容正控分别在CA/SPKI下与TLS1.2、TLS1.3端点完成认证回显，只证明兼容。
- Python安装器和wrapper回归通过。独立SPECv2与QUALITYv2通过，父任务重算源码／测试／日志SHA并新鲜读回候选程序；前后生产进程、配置、密码、DNS/proxy和冻结源码不变。

## 候选身份和限制

路径：`/Users/lihaiyan/anytls-tls-policy-v2-20261024/tls-policy-candidate`

SHA-256：`f5d25258676dd571b84df428eadf3efcd695955d5b550132f8400f975fa6db7a`

未升VERSION；其版本输出不代表这是正式发行程序，须按SHA区分。main与正式Release未改变，没有生产安装或授权切换。本轮没有修改SDK、加密实现、依赖锁、证书、公钥、密码、分片、填充或时序。

指纹识别不等于TLS解密；TLS版本策略也不增强弱密码在验证材料泄漏后的抗猜测能力，不防已攻陷终端、私钥或订阅链接泄漏。正常经正确认证的被动TLS抓包并不因此暴露密码验证材料。

原始证据、保留的失败和归一化对照：`artifacts/chrome-security-v1/`。边界说明：[Chrome与安全](chrome-security-boundaries.md)。
