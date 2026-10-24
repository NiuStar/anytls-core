# 公网 IP 私有订阅联动

目标：在 `NiuStar/anytls-go` Linux 服务端一键安装后，取得一条私有链接，在 `anytls-core` WebUI 的“HTTPS 订阅 → 从此订阅仅添加节点”中预览、确认添加。

## 使用边界

- 无需域名、ACME 或外部反向代理。默认 AnyTLS 端口 8443，订阅 HTTPS 端口 443；两者不能冲突，需服务端防火墙/云安全组放行。
- 默认经限时、可信 HTTPS 查询对外公网 IP；NAT、多网卡可用 `--public-ip` 显式指定。探测失败停止，不生成内网或猜测地址。
- 安装器保持已有密码、持久证书/私钥、订阅令牌。只有实际服务 TLS 身份和内容验证后，才向当前本地终端输出链接。
- 完整链接包含凭据和信任根，必须经可信私密渠道交付。不要发在公开仓库、日志、截图或工单中。
- 示例结构：`https://公网IP[:端口]/subscribe/私有令牌#anytls-cert-sha256=证书DER摘要`。不要手动把 DER 摘要填入节点的公钥摘要字段，两者算法输入和编码不同。

## 两次认证

1. **获取订阅前**：客户端按链接末尾的整张服务端叶证书 DER SHA-256（小写 hex）进行 TLS 握手校验，正确后才发送 HTTP 请求和访问令牌。链接末尾 fragment 不发给服务器。此路径不走 DNS、环境代理或跳转；只允许公网数字 IP。
2. **使用节点时**：订阅返回 `certificate-public-key-sha256`，内容是同一实际服务证书 DER-SPKI 的 SHA-256（标准 Base64）。内嵌引擎按此认证服务器公钥；标准 TLS 和 Chrome/uTLS 使用同一信任要求。

这里是明确的**固定证书/公钥信任**，不是公共 CA、主机名或有效期验证。配置中的 `skip-cert-verify: false` 不意味着引擎额外执行 PKIX；不得混用 CA 路径或 `skip-cert-verify: true`。证书更换需要重新分发新的完整链接，不能从未经验证的地址自动接受新指纹。

## WebUI 行为

- “仅添加节点”只追加通过验证的新 AnyTLS 节点；不导入来源规则、策略组或 provider。
- 保留旧节点、当前选择、策略组成员、规则顺序和已保存订阅文件；同名不同内容拒绝整次操作，相同节点重复导入不重复添加。
- 此链接不保存为后台刷新来源；这是从可重复使用的订阅端点进行一次添加，不承诺自动跟踪服务端变更。
- 新节点加入后需明确选择或调整所需策略组；不暗中替换现有出口。若已有自动应用机制在运行，保存可能触发受控重连，确认框会提示。
- 原有“预览导入 → 备份并导入”仍是整份配置替换流程，不应用于这类带固定证书 fragment 的添加链接。

## 交付状态

已公开发布 [anytls-go v0.0.28](https://github.com/NiuStar/anytls-go/releases/tag/v0.0.28) 和 [anytls-core v2026-10-24-03](https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-24-03)。较旧二进制不含该信任和订阅入口，须更新匹配版本；不只是更新脚本。

在目标 Linux/systemd 服务端执行（会安装并启动或重启该 AnyTLS 服务）：

```bash
curl -fsSL https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-install_server.sh -o anytls-install_server.sh && sudo bash anytls-install_server.sh --install
```

默认自动发现对外公网 IP、生成密码和持久证书，验证成功后在本地终端输出私有订阅链接。NAT 或多出口可追加 `--public-ip 实际公网IP`；默认订阅 HTTPS 443、AnyTLS 8443，需要放行两端口。443 已被其他服务占用时追加 `--subscription-listen :9443`，并放行该端口。

Mac 客户端安装／更新：

```bash
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash
```

在新版 WebUI 打开“配置与规则 → HTTPS 订阅”，粘贴完整私有链接（保留末尾 `#anytls-cert-sha256=...`），点击“从此订阅仅添加节点”，核对预览后“备份并添加节点”。随后明确选择新增节点或调整所需策略组。不要用整份配置替换按钮导入该链接。

本次公开附件、版本身份、实际互通、CI 与限制详见 [发布核验](releases/v2026-10-24-03-public-validation.md)。没有在用户的公网服务器执行上述安装，也没有自动升级现有助手或切换生产 VPN。

隔离测试与公网部署必须区分：回环 TLS、实际 AnyTLS 互通、WebUI 后端追加和桌面/手机界面是各自的验证层，不代表系统级 TUN、Linux systemd 安装或云防火墙已验证。
