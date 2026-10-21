# anytls-core

Go 编写的 macOS AnyTLS VPN 客户端。当前版本：**v2026-10-21-02**。源码发行与验证边界见 [版本说明](docs/releases/v2026-10-21-02.md)。

默认发布构建内嵌精简 sing-box 核心，无需独立 sing-box 可执行文件。保留外部核心构建模式用于对照和回退。本项目不是 SagerNet 官方应用。

## 功能

- `anytls start / stop / status`：launchd 管理系统 TUN，本机 sudo 授权。
- `anytls config`：终端策略组与节点选择，方向键、回车／空格确认；运行时可保存，`anytls reload` 受控重连后生效。
- `anytls webui`：普通用户启动本机管理页 `http://127.0.0.1:18089`，账户 `admin`；`anytls password` 查看应用密码，`anytls password reset` 轮换并撤销旧会话。
- `anytls update --check` / `anytls update`：检查／源码升级，保留配置与程序备份；不自动重启 VPN 或 WebUI。安装说明见 [安装与升级](docs/install-update.md)。
- AnyTLS TCP／UDP、Chrome uTLS、gVisor mixed 网络栈。
- 显式 select 策略组、有序分流、SHA-256 固定本地 JSON 规则集。
- 节点服务器 IPv4 `/32`、IPv6 `/128` 物理接口旁路。
- 启动检查 HTTPS 出口和路由，停止检查路由／DNS 恢复。
- HTTPS 启动探测对明确的瞬时错误最多尝试三次，使用共享 40 秒探测 context；每次重试前重新检查服务与路由。同步路由工具另有单次超时，不是整个启动流程的硬实时保证。

## 从源码构建

本次 Release 固定源码，**不附二进制下载**。需要 Python 3 和 **Go 1.26.8**；首次构建需能取得 go.mod 锁定的依赖。已有 macOS arm64 实测产物另记录于 [版本说明](docs/releases/v2026-10-21-01.md)。

必须使用附带 wrapper 应用已认证的 sing-box Box.Start 清理错误补丁，不能用普通 `go build` 替代发布构建：

```sh
export GOTOOLCHAIN=local GOWORK=off GOFLAGS=
export GO_BIN="$(command -v go)"
export GOMODCACHE="$(go env GOMODCACHE)"
TAGS=with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core
python3 scripts/go-patched.py --go "$GO_BIN" test -p 2 -tags "$TAGS" ./...
python3 scripts/go-patched.py --go "$GO_BIN" vet -p 2 -tags "$TAGS" ./...
mkdir -p dist
python3 scripts/go-patched.py --go "$GO_BIN" build -p 2 -tags "$TAGS" -o dist/anytls-macos .
```

wrapper 校验精确上游版本、归档、补丁、临时 replacement 及输出摘要，不修改原模块缓存。外部核心构建去掉 `embedded_core` tag，并自行提供已核验的 sing-box。

## 安装与使用

目标为 macOS Apple Silicon；没有 Apple 签名或公证。已有安装先停止 VPN 并备份程序、配置、选择文件和引用规则／证书，**不要覆盖真实配置**。

新安装示例：

```sh
mkdir -p ~/.anytls ~/.local/bin
cp dist/anytls-macos ~/.anytls/anytls-macos
chmod 755 ~/.anytls/anytls-macos
cp config.example.yaml ~/.anytls/config.yaml
# 编辑示例，填入真实节点和对应 CA；不要上传密码。
ln -s ~/.anytls/anytls-macos ~/.local/bin/anytls
export PATH="$HOME/.local/bin:$PATH"
```

在 `~/.anytls/config.yaml.selected` 中保存一个已配置的 AnyTLS 节点名作为 DNS/bootstrap 基座；策略组出口由各自 `selected` 决定。两者并非同一选择。

```sh
anytls -config ~/.anytls/config.yaml -network proxy check
anytls config
anytls start
anytls status
anytls stop
```

严格 TLS 模式要求 CA PEM。已有 `skip-cert-verify: true` 节点仍需显式确认；它不提供服务器身份安全保证。sudo 密码只在本机终端输入，不发到聊天。

## 配置与分流

支持 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`、`RULE-SET` 和末尾唯一 `MATCH`；目标为 AnyTLS 节点、select 组、DIRECT 或 REJECT（MATCH 不支持 REJECT）。第一条匹配决定出口。不支持完整 Clash 配置或 SS 出站；未知语法不静默忽略。

本地规则集为 sing-box source JSON `version: 3`、非空 `rules`，配置需要 `path` 与文件 SHA-256。`resolve-ip: true` 在非 `no-resolve` 引用前插入解析。规则和所需 CA 会复制进当次 root 私有运行快照。远程 provider 不自动下载、替换或转换。

默认内嵌 `check/run` 不生成 runtime.json，也不调用外部核心。外部模式保留临时 runtime.json 行为。

## 本版验证与已知限制

- Mac 原生完整测试：114 顶层与 252 子测试通过，3 项跳过；vet、构建通过。
- 已验证真实节点的代理 HTTPS 与 UDP DNS；先前内嵌版完成短时 TUN 新旧对比，公网／服务器路由、HTTPS 与 DNS 成功。
- 本版新增启动重试有旧源码业务失败／新源码通过的原生回归；**修复版持续 TUN 使用尚待用户体验，不宣称所有节点、规则和启动失败根因均已验收**。
- 曾出现间歇 DNS／TLS 超时。有限重试不是连通性保证，持续失败仍停止并恢复网络。
- 策略组保存会重新序列化 YAML，可能丢注释、未知组字段或改变未加引号的数字字符串。编辑前备份，密码等数字字符串应加引号；本版不宣称任意 YAML 无损往返。
- 无 kill-switch、自动规则更新、开机自启、测速或无缝热切换。TUN 节点服务器需固定 IP。DNS／嗅探不保证等同 Mihomo。

## 许可证

应用源码为 [GPL-3.0-or-later](LICENSE)。内嵌依赖、补丁及名称／关联限制见 [第三方说明](THIRD_PARTY_NOTICES.md) 和 [补丁说明](docs/embedded-upstream-patch.md)。本次仅分发项目源码及补丁，不打包上游源码或第三方二进制。若另行分发静态链接二进制，需要同时满足相应源码、许可证及 NOTICE 交付义务。
