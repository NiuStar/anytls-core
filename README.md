# anytls-core

> `CLOSED` 仅为最后保存的停止记录状态，完整收尾未验证、连续性 UNKNOWN；真实日志需本机授权更新配套助手并显式重连新版 VPN。目标测试机 `172.16.51.184` 尚未由本任务安装或验收。

Go 编写的 macOS AnyTLS VPN 客户端。本次版本 **[v2026-10-24-02](https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-24-02)** 精简 sing-box 的实际链接路径，移除内置调试 HTTP／pprof 和持久化缓存构造，保留 AnyTLS、mixed TUN、DNS、路由、gVisor 与 Chrome uTLS；提供 Intel（amd64）和 Apple Silicon（arm64）构建。未剥离符号的同条件 arm64 候选减少 1,050,272 字节，Mac Studio 真实 TUN 试验及旧版恢复通过；Intel 目标原生体验由用户另测。正式发行和附件状态以 GitHub Release 为准，见 [版本说明](docs/releases/v2026-10-24-02.md)。保留 [上一稳定版](docs/releases/v2026-10-23-01-public-validation.md) 的路由观察、私有磁盘历史、受认证助手分页、桌面／手机日志页、显式私有 IPv4 局域网 WebUI、预编译网页更新、并发测速、配置方案和 32 MiB 配置支持。ROUTED 不等于连接成功，DNS／REJECT／早期错误仍有覆盖缺口；普通更新不自动更新助手或重启 VPN，不宣称修复 Intel START_FAILED 或此前 DIRECT 问题。

## 一键安装（预编译程序 + 受限特权助手）

在 **Mac 的本机终端**运行（双架构版本支持 Apple Silicon 与 Intel）（不要加 `sudo`）：

```bash
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash
```

脚本按硬件架构从官方 Release 下载 `darwin-arm64`（Apple Silicon）或 `darwin-amd64`（Intel）二进制包，校验 SHA256，再在本机进行一次系统授权安装助手；**不需要安装 Go、不在用户电脑编译**。已有配置与密码保留，旧程序先备份，不自动停止／重载 VPN。缺 Python 3 时会提示安装；Intel 支持从提供 `darwin-amd64` 附件的双架构 Release 开始；旧版 arm64-only Release 不能在 Intel 安装。没有二进制附件的旧 Release 会明确拒绝，不自动转源码构建。

默认安装最新稳定版，无需指定版本；正常公共证书环境无需手动 export CA。若代理／私有 CA 不在可信证书库中，仍需配置经独立确认可信的 CA，校验失败会停止，绝不绕过。旧的 `install-control-helper.sh` URL 继续可用，`--version` 仅用于主动固定版本。内部下载仍强制 HTTPS／TLS1.2 和证书校验；Python 没有加载任何默认 CA 且未显式指定 CA 时，脚本仅为本次安装选择可用的 `/etc/ssl/cert.pem`，不改系统信任、不自动信任代理证书。

安装成功后自动为 Bash／Zsh 配置 `~/.local/bin`，保留原有 Shell 配置，重复安装不重复追加。新开的终端直接可用 `anytls`。通过管道执行的安装器无法修改当前父终端的 PATH；当前终端可执行 `export PATH="$HOME/.local/bin:$PATH"`，或直接使用下方绝对路径。特殊 Shell／配置文件不可安全修改时会警告，不擅自覆盖。

脚本会即时显示下载组件、发行附件、校验、系统助手授权、程序替换和 WebUI 切换阶段；网络等待期间每约5秒显示已接收字节、总大小（服务器提供时）与耗时。对应源码附件较大，GitHub 下载缓慢时也会持续提示。进度写入终端 stderr，不包含密码或签名下载链接。

先下载审阅再运行：

```bash
curl --fail --show-error --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/NiuStar/anytls-core/main/install-control-helper.sh -o install-control-helper.sh
bash install-control-helper.sh --check-download # 只校验下载，不安装、不授权
bash install-control-helper.sh
```

完成后：

```bash
~/.anytls/anytls-macos helper status
~/.anytls/anytls-macos password
```

打开 **http://127.0.0.1:18089**，账户 `admin`，密码由上述命令查看。安装完成自动启动新版 WebUI；若默认端口已有本工具的旧 WebUI，会核对所属用户与完整启动命令后关闭旧进程、启动新版，并确认页面可访问。端口若被其他程序占用则报错，不强行关闭。新装需要填写自己的节点后再启动 VPN。系统密码只在本机系统终端输入，工具不保存。详见 [二进制安装](docs/install-binary.md) 与 [助手权限](docs/privileged-helper.md)。

Release 同时提供对应应用源码、锁定依赖源码和许可证／NOTICE；SHA256SUMS 是下载完整性校验，不是 Apple 签名或公证。

默认发布构建内嵌精简 sing-box 核心，无需独立 sing-box 可执行文件。保留外部核心构建模式用于对照和回退。本项目不是 SagerNet 官方应用。

## 功能

- `v2026-10-22-05` 已发布最多8路并发测速、整数延迟分色、全体取消及迟到隔离；见 [版本说明](docs/releases/v2026-10-22-05.md) 与 [公开附件验收及DIRECT未关闭边界](docs/releases/v2026-10-22-05-public-validation.md)。

- `v2026-10-22-04` 已发布启动／重载／保存自动应用的分阶段、脱敏诊断，区分主错误与恢复证据；见 [版本说明与旧助手兼容边界](docs/releases/v2026-10-22-04.md) 和 [公开附件验收](docs/releases/v2026-10-22-04-public-validation.md)。

- `v2026-10-22-03` 源码新增配置方案保存／复制／切换、编辑区复制和节点 TCP／AnyTLS HTTPS 延迟测试，见 [版本说明及验收边界](docs/releases/v2026-10-22-03.md)。公开可安装版本以 GitHub 最新稳定 Release 为准；未发布的源码不等于安装器已取得新版。

- `anytls start / stop / status`：launchd 管理系统 TUN，本机 sudo 授权。
- `anytls config`：终端策略组与节点选择，方向键、回车／空格确认；运行时可保存，`anytls reload` 受控重连后生效。
- `anytls webui`：普通用户启动本机管理页 `http://127.0.0.1:18089`，账户 `admin`；`anytls password` 查看应用密码，`anytls password reset` 轮换并撤销旧会话。
- `anytls update --check` / `anytls update`：从 `v2026-10-22-06` 起检查／安装官方预编译更新，无需本机 Go，保留配置与程序备份；不自动重启 VPN 或 WebUI。失败按阶段给出受控原因，网页区分内存与磁盘版本并保留待重启状态。见 [更新说明](docs/install-update.md)。
- AnyTLS TCP／UDP、Chrome uTLS、gVisor mixed 网络栈。
- 显式 select 策略组、有序分流、SHA-256 固定本地 JSON 规则集。
- 节点服务器 IPv4 `/32`、IPv6 `/128` 物理接口旁路。
- 启动检查 HTTPS 出口和路由，停止检查路由／DNS 恢复。
- HTTPS 启动探测对明确的瞬时错误最多尝试三次，使用共享 40 秒探测 context；每次重试前重新检查服务与路由。同步路由工具另有单次超时，不是整个启动流程的硬实时保证。

## 从源码构建

双架构 Release 提供 macOS arm64 / amd64 预编译程序，普通用户使用上方一键安装即可。以下为开发者源码构建方式：需要 Python 3 和 **Go 1.26.8**，首次构建需能取得 go.mod 锁定的依赖。

必须使用附带 wrapper 应用已认证的 sing-box Box.Start 清理错误补丁和核心链接裁剪（缓存／调试 HTTP 的显式拒绝）；不能用普通 `go build` 替代发布构建：

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

发行目标为 macOS Apple Silicon 与 Intel；双架构适配说明见 [Intel 支持](docs/macos-intel-support.md)。没有 Apple 签名或公证。已有安装先停止 VPN 并备份程序、配置、选择文件和引用规则／证书，**不要覆盖真实配置**。

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

应用源码为 [GPL-3.0-or-later](LICENSE)。内嵌依赖、补丁及名称／关联限制见 [第三方说明](THIRD_PARTY_NOTICES.md) 和 [补丁说明](docs/embedded-upstream-patch.md)。v2026-10-21-03 的预编译附件同时提供对应源码和依赖许可证／NOTICE，不将仅有源码的旧 Release 与新版二进制分发混同。
