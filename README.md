# anytls-core

> `CLOSED` 仅为最后保存的停止记录状态，完整收尾未验证、连续性 UNKNOWN；真实日志需本机授权更新配套助手并显式重连新版 VPN。目标测试机 `172.16.51.184` 尚未由本任务安装或验收。

Go 编写的 macOS AnyTLS VPN 客户端。当前版本 **v2026-10-27-01** 新增 WebUI 单条分流规则入口，支持下拉选择类型／目标／位置、GEOIP 的 CN 与现有有效 RULE-SET，保留域名／CIDR 文本输入；默认在最终 MATCH 前插入，不移动 MATCH 或重排旧规则。局部插入保留其他 YAML 原字节，陈旧版本、无效规则集和不支持的布局明确拒绝。见下方“单条分流规则”及 [本版说明与待验收项](docs/releases/v2026-10-27-01.md)；最终 Mac 原生测试／构建／打包、公开 CI 和附件验收尚待完成，可安装版本以 [公开 Release](https://github.com/NiuStar/anytls-core/releases) 为准，源码版本不等于已发布。保留原生 GEOIP/CN 完整快照、可信 sticky 祖先守卫兼容、记录归属隔离与单次 decode/New、独立 `check`、严格 TLS 和既有分流合同。发行目标仍为 Intel（amd64）和 Apple Silicon（arm64）；固定 Go1.27.3／sing-box v1.14.3，SDK、补丁、构建 wrapper、打包器不变，默认只下载程序包与校验和。发布不安装程序、不改正式配置／规则、不更新助手、不切换 WebUI、不重启 VPN 或 TUN。既有正式 root 记录遥测不代表本版单条规则或 GEOIP 已在正式 TUN 验收；不宣称物理出口、DIRECT／IP白名单、Intel START_FAILED、IPv6／DNS或长期掉线已修复。保留公网 IP 私有订阅、严格整叶／SPKI 认证、仅添加节点、配置方案、并发测速与32MiB配置能力。ROUTED 不等于连接成功，普通更新不自动更新助手或重启 VPN。

## 一键安装（预编译程序 + 受限特权助手）

在 **Mac 的本机终端**运行（双架构版本支持 Apple Silicon 与 Intel）（不要加 `sudo`）：

```bash
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash
```

若首个 `raw.githubusercontent.com` 请求出现 TLS reset／无法连接，改用 **GitHub 官方 API** 取得同一 `main/get.sh`（不是第三方镜像）：

```bash
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/NiuStar/anytls-core/contents/get.sh?ref=main' | bash
```

脚本下载后的三个组件请求优先使用 raw；curl 失败时会提示并改用官方 API，保留 HTTPS／证书校验、超时与进度。两处都失败即停止，不执行失败下载；空响应或 JSON／HTML 等非脚本响应也会拒绝。首次入口尚未下载，不能自行回退，故需上述备用命令；API 限流或二进制 Release 下载故障仍可能阻断安装，不修改 DNS、不跳过 TLS 校验。

脚本按硬件架构从官方 Release 下载 `darwin-arm64`（Apple Silicon）或 `darwin-amd64`（Intel）二进制包及 `SHA256SUMS`，校验后在本机进行系统授权安装助手；**默认不下载应用源码、对应源码／依赖包，不需要安装 Go、不在用户电脑编译**。二进制包内的许可证／NOTICE 仍保留。已有配置与密码保留，旧程序先备份，不自动停止／重载 VPN。缺 Python 3 时会提示安装；没有对应架构二进制附件的旧 Release 会明确拒绝，不自动转源码构建。

默认安装最新稳定版，无需指定版本；正常公共证书环境无需手动 export CA。若代理／私有 CA 不在可信证书库中，仍需配置经独立确认可信的 CA，校验失败会停止，绝不绕过。旧的 `install-control-helper.sh` URL 继续可用，`--version` 仅用于主动固定版本。内部下载仍强制 HTTPS／TLS1.2 和证书校验；Python 没有加载任何默认 CA 且未显式指定 CA 时，脚本仅为本次安装选择可用的 `/etc/ssl/cert.pem`，不改系统信任、不自动信任代理证书。

安装成功后自动为 Bash／Zsh 配置 `~/.local/bin`，保留原有 Shell 配置，重复安装不重复追加。新开的终端直接可用 `anytls`。通过管道执行的安装器无法修改当前父终端的 PATH；当前终端可执行 `export PATH="$HOME/.local/bin:$PATH"`，或直接使用下方绝对路径。特殊 Shell／配置文件不可安全修改时会警告，不擅自覆盖。

脚本会即时显示下载组件、二进制包与校验和、校验、系统助手授权、程序替换和 WebUI 切换阶段；网络等待期间每约5秒显示已接收字节、总大小（服务器提供时）与耗时。源码附件仅供需要时从 Release 单独取得，不参与默认安装下载。进度写入终端 stderr，不包含密码或签名下载链接。

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

Release 同时提供对应应用源码、锁定依赖源码和许可证／NOTICE；**这些源码附件供单独下载，默认一键安装不下载它们**。SHA256SUMS 是下载完整性校验，不是 Apple 签名或公证。

默认发布构建内嵌精简 sing-box 核心，无需独立 sing-box 可执行文件。保留外部核心构建模式用于对照和回退。本项目不是 SagerNet 官方应用。

### 单条分流规则（v2026-10-27-01）

配置页 → **分流规则 → 新增规则**，选择类型、匹配值和目标，预览后点 **校验并保存**。支持 DOMAIN、DOMAIN-SUFFIX、IP-CIDR、GEOIP（只选 CN）和现有有效 RULE-SET；不添加或移动 MATCH，不重排旧规则。默认放在最终 MATCH 前，**已有前序规则仍优先**；也可选择最前面或现有第 N 条前（界面从1编号）。相同类型／值／目标／标志已存在时不重复插入、不重新连接。

类型、目标、插入位置、GEOIP 国家代码和 RULE-SET 标签均使用下拉选择；GEOIP 国家代码下拉目前只有 CN。DOMAIN／DOMAIN-SUFFIX／IP-CIDR 保留自由文本输入，指定序号为数字输入，no-resolve 为复选框。

选项与 ETag 来自同一份配置字节；保存须提供匹配的 `If-Match`，陈旧版本拒绝，不覆盖新配置。目标只列出可解析且可构造的节点／组及 DIRECT／REJECT。RULE-SET 须通过路径／SHA／结构校验和实际内嵌核心 decode/New/Close（不 Start、不监听）；保存前也复查已有启用规则集。没有有效规则集时不能提交该类型，不自动下载或创建 provider。

建议先“导出当前配置”或“保存当前为方案”备份；此入口沿用原子配置保存，不自动创建导入备份。保存后运行中的 VPN 会自动应用，可能短暂断网；未运行时仅保存，不启动。保存与生效结果分别显示。原始配置草稿会保留，但保存版本失效，须先复制草稿，再重新读取合并。仅普通显式块状 rules 列表且末尾有唯一 MATCH 可安全局部插入；流式列表／规则别名／合并等会提示使用原始编辑器，不静默重写原 YAML。选择、订阅、其他规则、注释及未知字段保持原字节。完整接口合同见 [API](web_assets/API.md#single-rule-add-contract)。

### WebUI IPv4 监听（v2026-10-25-02）

默认仍只监听 `127.0.0.1`。需要所有 IPv4 网卡访问时，普通用户运行：

```sh
anytls webui --listen 0.0.0.0 --port 18089
```

浏览器使用 `http://服务器IP或主机名:18089`，不是 `0.0.0.0`；无需逐台配置网卡地址或 Host 白名单。也可显式绑定本机已分配的规范 IPv4（含公网地址）。监听参数不接受 DNS、IPv6、前导零或附带端口。默认回环与 root 禁止不变；登录、同请求 Host 的精确 Origin、CSRF 与无 CORS 保留。非回环显示 `network-http`，HTTP 不加密凭据与会话，网络访问控制和传输保护由部署环境管理。已有程序须安装本版并以所需监听参数启动才具有该能力；发布不自动部署或重启。安装器保留已有绑定，切换到通配监听前须退出旧 WebUI，避免端口冲突。

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

双架构 Release 提供 macOS arm64 / amd64 预编译程序，普通用户使用上方一键安装即可。以下为开发者源码构建方式：需要 Python 3 和 **Go 1.27.3**，首次构建需能取得 go.mod 锁定的依赖。

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

严格 CA 模式要求 CA PEM；节点可使用 `fingerprint: '<64位十六进制 SHA-256>'` 固定**完整叶证书 DER**（大小写均接受，读取后规范为小写），与 `client-fingerprint: chrome`／`golang` 的 ClientHello 配置完全不同。`fingerprint` 是可选的 pin-only 身份认证，不校验证书 CA 链、主机名或有效期；必须由可信渠道独立取得，证书更新后需更新指纹。不得与 `ca`、`certificate-public-key-sha256` 或 `skip-cert-verify: true` 混用；空值、null、非字符串、非64位十六进制均拒绝，不会退回跳过校验。纯数字指纹也必须加引号。原有 `certificate-public-key-sha256` 仍表示固定公钥 SPKI 的 base64 SHA-256，不是完整证书指纹；两种 pin-only 模式均无需本地 CA 文件，不提供公共 CA／主机名校验。已有跳过校验节点仍需显式确认；它不提供服务器身份安全保证。sudo 密码只在本机终端输入，不发到聊天。

### 显式关闭 SNI（默认不变）

节点可设置布尔 `disable-sni: true`，仅关闭 ClientHello 的 SNI 扩展；已有 `sni` 不会被静默删除，在 CA 模式下仍用作主机名验证参考，链验证与整叶 pin 保持不变。显式 null／非布尔拒绝。数字 IP＋可信整叶 pin 不需要 SNI；已有配置可显式关闭，与面板对新订阅默认不输出 SNI 是独立策略，不自动迁移。此为 SNI 敏感路径的候选规避选项，不宣称完整根因修复或长期稳定。转换、保存编辑和 YAML 导出保留该字段；详见 [SNI 配置与验证边界](docs/disable-sni.md)。

### 无域名公网 IP 服务端订阅

与 [anytls-go v0.0.28](https://github.com/NiuStar/anytls-go/releases/tag/v0.0.28) 联动：服务端一键安装生成持久证书和私有订阅链接；本客户端 v2026-10-24-03 在“配置与规则 → HTTPS 订阅 → 从此订阅仅添加节点”预览、确认后追加节点，保留现有选择和分流。完整链接是私有凭据，必须可信交付；不会从未经验证的地址接受指纹。两项目匹配版本发布后使用，详见 [公网 IP 私有订阅](docs/public-ip-private-subscription.md)。

## 配置与分流

支持 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`、`GEOIP,CN`、`RULE-SET` 和末尾唯一 `MATCH`；目标为 AnyTLS 节点、select 组、DIRECT 或 REJECT（MATCH 不支持 REJECT）。第一条匹配决定出口。不支持完整 Clash 配置或 SS 出站；未知语法不静默忽略。

`GEOIP,CN,DIRECT` 和 `GEOIP,CN,DIRECT,no-resolve` 均可原生编译、导入、保存、导出与快照使用，目标也可为节点、组或 REJECT。仅接受精确 `CN`，不把 `gcn`、`cn` 或其他国家自动改为 CN。Clash 导入保留支持的 CN 规则；其他国家仍按现有不支持项预览跳过并提示，原生配置则拒绝。内置完整上游 CN IPv4/IPv6 快照（6525/3489 条，2026-10-26），来源 gaoyifan/china-operator-ip，MIT；定义为可信国内 BGP 分类＋未宣告 RIR-CN 登记兜底，不保证物理所在地或商业数据库完整度。精确提交、SHA、许可和更新方式见 `assets/geoip/SOURCE.json`；不在运行时联网下载、不自动过期。

无 `no-resolve` 时，仅流量到达该规则位置才执行解析，复用现有 secure-dns（1.1.1.1 DoH，经 anytls-out）与 prefer_ipv4 策略，随后匹配 IPv4/IPv6。域名解析结果中任一地址属于内置 CN 集合即命中；实际拨号仍可能使用完整地址列表，因此命中 `GEOIP,CN` 不保证最终连接 IP 属于 CN。此前已匹配的规则不会因该 GEOIP 主动解析。此模式会为原本无 DNS block 的 mixed 配置加入该 DNS 服务，并启用 DNS hijack/reverse_mapping；较早 DOMAIN→DIRECT 的实际拨号仍可能需要该 DNS 服务。`no-resolve` 不新增解析动作或 DNS block，仅匹配已有目标 IP（包括先前已解析结果）。非 GEOIP 配置不改变 DNS 或规则编译结果。固定 sing-box v1.14.3 使用原生 `ip_cidr`，不用已移除的旧 GeoIP 选项、不升级 SDK。连接记录显示真实规则种类 GEOIP/CN 与实际出口，不猜测命中的子网或成功状态。

本地规则集为 sing-box source JSON `version: 3`、非空 `rules`，配置需要 `path` 与文件 SHA-256。`resolve-ip: true` 在非 `no-resolve` 引用前插入解析。规则和所需 CA 会复制进当次 root 私有运行快照。远程 provider 不自动下载、替换或转换。

默认内嵌 `check/run` 不生成 runtime.json，也不调用外部核心。外部模式保留临时 runtime.json 行为。

## 本版验证与已知限制

- 精确实现提交的 Linux 完整回归460项顶层／1360项子测试 PASS、6项 SKIP，vet通过；定向单条规则9项顶层／50项子测试通过。最终 Mac 原生测试／构建／打包、公开 CI 与公开附件验收待完成，不以 Linux 结果替代。
- 实际 Chromium 在1280／390宽度通过下拉／文本输入、预览／提交、陈旧响应隔离、保存草稿保护和刷新失败反馈回归；API 为合成响应，不是实际 Mac 助手或 TUN 验收。
- `TestDiskRecordsStickyAncestorLifecycle` 的本地间歇失败已定位为夹具读取与合法 state.json 原子替换重叠；本版仅在该测试增加互斥排序，保留真实 os.Rename 与全部断言，不改连接记录实现或严格守卫。固定候选100次压力、Linux完整460项顶层／1360项子测试 PASS、6项 SKIP与vet通过；这些证据来自独立修复提交，不冒充最终发行身份验收。旧发行提交的公开 CI run40429261079仍为失败，Ubuntu失败断言不可见、原因 UNKNOWN；不宣称该测试修正已解释或清除旧CI失败。详见版本说明。
- 既有 GEOIP 用户 URL 私有副本及记录回放观察属于上一版证据，不作为本版新规则入口的正式 root／TUN 验收；物理出口仍 UNKNOWN。
- 曾出现间歇 DNS／TLS 超时。有限重试不是连通性保证，持续失败仍停止并恢复网络。
- 策略组保存会重新序列化 YAML，可能丢注释、未知组字段或改变未加引号的数字字符串。编辑前备份，密码等数字字符串应加引号；本版不宣称任意 YAML 无损往返。
- 无 kill-switch、自动规则更新、开机自启或无缝热切换。TUN 节点服务器需固定 IP。DNS／嗅探不保证等同 Mihomo。

## 许可证

应用源码为 [GPL-3.0-or-later](LICENSE)。内嵌依赖、补丁及名称／关联限制见 [第三方说明](THIRD_PARTY_NOTICES.md) 和 [补丁说明](docs/embedded-upstream-patch.md)。v2026-10-21-03 的预编译附件同时提供对应源码和依赖许可证／NOTICE，不将仅有源码的旧 Release 与新版二进制分发混同。
