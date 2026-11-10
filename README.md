# anytls-core

## App 0.5.2 / build 0.5.2.20261110.1（发行候选，资格验证中）

核心 `v2026-11-10-01`，macOS 13+，Apple Silicon／Intel 独立原生包。
- 启动完成表示 `LOCAL_READY / INTERNET_UNVERIFIED`，不再同步等待外部检测网站；本地进程、TUN、旁路、DNS 及恢复保护保留。
- 受支持节点运行中热切换，不重启核心或重建 TUN；新连接走新节点，已有连接保留原出口。固定规则与专用组不被覆盖，DNS 缓存和 DoH 池按切换隔离。
- 非选择配置变更或热切能力不满足时明确 `RELOAD_REQUIRED`，不隐式 stop/start；UNKNOWN 只凭原操作绑定的认证只读恢复，普通刷新不解锁、不重放。
- 本版须通过最终源码的完整原生／CI／双架构附件门禁后正式发布；当前不是已发布或全部通过。Intel 本机手测继续延后，GitHub Intel 原生资格不豁免。ad-hoc 签名、未公证；发布不安装或启停用户 VPN。

详见[0.5.2 发布说明与验收边界](docs/releases/v2026-11-10-01.md)。以下为历史源码冻结时的记录，不代表当前发行状态。

## App 0.5.1 / build 0.5.1.20261109.1（正式发布准备，尚未发布）

核心 `v2026-11-09-03` 须从最终冻结提交原生重建，不复用 0.5.0 核心；目标为 macOS 13+ 的 Apple Silicon arm64 与 Intel amd64 双架构独立发行包。
- 节点菜单使用原生自定义按钮：点击测试保持菜单打开，完成结果原位更新，不重建跟踪中的菜单，不自动选择节点。
- 全部节点测试默认最多 6 个并发，重复点击合并为同一批；乱序完成仍绑定原节点、端点、ETag 和会话。完成样本保留至明确重测或退出。
- App 发送 `tcp_direct`，在 macOS 上只接受可用 IP 字面量；必须发现符合地址族的物理 Ethernet/Wi-Fi 路由、绑定网卡并读回内核 socket 选项，才允许 TCP connect。域名、缺失物理路由、IPv6 无对应路径或绑定失败返回 `UNAVAILABLE`，不走系统 DNS，不回退普通 TCP 或 VPN 路由。
- 测量 TCP 建连延迟，不是带宽或代理 HTTPS。Web 原有 `tcp`/`https` 保持兼容；不切节点、不改配置、DNS 或路由，不启停 VPN。默认 IPv4-only/TUN 策略不变。
- 启动显示连接初始化进度，提供显式「重新初始化连接…」；不重放旧操作，不把历史 UNKNOWN 改成功，不绕过持久事务保护。升级必须由用户从新 App 主动「安装／更新组件…」，使用本版配套核心与助手，不能只换 App 或默认删除历史记录／重置。
- ad-hoc 签名，未 Developer ID 签名或公证，不承诺 Gatekeeper 放行。最终提交双架构原生构建／测试／签名验包、完整 Go／Python、分支／main／标签 CI 与公开附件核验均须独立通过；旧内部 ARM 或 Rosetta 结果不等于本版最终资格，NOT_RUN 不能计为 PASS。真实管理员安装、节点出站及 VPN-on 物理旁路端到端仍须另验。
- 当前仅为待资格门禁的源码与发布说明，未来标签和附件名称不是已可下载的链接。构建和发布不安装生产 App／助手、不授权或启停服务／VPN。

详见[0.5.1 发布说明与验收边界](docs/releases/v2026-11-09-03.md)。以下旧版本说明是历史记录，不代表 0.5.1 的当前发行范围或验证结果。

## App 0.5.0 / build 0.5.0.20261109.1（原生 ARM 内部手测候选，未发布）

核心 `v2026-11-09-02` 从当前修复源码重新构建，避免不同映像沿用旧版本标签。修复历史已完成恢复记录遮蔽当前普通 AWAITING_HELPER 的只读检查，以及 Swift 无元数据时误报身份变化；仍保留断链、损坏、未知结果及不同候选 SHA 的 HOLD。

仅 Apple Silicon arm64 内部包，ad-hoc 签名、未公证；原生回归、签名与归档读回以随包 BUILD-INFO / BUILD-EVIDENCE 为准，完整 Go、Intel 原生、正式发行及生产 VPN 端到端未完成。构建不安装、不授权、不启动 App 或 VPN。用户另行明确授权的旧记录清理与直接重置不属于此构建步骤，不可用新 SHA 强行续接旧事务。详见[0.5.0 手测边界](docs/releases/v2026-11-09-02.md)。


## AnyTLS 菜单栏 0.4.9 内部候选（仅 Rosetta 验证，未发布）

App `0.4.9` / build `0.4.9.20261109.1` 增加启动连接初始化及显式「重新初始化连接…」入口；仅重新验证和连接已有组件，不安装、不重放上次操作、不启停 VPN。显式同意后也只丢弃客户端临时未知状态，须新鲜认证状态、节点和助手就绪校验完成才解除本次客户端锁；上次操作结果不追认为成功，磁盘历史 UNKNOWN 仍受原保护。

节点子菜单的全部节点 TCP 延迟测试结果保留在本次应用内存生命周期，直到退出或明确重新测试；刷新、休眠、重新登录及 VPN 状态变化不清空完成样本。显示「上次」及测试时间；配置变化显示「旧配置/上次」。这不是带宽或实时速度，不切换节点。Go `VERSION` 仍为 `v2026-11-09-01`，未重建核心，拟复用 exact qualified signed core。MacStudio 物理 arm64 已交叉编译 x86_64 并通过 Rosetta 五套隔离 fixture，共 911 项；测速保留和初始化 UNKNOWN 的反事实业务 RED/GREEN 已观察。不是 Intel 物理原生验收，正式发布与生产端到端仍 HOLD；不得把下方旧版结果当作 0.4.9 验收。详见[开发候选边界](docs/macos-menubar.md)。

## AnyTLS 0.4.7：已人工对账的旧重载事务兼容修复候选

本候选针对旧 `.core-reload-*` 事务已具备完整 `operator-reconciled.json` 人工对账证据、安装器可接受而 App 仍报 `CORE_RELOAD_PENDING` 的兼容性缺口。按既有安装器的只读证据合同校验，不删除日志、不把历史 UNKNOWN 改成功，不根据当前 VPN 停止状态推断历史完成。缺失、冲突、篡改或未完成证据继续 HOLD。

**当前仅准备内部手测包，未公开发布；以下正式附件名为未来发布约定，不代表下载已可用。** 最终源码审查、受影响 Intel 原生验证和用户手测状态以独立回执为准，旧版结果不自动沿用。

本版修复显式组件恢复已经完成、证据完整，却在后续升级时仍遇到 `RECOVERY_HOLD` 的问题。保留历史 UNKNOWN 和原始记录；缺少完成证明、配置变化、断链或其他未完成操作仍保持 HOLD。安装仍由用户主动确认并按需接受原生管理员授权，不新增 root 操作、不后台启动 VPN；本候选尚未完成整版发布验收，也未在生产安装。

本次发行标签为 **`v2026-11-09-01`**，App build 为 `0.4.7.20261109.1`。面向 **macOS 13+、Apple Silicon 与 Intel**：按芯片下载 `anytls-core-v2026-11-09-01-menubar-darwin-arm64.zip`（Apple Silicon）或 `anytls-core-v2026-11-09-01-menubar-darwin-amd64.zip`（Intel），解压后将 `AnyTLSMenuBar.app` 拖入「应用程序」并打开，在菜单中选择「安装／更新组件…」，按需接受 macOS 原生管理员授权。App 流程无需终端；首次安装不启动 VPN。一个 App 内嵌同一 Go 核心和固定助手能力，无登录窗口、不查询钥匙串；仅在核心／助手／控制台身份匹配后通过匿名私有管道自动认证，后端 HTTP 登录与 CSRF 校验保留。后台失败只更新红色菜单图标和提示，不抢焦点或弹窗；用户主动启动、停止、选节点或安装仍可能出现必要原生确认。

从 0.3.1 升级，先用旧 App 正常退出并停止 VPN，再替换 App；本版核心版本与候选不同，**不能只替换 App 就直接使用**，须从新 App 菜单「安装／更新组件…」完成受控迁移。支持规范 `~/.anytls/anytls-macos` 的旧 0700／0755 文件，保留配置和选择；更新后 VPN 保持停止，主动点「恢复 VPN…」才启动。旧 `~/.anytls/anytls`、双文件布局、自定义目录或未知身份／事务保持 HOLD，不强制覆盖。旧终端安装入口和双架构 CLI 保留在下方，不自动替换任何已安装服务。

**继承的拒绝与新鲜性边界：**只有收到完整 strict ACK、确认安全收尾的 typed HTTP 503 FAILED，才分类为已知拒绝，并以中文提示系统代理冲突；202、丢响应及其他未知结果仍锁定，不自动 STOP／START。旧内存 UNKNOWN 没有原 ACK，安装新版不能据此恢复或解锁；系统代理由用户自行决定，软件不静默关闭。连通性以 monotonic 读取边界过期，并对 MenuModel 缓存投影；timer 不作为新鲜性权威，产品 45／5／15／30 秒不变。双架构 affected 证据已通过，完整 local／原生五套／CI／公开附件须另以最终源码收据核验；当前生产未修复。

**验证与限制：**本版保留迁移 STOP 回执兼容性，并为既有未完成组件更新提供独立显式恢复入口；保留控制台参数顺序兼容。恢复新建独立事务，保留旧 UNKNOWN 与证据，不自动重放 STOP、授权或启动 VPN。支持 Apple Silicon 与 Intel 两个原生 App。最终 native／CI／公开下载资格以本次提交对应收据为准，不继承旧版测试或以文档提前宣称通过。真实管理员安装、用户控制台迁移、正式 VPN 路由／DNS／浏览器验收单列；发布不安装或启停用户 VPN。退出仍要求认证 STOP 回执和停止读回，不保证崩溃／强杀清理。仍为 ad-hoc 签名，未 Developer ID 签名或公证。详见[本版说明](docs/releases/v2026-11-09-01.md)和[菜单栏文档](docs/macos-menubar.md)。保持 sing-box v1.14.3 及既有 DoH／TLS 策略；250ms 为采样／变化发布节奏，非即时性能承诺。

## 终端一键安装（保留入口；预编译程序 + 受限特权助手）

在 **Mac 的本机终端**运行（双架构版本支持 Apple Silicon 与 Intel）（不要加 `sudo`）：

```bash
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash
```

完整安装成功后默认自动切换核心（会短暂重连，仅在 VPN 原本运行时执行；原本停止时不启动），无需额外参数。需要跳过时使用：

```bash
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash -s -- --no-reload-core
```

显式 `--reload-core` 仍可使用；下载检查和仅更新模式不重连。安装后的这次重连默认遵循节点 TLS 配置：已有 `skip-cert-verify: true` 无需二次确认，CA／pin 节点仍按原规则校验，不强制所有节点跳验，也不放宽发行下载 HTTPS、DoH 或 Google 等目标站点 TLS。身份检查、一次性操作回执与 UNKNOWN 处理见[安装说明](docs/install-binary.md#安装完成后默认重连核心)；仅对严格证明为停止前助手预检拒绝的历史事务自动对账解除阻断，原事务原地保留、不归档、不重发旧 reload。该恢复路径若 VPN 仍运行会主动停止一次，确认停止后继续安装，不恢复旧配置，也不会自动重新开启 VPN；其他 UNKNOWN 仍需只读核对。无需为此重新发布内嵌核心二进制。

若首个 `raw.githubusercontent.com` 请求出现 TLS reset／无法连接，改用 **GitHub 官方 API** 取得同一 `main/get.sh`（不是第三方镜像）：

```bash
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/NiuStar/anytls-core/contents/get.sh?ref=main' | bash
```

脚本下载后的三个组件请求优先使用 raw；curl 失败时会提示并改用官方 API，保留 HTTPS／证书校验、超时与进度。两处都失败即停止，不执行失败下载；空响应或 JSON／HTML 等非脚本响应也会拒绝。首次入口尚未下载，不能自行回退，故需上述备用命令；API 限流或二进制 Release 下载故障仍可能阻断安装，不修改 DNS、不跳过 TLS 校验。

脚本按硬件架构从官方 Release 下载 `darwin-arm64`（Apple Silicon）或 `darwin-amd64`（Intel）二进制包及 `SHA256SUMS`，校验后在本机进行系统授权安装助手；**默认不下载应用源码、对应源码／依赖包，不需要安装 Go、不在用户电脑编译**。二进制包内的许可证／NOTICE 仍保留。已有配置与密码保留，旧用户程序先备份；完整安装成功后默认受控重连原本运行的 VPN，`--no-reload-core` 可跳过。缺 Python 3 时会提示安装；没有对应架构二进制附件的旧 Release 会明确拒绝，不自动转源码构建。

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

### WebUI 与代理 IPv4 默认监听（v2026-10-31-03）

安装器、手动 WebUI 和新建 WebUI LaunchAgent 默认监听 `0.0.0.0:18089`。普通用户可直接运行 `anytls webui`；以下命令显式写出默认值：

```sh
anytls webui --listen 0.0.0.0 --port 18089
```

浏览器使用 `http://服务器IP或主机名:18089`，不是 `0.0.0.0`；无需逐台配置网卡地址或 Host 白名单。也可显式绑定本机已分配的规范 IPv4（含公网地址）。监听参数不接受 DNS、IPv6、前导零或附带端口。默认全 IPv4 监听；显式 `--listen 127.0.0.1` 可限制本机，root 禁止不变；登录、同请求 Host 的精确 Origin、CSRF 与无 CORS 保留。非回环显示 `network-http`，HTTP 不加密凭据与会话，网络访问控制和传输保护由部署环境管理。已有程序须安装支持该能力的版本并以所需监听参数启动；发布不自动部署或重启。本版继承v2026-10-31-04安装器策略：安装／重装统一使用 `0.0.0.0`，不再从旧进程推断配置；本次安装显式传入 `--webui-listen 127.0.0.1` 才限制为仅本机。已有 LaunchAgent 的显式 argv 不会自动迁移，旧进程也不会仅因源码变更而改变监听。

SOCKS／HTTP 代理模式默认监听 `0.0.0.0:11080`；使用 `--local-listen 127.0.0.1` 可限制为本机。代理入口没有入站认证，不应直接暴露到不可信网络。请通过防火墙限制访问。TUN 及特权助手 Unix socket 不属于 TCP 监听，不改为网络服务。

### TUN 初始地址族策略（本地候选，尚未发布）

**默认改为 IPv4-only；这是有意的默认行为迁移，不是自动探测或失败后换族。**
顶层 `ipv6` 缺省或 `false` 时，TUN 只配置 `172.19.0.1/30`，不配置虚拟 IPv6
地址；自动路由保持启用。统一严格 DoH 使用 `ipv4_only`：正常返回 A，AAAA 返回
`NOERROR` 空答案（NODATA），不改为 REFUSED、不转发到其他解析器。

确实需要双栈的旧配置须显式加入：

```yaml
ipv6: true
nodes:
  # 保留原节点、证书与分流配置
```

仅接受 YAML 布尔值 `true` / `false`（以及解析为布尔的别名）；`null`、空值、
字符串（包括 `off`、`"false"`）、数字、列表和映射均拒绝，代理模式导入／校验也不
静默丢弃坏值。Clash 导入、保存和导出保留显式 `false`。

`ipv6: true` 恢复原 TUN `fdfe:dcba:9876::1/126` 和双栈 DNS，前提是所选业务出口
确有可用 IPv6 目标连接能力；程序不检测或承诺此能力。物理主机 IPv6、虚拟 TUN、
AnyTLS 外层服务器地址族与远端目标地址族不同，不能由服务器是 IPv4／IPv6 推断出口。
IPv6 服务器仍保留 `/128` 物理旁路。`-server` / `-password-file` 构建默认同为
IPv4-only，无新增命令行开关；需双栈时使用 YAML。普通 mixed／proxy 模式不继承
本节的 TUN 地址／DNS 变化。严格 TLS、leaf pin、选择与分流、DoH detour 不变；
不新增 fallback、连接重试、目标域名特例或静态目标 IP。

本地无特权 SDK／loopback 验证不等于 macOS 正式 TUN、浏览器或目标站点验收。

## 功能

### 当前候选控制台与运行边界

- 16 个路由页面按网络概览、连接管理、节点与线路、设置和调试工具组织；路由数量不是全部页面功能验收。节点卡片已接入桌面4列／窄桌面3列／手机2列、完整长名称换行、当前选择与启动节点区分、原延迟阈值和44×44操作目标；更多复用编辑与 TCP 测试，无新增节点删除 API。见[产品接入与证据边界](docs/nodecards-r3-product.md)。
- 助手激活边界：控制请求发送后若身份不符，结果保持 UNKNOWN，按 at-most-once 不自动重发；完整安装器严格核对八字段激活回执及 SHA／tag／path，拒绝不合格回执。两项最小补丁专项独审通过，不等于原生安装／root 回滚验收，普通 update 范围不变。
- 配置方案以稳定 ID 标识；整套切换包含节点、策略组和规则，并以版本／If-Match CAS 拒绝陈旧保存，不把改名当新方案。HTTPS 订阅支持预览、确认、绑定方案及每小时自动检查；检查不是无确认覆盖当前配置，WebUI 未运行时不承诺后台检查。
- WebUI 常驻固定 HTTPS endpoint 连通性检查与已记录小时分布属于普通用户 WebUI 的观察，不等于 VPN 健康、全日覆盖或全天 SLA。连通性目标固定为 `https://www.gstatic.com/generate_204`，不接受用户任意 URL。
- VPN 流量仅统计当前受验证实例中 SDK ROUTED TCP／UDP transport payload；排除 ICMP、所有 raw Flow 包、IP／传输头和 TCP 底层重传，不等于网卡／TLS wire／全设备总流量；记录条数不是字节。缺失、过期、非运行或旧助手状态显示不可用，不补造零值。见[流量契约](docs/r10-traffic-contract.md)。
- **三种身份分别核对**：普通用户程序／WebUI 的内存与磁盘版本、root 助手、实际 VPN 核心不是同一 authority。网页升级成功不证明助手已更新；助手更新成功也不证明运行中的核心已经替换。`get.sh` 必须由普通用户在 Mac 本机运行（入口拒绝 root），完整安装阶段通过本机系统授权取得助手所需 root 权限；不要给整条命令加 sudo，也不要将系统密码发到聊天。安装保留配置及旧用户程序备份，完整安装成功后默认对原本运行的 VPN 请求一次受控重连，原本停止时不启动。`--no-reload-core` 可跳过，之后按维护安排执行 `anytls reload`／重连。两种方式均需另验目标机实际核心身份与业务，不承诺旧核心私有快照备份或自动回退。

- `v2026-10-22-05` 已发布最多8路并发测速、整数延迟分色、全体取消及迟到隔离；见 [版本说明](docs/releases/v2026-10-22-05.md) 与 [公开附件验收及DIRECT未关闭边界](docs/releases/v2026-10-22-05-public-validation.md)。

- `v2026-10-22-04` 已发布启动／重载／保存自动应用的分阶段、脱敏诊断，区分主错误与恢复证据；见 [版本说明与旧助手兼容边界](docs/releases/v2026-10-22-04.md) 和 [公开附件验收](docs/releases/v2026-10-22-04-public-validation.md)。

- `v2026-10-22-03` 源码新增配置方案保存／复制／切换、编辑区复制和节点 TCP／AnyTLS HTTPS 延迟测试，见 [版本说明及验收边界](docs/releases/v2026-10-22-03.md)。公开可安装版本以 GitHub 最新稳定 Release 为准；未发布的源码不等于安装器已取得新版。

- `anytls start / stop / status`：launchd 管理系统 TUN，本机 sudo 授权。
- `anytls config`：终端策略组与节点选择，方向键、回车／空格确认；运行时可保存，`anytls reload` 受控重连后生效。
- `anytls webui`：普通用户启动全 IPv4 网卡管理页（本机可访问 `http://127.0.0.1:18089`，其他设备使用主机实际地址），账户 `admin`；`anytls password` 查看应用密码，`anytls password reset` 轮换并撤销旧会话。
- `anytls update --check` / `anytls update`：从 `v2026-10-22-06` 起检查／安装官方预编译更新，无需本机 Go，保留配置与程序备份；不自动重启 VPN 或 WebUI。失败按阶段给出受控原因，网页区分内存与磁盘版本并保留待重启状态。见 [更新说明](docs/install-update.md)。
- AnyTLS TCP／UDP、Chrome uTLS、gVisor mixed 网络栈。
- 显式 select 策略组、有序分流、SHA-256 固定本地 JSON 规则集。
- 节点服务器 IPv4 `/32`、IPv6 `/128` 物理接口旁路。
- 启动检查 HTTPS 出口和路由，停止检查路由／DNS 恢复。
- HTTPS 启动探测对明确的瞬时错误最多尝试三次，使用共享 40 秒探测 context；每次重试前重新检查服务与路由。同步路由工具另有单次超时，不是整个启动流程的硬实时保证。

## 从源码构建

双架构 Release 提供 macOS arm64 / amd64 预编译程序，普通用户使用上方一键安装即可。以下为开发者源码构建方式：需要 Python 3 和 **Go 1.27.3**，首次构建需能取得 go.mod 锁定的依赖。

必须使用附带 wrapper 应用已认证的 sing-box 补丁，包括 Box.Start 清理、DNS stream 缓冲所有权修复和核心链接裁剪（缓存／调试 HTTP 的显式拒绝）；不能用普通 `go build` 替代发布构建：

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

严格 CA 模式要求 CA PEM；节点可使用 `fingerprint: '<64位十六进制 SHA-256>'` 固定**完整叶证书 DER**（大小写均接受，读取后规范为小写），与 `client-fingerprint: chrome`／`golang` 的 ClientHello 配置完全不同。`fingerprint` 是可选的 pin-only 身份认证，不校验证书 CA 链、主机名或有效期；必须由可信渠道独立取得，证书更新后需更新指纹。不得与 `ca`、`certificate-public-key-sha256` 或 `skip-cert-verify: true` 混用；空值、null、非字符串、非64位十六进制均拒绝，不会退回跳过校验。纯数字指纹也必须加引号。原有 `certificate-public-key-sha256` 仍表示固定公钥 SPKI 的 base64 SHA-256，不是完整证书指纹；两种 pin-only 模式均无需本地 CA 文件，不提供公共 CA／主机名校验。已有跳过校验节点不提供服务器身份安全保证；完整安装后的受控重连默认接受节点配置，无需二次确认，CLI 的独立确认规则不变。sudo 密码只在本机终端输入，不发到聊天。

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

- 本版为尚未发布的证据快照。R10 基线 `6a763573c693d6b701859a0ef87d2408e27a0cf0` 的保留原生证据为760顶层／2479子测试 PASS、8顶层 SKIP、0 FAIL，11包及vet/build通过；这是继承的基线证据，不是新增节点卡片或最终发行身份验收，也不是本次重跑。卡片已有局部浏览器／真实认证 HTTP 证据，两项助手补丁已有专项独审；“更多”旧 owner 与 Run 取消终结问题已作最小修复并专项独审，Check-only 语义保持；本地第三轮 full 753顶层／2472子PASS、10SKIP、11包及vet/build通过。前两轮失败保留；扩展连接复用曾出现EOF，归因未定，未添加重试或放宽断言。最终实现身份、native／打包、整体验收、分支／main／标签 CI、公开双架构六附件与独立版本执行均 PENDING；安装、root 助手与正式 VPN／目标站点另验。旧版699／2336等数字仅归属[v2026-11-02-02历史说明](docs/releases/v2026-11-02-02.md)。
- 默认逐连接换族保留IPv6优先尝试、同一实际编译规则与同一具体出口约束；证书／认证／取消／ACK未确认不触发换族，备用连接也须ACK成功后才能发送业务载荷。EDNS、自定义TLS、ECS／optimistic／rewrite、动态selector、应用自带DNS及其他未支持路径保持UNKNOWN，不全局禁用IPv6、不添加明文DNS回退。用户真实Chrome商店／站点／正式TUN体验仍待验，不宣称所有故障已修复或普遍WAN提速。
- 既有 `--dns-metrics` 仍默认关闭，仅前台 `run` 显式启用后尝试写一次stderr聚合。本版另有 `dns_schema:1` 有界运行证据：仅新暂存且绑定启动operation／epoch的嵌入式服务启用；普通CLI／Check禁用，旧进程argv不迁移。认证API／页面读取最多64条实际完成和GotConn计数，STALE／GAP不掩盖；不是持续存活证明，也不提供完整查询、缓存命中／合并、HTTP状态、新TLS握手、实际叶证书或实际detour证明。
- 真实SDK确定性拨号失败benchmark中，开启观测增加同步469ns／352B／9alloc、异步496ns／416B／10alloc；不是WAN／TLS或端到端性能，helper零分配不代表runtime零分配。缓存、并发合并、连接复用与恢复是已有GREEN基线；本版不宣称DNS加速、GoogleIPv6或Intel现场已修复。原生局部门与CLI入口的边界见[版本说明](docs/releases/v2026-10-31-01.md)。
- 既有 GEOIP 用户 URL 私有副本及记录回放观察属于上一版证据，不作为本版新规则入口的正式 root／TUN 验收；物理出口仍 UNKNOWN。
- 曾出现间歇 DNS／TLS 超时。有限重试不是连通性保证，持续失败仍停止并恢复网络。
- 策略组保存会重新序列化 YAML，可能丢注释、未知组字段或改变未加引号的数字字符串。编辑前备份，密码等数字字符串应加引号；本版不宣称任意 YAML 无损往返。
- 无 kill-switch、自动规则更新、开机自启或无缝热切换。TUN 节点服务器需固定 IP。DNS／嗅探不保证等同 Mihomo。

## 许可证

应用源码为 [GPL-3.0-or-later](LICENSE)。内嵌依赖、补丁及名称／关联限制见 [第三方说明](THIRD_PARTY_NOTICES.md) 和 [补丁说明](docs/embedded-upstream-patch.md)。v2026-10-21-03 的预编译附件同时提供对应源码和依赖许可证／NOTICE，不将仅有源码的旧 Release 与新版二进制分发混同。
