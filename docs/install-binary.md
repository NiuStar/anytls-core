# 预编译 Release 安装器（macOS Apple Silicon / Intel）

此入口从固定官方仓库 `NiuStar/anytls-core` 的稳定 GitHub Release 下载
按硬件选择 `darwin-arm64` / `darwin-amd64` 二进制，**不安装 Go、不本地编译、不运行压缩包内的 Python/shell**。
需要普通用户、macOS arm64 或 Intel x86_64、Python 3、curl 和可交互的本地终端。不要用 sudo
运行整个安装器；受限助手安装步骤会由候选程序调用系统 sudo 自行授权。安装器
不读取、保存或传输系统密码。VPN 不会因安装而自动启动。

## 使用

推荐在本机终端使用统一短入口（默认最新稳定版，旧 URL 继续兼容）：

```sh
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash
```

正常公共证书环境无需在命令前手动 export CA；若代理／私有 CA 不在可信证书库中，仍需配置经独立确认可信的 CA，校验失败会停止而不绕过。自动选择仅适用于以下条件：未显式设置 SSL_CERT_FILE／SSL_CERT_DIR，且 Python 默认 CA 库为空时，bootstrap 验证系统 `/etc/ssl/cert.pem` 含 CA 后仅为本次安装使用它；已有默认 CA 或显式设置不替换，证书失败不关闭校验。

成功后 Bash／Zsh 的登录和交互配置会加入幂等 PATH 段，原文件保留；新终端可直接运行 `anytls password`。脚本无法修改父终端环境，当前窗口仍需 `export PATH="$HOME/.local/bin:$PATH"` 或用 `~/.anytls/anytls-macos password`。不支持的 Shell／危险配置文件只警告，不改写。`--check-download` 不改 Shell 配置。

从可信 checkout 执行：

```sh
bash install-control-helper.sh
bash install-control-helper.sh --version v1.2.3
```

`v1.2.3` 仅为 tag 格式示例；请替换成实际包含二进制附件的稳定版本。不指定
`--version` 时使用最新稳定 Release。支持稳定 semver 和项目的 `vYYYY-MM-DD-NN`
格式，不接受 prerelease、分支、任意仓库或下载 URL。

根入口由可信 main 同时下载 `scripts/install-binary.py` 和其同目录
`install.py`。二进制安装器只通过 `__file__` 的 sibling 加载后者，复用 HTTPS
重定向约束、稳定版本校验、安全解压、配置初始化及备份/原子发布逻辑；不会从
Release 归档寻找 Python 模块。可信 bootstrap/main 和 GitHub HTTPS 都属于本次
信任边界；SHA256SUMS **不是独立签名，也不抵御 GitHub 发布权限被攻破**。

## 下载失败与重试边界

Python 下载器仅对 **GET 打开响应之前**的明确瞬态 SSL EOF、连接重置／中止或超时重试一次（最多两次打开，间隔 0.5 秒；首次打开超过 30 秒不再重试）。每次重新创建请求并继续校验官方 HTTPS／重定向域名；socket 超时为 15 秒，DNS 和多跳重定向可能增加总耗时，这不是整项下载的硬性墙钟截止时间。此策略共用于普通安装、下载检查和仅更新；不重放读取中的响应或任何助手／启动／重连操作。

证书校验失败（包括 URLError 包装）、未知 SSL 错误、HTTP 错误、信任校验、摘要／JSON／归档错误和本地磁盘错误不重试，不改 CA、不绕过 TLS，也不回退到未验证下载。已开始写入的临时文件不重放；专属工作目录按原规则清理，已有目标文件保持独占创建保护。

诊断只显示固定异常类别及已识别的 SSL reason，不输出原始异常中的 URL／签名参数。仅在已知下载／验证边界失败时，明确提示**本次未执行助手安装、二进制发布、WebUI 信号或核心重连**；历史 UNKNOWN／pending 回执仍保留，不能据此清除或重复发送。已进入后续安装／重连阶段的失败仍保留原先的 UNKNOWN／只读核对提示。泛化的 `SSLError` 本身不能证明是证书错误。

## 安装完成后默认重连核心

```sh
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash
```

完整安装默认启用核心重连，无需手动添加 `--reload-core`；该参数保留为显式兼容写法。可用 `--no-reload-core` 明确跳过。`--check-download` 和 `--update-only` 默认始终不重连，且不接受显式 `--reload-core`。

安装后的这次重连默认遵循现有节点 TLS 配置，无需二次确认：内部 reload 请求固定 `allow_insecure: true`，仅允许节点已明确配置的 `skip-cert-verify: true`；不改写配置、不从旧进程参数继承权限，也不强制所有节点跳验。CA、完整叶证书 pin 和 SPKI pin 的原有校验及冲突拒绝规则保持；未启用跳验且没有 CA／pin 的节点仍按原规则失败。跳验节点不提供服务器身份保证。发行包／脚本下载的 HTTPS、DoH 和 Google 等目标站点 TLS 校验均不放宽。

默认完整安装时，安装器在替换助手之前读取当前 VPN 状态；仅当 VPN 原本正在运行，且程序安装、助手身份校验与 WebUI 就绪均成功，才请求一次受控重连。原本停止／首次安装时不自动启动。无法认证状态或配置／进程身份发生变化时停止，不猜测、不强制重连。重连期间网络可能短暂中断；该选项不承诺旧核心私有快照备份或自动回退。

重连使用独立后台 worker 和私有持久回执，避免终端／SSH 断开造成重复控制请求。成功必须核验本次操作、新核心来源和运行状态；超时、断连或回执身份不明记为 UNKNOWN，保留输出的事务目录，**不要为了取得回执重复运行安装命令**。安装成功、核心切换成功和实际网络／浏览器验收是分别的结果；184 等目标机的真实原生安装与网络仍需本机测试。

只有严格证明为**停止旧核心之前的助手预检拒绝**时，一键安装器会自动对账解除阻断，**不归档、不删除事务目录、不重发旧请求**。完整安装（包括 `--no-reload-core`）及仅更新模式均在安装独占锁内先检查历史回执；没有历史事务时不增加助手读取。对账要求原 `response.json` 为 root-peer IPC worker 留存且与 job／intent／UNKNOWN result／claim 严格绑定的 `PREFLIGHT_FAILED`、`HELPER_PREFLIGHT`、`PREFLIGHT_REJECTED`，没有 stop／start／cleanup／receipt 写入证据；同时核对当前用户程序与助手的完整 SHA／tag／配置物理路径身份、本次开始时捕获的当前配置及选择文件摘要、完整进程清单及 worker 已退出。不要求当前内容或核心 PID 与历史相同，不恢复旧配置。若当前 VPN 正在运行，安装器在同一安装锁内主动请求一次 STOP，然后要求助手确认未加载未运行且清单确认核心为空，才继续对账和安装；已停止时不发送 STOP。此恢复路径保持 VPN 停止，后续安装不会因此自动启动，用户可安装完成后自行开启。

对原 operation 发出一次只读 `startup.read`：若旧 timeline 仍在，必须是完整无丢失 HELPER 预检失败流；缺少 CORE 观察造成的全局 gap 不等于 HELPER 流缺失。若已被后续手动停止等操作轮换，只接受同助手 epoch／配置身份的严格 `OPERATION_MISMATCH`（新 operation、trace=null）；mismatch 本身不是失败证据，停止前拒绝的 authority 仍是同一完整助手二进制原先返回并持久化的严格 response，不支持无 response／发送超时等泛化 UNKNOWN。助手 epoch、用户程序／助手完整二进制或配置物理路径变化、本次检查中当前配置／选择再次变化、无法确认核心停止、活动 worker、证据不全或畸形均继续阻断并要求核对。

主动停止使用独立新 operation，先独占持久写入 `stop-intent.json` 再发送一次 root-peer 认证的 STOP；保留回复和精确 operation 的 `startup.read` 停止成功证明。超时／丢失回复不盲目重发，后续仅读取同一 operation，并确认当前助手及空核心清单；无法确认则保留 pending。只读检查共享约 25 秒预算，各 IPC／进程读取使用剩余超时，写 marker 和删除 pending 前均检查预算；STOP 本身另有 300 秒请求上限，不承诺所有文件系统阻塞的硬总时限。

成功对账只独占写入 `reconciled.json`，状态为独立的 `RECONCILED_PREFLIGHT_REJECTED`（不是 `SUCCEEDED`／`accepted`），包含原回执摘要、operation／epoch、助手只读回复、独立 STOP 证明摘要（若有）与当前 STOPPED 状态／当前配置 pin；历史 config／selection 摘要仍保留在原 job 中；文件及目录 fsync 并读回后，最后才删除本事务的 `pending.json`。原 job／intent／response／UNKNOWN result／claim 字节保持，整个目录原地保留。后续 guard 重新核对所有绑定摘要；回执被改动／删除、对账写入／同步／读回失败或 pending 因崩溃重新出现都保守阻断，不自动重写或继续未确认的提交。旧 SUCCEEDED 但未经原父进程 accepted 的事务仍不自动清除。仅安装脚本变化，不修改 `VERSION`、Go 核心或既有二进制包。

该功能由可信 main 安装脚本提供，不改变既有 `v2026-11-04-01` 二进制包；`--version` 固定下载包，不固定安装脚本版本。

## 仅验证下载

```sh
python3 -I scripts/install-binary.py --check-download
python3 -I scripts/install-binary.py --check-download --version v1.2.3
python3 -I scripts/install-binary.py --check-download --arch amd64 # 仅校验Intel包，不执行
```

本地需同时保有可信 `scripts/install.py`。检查模式不启动任何子进程：macOS默认按当前Python进程架构选包（Rosetta下可用`--arch arm64`指定检查原生包），非macOS默认arm64；实际安装才通过sysctl确认硬件，不能将探测失败当作Intel。
检查模式可在非 macOS 上运行，使用
临时目录只下载并校验当前架构二进制包与 `SHA256SUMS`，验证包结构、版本、manifest、
Mach-O 头及二进制摘要；输出 JSON 的 `download_verified: true` 和
`executed: false`。**不运行二进制、不调用 helper、不创建应用目录、配置或 PATH
链接**。临时树退出即清理；可设置 `TMPDIR` 指定临时目录。

此模式只证明发布内容与其 HTTPS 下载的校验材料一致，不证明 macOS 可执行、
助手权限安装、真实 TUN、WebUI 或网络行为。安装前的 `version` 命令不属于检查
模式。

## Release 合同

双架构稳定 tag 提供以下六个精确附件；**默认安装仅下载 `SHA256SUMS` 和当前架构的二进制包**，不下载或要求源码附件。源码仍在 Release 单独提供，不影响默认安装；没有二进制的旧 source-only Release
明确失败，不会回退编译：

- `anytls-core-TAG-darwin-arm64.tar.gz`
- `anytls-core-TAG-darwin-amd64.tar.gz`
- `anytls-core-TAG-source.tar.gz`（精确应用源码、构建脚本及补丁）
- `anytls-core-TAG-corresponding-source.tar.gz`（应用源码、实际链接依赖源码和 Go 源码）
- `anytls-core-TAG-darwin-amd64-corresponding-source.tar.gz`（Intel产物的独立对应源码与构建身份）
- `SHA256SUMS`（上述五个归档必须各有唯一 SHA256 行）

所有初始 API 和附件 URL 固定官方仓库及精确 tag；附件仅接受可信 GitHub HTTPS
重定向域。二进制包前缀必须为 `anytls-core-TAG-darwin-ARCH/`（ARCH 为 arm64 或 amd64），至少包含：

```text
bin/anytls-macos
VERSION
BUILD-INFO.json
config.example.yaml
LICENSE
THIRD_PARTY_NOTICES.md
```

允许附带 `licenses/` 等额外普通文件，但不执行它们。`VERSION` 必须为 plain
`TAG`（可有一个末尾换行），`BUILD-INFO.json` 至少包含：

```json
{"source_commit":"<40位小写Git commit>","binary_sha256":"<64位小写SHA256>"}
```

重复 JSON 字段拒绝；`source_commit` 必须等于官方 `/commits/TAG` 的结果；
`binary_sha256` 必须等于流式计算的实际文件摘要。二进制要求与选定架构一致的 thin arm64 或 x86_64
Mach-O executable 头；`BUILD-INFO.json.platform` 也必须为对应 `darwin-ARCH`；这不替代 macOS 平台加载及实际执行。归档流式展开，拒绝
越界、错误前缀、重复成员、file/directory 碰撞、符号/硬链接及特殊文件；不继承
可执行位。源码包不参与默认下载、检查或安装；需要源码时从同 tag Release 单独取得。

## 安装顺序与更新边界

固定普通用户路径如下，不提供任意系统目录覆盖选项：

- 二进制：`~/.anytls/anytls-macos`
- 配置：`~/.anytls/config.yaml`
- PATH 链接：`~/.local/bin/anytls` → 上述二进制
- 旧二进制备份：`~/.anytls/backups/`
- 本次二进制包、包内许可证／manifest 与 SHA256SUMS：
  `~/.anytls/releases/TAG-<随机标识>/`

先拒绝应用目录 symlink、已有非普通目标/配置，以及与其他程序冲突的 PATH
入口。全部下载验证成功后，将候选复制为同一 appdir 内随机的普通文件
`.anytls-bin-candidate-*`，赋 `0700` 后执行 `version` 校验精确 tag。
已有配置原字节保留；首次仅复制包内真实 `config.example.yaml` 为 `0600`，
不生成假节点/凭据。仍需输入实际服务器、密码与 CA 等信息才能正常使用 VPN。

在任何 root 安装之前创建/检查 CLI 链接；初次安装时它会暂时指向尚未发布的
目标。候选以 `/dev/tty` 为 stdin 执行 `helper install`，由原生 sudo 授权；
该命令的认证 readiness 和随后的普通用户 `helper status` 都成功后，才先备份实际旧
二进制，再原子发布并再次执行 `version`。最后一次 status 必须是单个严格 JSON 对象，
包含现有八个必需字段（仅允许附加现有 schema 的 `diagnostics`），拒绝重复、未知、缺失、
null 或错误类型字段；同时要求 `ok=true`、空 `code`，助手 SHA256 等于候选完整文件摘要，
助手版本等于发行 tag，配置身份等于正式 `config.yaml` 的规范绝对路径 UTF-8 SHA256
（与 Go `controlHelperConfigIdentity` 一致，不是配置内容摘要）。候选位于同一 appdir，
其兄弟配置与正式配置身份一致；发布前再次核对候选字节与配置身份。退出零但空输出／
畸形回执或任一身份不符均不发布、不自动重试助手安装、不重启 WebUI；只输出固定错误码，
不输出回执或配置内容。`loaded`/`running` 必须是布尔值，但不要求 VPN 已运行。
完整安装默认按上文条件重连原本运行的 VPN 一次；`--no-reload-core` 跳过，原本停止时不启动。仅更新用户程序的 `--update-only` 路径仍不重连。

二进制归档校验成功后，先保留并读回核对包内许可证、NOTICE 和程序身份材料，以及二进制归档与校验和；保留失败不会执行候选或改变旧程序／配置。不下载应用源码或对应源码归档，也不删除以前安装保留的源码。随后将候选复制到同一 appdir 内并验证版本。
安装不是跨用户文件和 root helper 的原子事务：首次创建的配置/链接可能保留；helper 已成功后
若备份/发布或最终 version 失败，helper 或用户二进制可能已经
更新。不要把失败当作自动回退；检查 `anytls helper status`、当前
`anytls version` 与备份后再决定恢复或重试。安装/重启阶段持有
`~/.anytls/.install.lock` 的非阻塞独占锁（拒绝符号链接、权限 `0600`），
并发安装器会明确失败。

**安装成功默认重启已有 WebUI，首次安装也会启动。**
手动启动的 WebUI 在本次安装／重装中默认绑定 `0.0.0.0:18089`（浏览器使用实际主机地址，本机仍可访问 `http://127.0.0.1:18089/`）；其旧 `--listen` 只用于身份核验。需要仅本机时，本次显式传入 `--webui-listen 127.0.0.1`。不迁移或停止其他端口的 WebUI。

已有 `--managed-agent` 的 WebUI 使用单独的托管路径：核对当前 UID、完整 PID/启动时间/命令、按程序与配置规范路径派生的 label、固定 plist 和现有 `webui agent-status` 的已加载任务验证；单独一个 managed flag 不建立权限。保持现有 plist、托管监听参数和启动方式，不卸载任务、不创建并行控制台。如果本次指定／默认监听与现有托管监听不一致，在助手安装和程序替换前拒绝迁移。安装成功后只对再次认证的旧 WebUI 请求一次 SIGTERM，由既有 KeepAlive 拉起磁盘新程序，读回新 PID、托管状态及真实 HTTP 页面就绪。超时或身份漂移不强杀、不重复重启，也不继续核心重连。
在 helper 安装及发布前，使用系统 `lsof` 查询 18089 监听 PID，并通过完整
`ps` 信息核对当前 UID、启动时间和精确目标路径命令；接受
`~/.anytls/anytls-macos webui`，可带一次 `--port 18089` 和一次 `--listen 192.168.5.2`，
两者顺序不限，也支持 `--port=18089` / `--listen=192.168.5.2`。这些旧参数只用于身份识别。新进程使用本次安装的 `--webui-listen`，省略时为 `0.0.0.0`。
listen 接受规范 IPv4 字面量，保留 `0.0.0.0` 通配、回环、私有或公网显式绑定；
不接受 DNS、IPv6、CIDR、zone 或附带端口。
规范地址拼写另作字符串比对，不依赖旧 Python 对前导零的宽松行为。
重复 flag、缺值、其他端口、位置参数、引号或 shell 表达式一律拒绝；
不将 `ps` 命令文本当作可执行 shell，目标路径（包括空格）必须精确匹配。
外来占用、多监听或未知参数一律拒绝继续，不根据 basename、子串或历史
`webui.pid` 杀进程；历史 pidfile 完全不作为权限依据，也不更新它。

仅在 helper 安装/status、原子发布和新目标 version 都成功后，重新核对旧进程
身份与启动时间，向明确识别的旧 WebUI 发送一次 `SIGTERM`，有界等待旧进程
消失且端口空闲（托管模式则等待认证的 KeepAlive 新进程）；身份变化不再发信号，超时不使用 `SIGKILL`。helper 失败不会
关闭旧 WebUI。手动模式新进程以 `webui --port 18089`（追加本次 `--listen 地址`）独立会话启动，stdin 为 `/dev/null`，
stdout/stderr 追加到 `0600` 的 `~/.anytls/webui.log`。必须确认监听 PID 等于
新子进程 PID，且首页 HTTP 200 含实际控制台标记，并再次确认端口归属，才报告成功。
显式地址使用同一地址探测；通配监听保留 `--listen 0.0.0.0`，但就绪 URL 使用具体的 `http://127.0.0.1:18089/`，不访问 `0.0.0.0`。
新版 WebUI 校验显式地址确实分配给本机网卡；通配地址跳过接口分配检查。本次显式选择的地址失效会启动失败，不自动回退 loopback。
默认网络 HTTP 无 TLS，凭据与会话未经传输加密；请用防火墙限制来源或配置可信传输保护。网络访问控制由部署环境管理。安装器会将已识别的手动旧入口切换到本次指定地址／默认全网卡；已托管 LaunchAgent 不自动迁移。`--check-download` 与 `--update-only` 不接受 `--webui-listen`，因为这两种模式不启动／迁移WebUI。

如果发布后无法停止旧 WebUI 或新版启动/就绪失败，会返回非零并明确报告
`binary installed but WebUI start failed`；二进制已经安装，不伪称整笔回滚。
启动失败只尝试 TERM/等待本次创建的子进程，不操作未知 PID。请检查日志、端口及
`anytls version` 后重试。WebUI 重启会清空登录会话，需重新登录；既有应用密码、
节点密码和配置仍保留。

**完整安装默认在安装成功后受控重连原本正在运行的 VPN；原本停止时不启动。**
使用 `--no-reload-core` 可保留运行中的旧快照，之后何时显式重连由用户决定。下载检查与仅更新模式不重连。此行为由可信 main 的 Python 安装器实现，不要求新二进制 tag。

## 安装进度

公开 shell 在下载两个可信安装组件时显示阶段和 curl 进度条；进入 Python 后，6个阶段分别提示附件下载、安全解压及身份校验、材料保留、系统助手授权、备份替换和 WebUI 就绪。

每次 API／附件请求立即提示文件名；连接和接收数据时每约5秒输出已收字节、总大小（Content-Length可用时）和耗时。0字节表示尚未收到可交付给读取循环的数据，不保证网络毫无传输；这是接收状态，不是伪造百分比或剩余时间。原有网络读超时保留，不将缓慢但持续接收的数据冒称超时失败。

进度仅写stderr并及时flush，`--check-download` 的stdout仍为原有JSON。下载“完成”指传输结束，所有附件SHA通过后才显示第2阶段；系统密码只在本机Password提示处输入且不回显。失败／取消会标记，不打印密码、认证头或签名重定向查询。

已启动的旧安装进程不会动态加载新脚本；不要为了看新提示而同时启动第二个安装器。等待当前结果，或自行取消后再重跑。

## 本地单元验证

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/install_binary_test.py
```

测试使用实际临时 tar/文件及模拟 transport/subprocess/HTTP，禁止真实网络和
未模拟的 subprocess.Popen；覆盖校验材料、URL、路径、版本、manifest、候选权限、
配置保留、链接冲突、助手失败及真实备份/原子发布文件操作，并覆盖 WebUI 首次
启动/安全重启、外来 UID/路径/参数、陈旧 pidfile、启动时间变化、TERM 超时、
子进程退出、错误监听 PID、HTTP 标记与就绪竞态、失败清理及安装锁。属于
**UNIT-SIMULATED**，不是一次真实 macOS 特权安装验收；仍需真实 Mac 上验证系统
lsof/ps 输出、官方二进制启动和 VPN 运行状态不变。
