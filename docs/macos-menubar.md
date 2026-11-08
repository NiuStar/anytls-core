# AnyTLS macOS 菜单栏客户端 0.4.3

原生 Swift / AppKit 统一 App 0.4.3（build 0.4.3.20261108.1），发行标签 `v2026-11-08-01`，macOS 13+、**Apple Silicon arm64 与 Intel x86_64（发行名 amd64）**。包内携带同一 Go 核心（CLI / 控制台 / 固定特权助手角色），没有第二个 VPN 引擎。保留菜单栏双行流量、显式启动/停止/重连、启动节点、完整控制台；不包含登录／连接设置窗口，也不读取钥匙串。

从本标签 Release 按芯片下载 `anytls-core-v2026-11-08-01-menubar-darwin-arm64.zip` 或 `anytls-core-v2026-11-08-01-menubar-darwin-amd64.zip`，解压、拖入「应用程序」并打开，通过菜单「安装／更新组件…」完成准备及必要的 macOS 原生授权，无需终端；首次安装不启动 VPN。0.3.1 用户先用旧 App 正常退出并停止 VPN，再替换 App。稳定标签导致核心映像身份变化，仍须从新 App 主动安装／更新，不能承诺只换 App 即可直接用。签名为 ad-hoc，未 Developer ID 签名或公证；Intel 与 Apple Silicon 使用各自原生包，不混装。旧终端一键安装及双架构 CLI 保留，发布本身不替换用户服务。

组件生命周期使用独立私有根目录中的 0600 `lifecycle.lock` 内核排他 flock；校验物理父目录、所有者、普通文件与单链接，不跟随符号链接，不删除或偷取锁。竞争 App 在 prepare、授权、STOP、TERM 前拒绝。锁覆盖异步操作至本次完成；崩溃释放内核锁但不清除持久 UNKNOWN/ARMED/ACTIVATION_UNKNOWN。仅有锁文件的安全目录不代表授权记录；未知目录成员、读权限错误保持 HOLD。正常退出 drain 失败仅撤销该次 ready 证明；下次 Quit 必须新鲜 STOP。原生受控进程测试不代表真实 launchd KeepAlive、管理员授权或 VPN 路由验收；用户需另行在本机接受这些关卡。

**受控迁移与验收边界**：规范 `~/.anytls/anytls-macos` 的旧 0700/0755 组件通过包内 Go 的 migration-inspect → 用户确认 → migration-commit → 固定暂存助手授权 → migration-finish 更新。旧文件名 `~/.anytls/anytls`、双叶、非规范目录、未知事务、未知监听保持 HOLD。Go 独占一次 STOP 和规范文件发布，GUI 不再重复 API STOP。保留原配置、选择、应用密码及相对 CA/规则；原运行中的 VPN 在更新后保持停止，菜单提供「恢复 VPN…」。这是为消除异步更新完成后延迟弹窗而有意改变的恢复策略；恢复须由用户点击并立即确认 TLS 风险，绝不后台发送 true。已有候选隔离 Swift 五套 502 项断言（95＋236＋49＋54＋68）和 Go 3427 项 PASS 记录；稳定标签的最终 native／CI／公开附件核验待对应提交收据，不能直接继承为稳定版通过。真实管理员首次安装、手动／托管控制台迁移、正式 VPN 退出后的路由／DNS 恢复及生产浏览器端到端均 NOT_RUN。

## 主动初始化与正常退出

菜单首个可执行操作「安装／更新组件…」执行包内 `desktop prepare`，再执行固定已准备 runtime 的 `desktop inspect`。校验包 SHA 清单、准备后 SHA、UID、系统账户 HOME、固定 binary/config、路径 identity、endpoint、bind、版本和状态；只有 `helper_state=missing` 才通过 `/usr/bin/osascript` 原生管理员授权执行固定 `helper-install-root UID HOME`。不会接收、保存或记录系统密码。每次授权前将精确 operation/stage/SHA、控制台 PID/UID/出生时间/argv、恢复选择写入独立 `~/.anytls-desktop-state` 0700 目录的 0600 JSON，并 fsync/rename/fsync；不保存密码。部分首次准备也持久阻止重放。重启 App 不清除 ARMED/UNKNOWN；下一次主动操作只读 inspect 并尝试 Go finish 的新助手就绪检查，不重发 STOP 或系统授权。只有原生明确用户取消 (-128) 记 DENIED，单独菜单「重试已取消的授权…」在重新核对后授权一次；其他错误/超时不能证明 root worker 已结束，保持阻塞人工核实，不提供假恢复。恢复 START 前另写 ACTIVATION_UNKNOWN，丢失回执跨重启不自动再启动；显示“组件已安装，恢复结果未知”。

正常启动不弹窗，仅尝试匹配已准备组件；不自动 prepare 或授权。拒绝未知端口监听。既有托管控制台必须由规范旧 binary（不是 bundle binary）返回真实 `webui agent-status` JSON，并通过 Go 的精确 plist/launchctl 策略校验，再核对 lsof UID/PID、proc_pidinfo 出生时间和 proc_pidpath/KERN_PROCARGS2 精确可执行路径与 argv。未知所有权在 commit/STOP 之前 HOLD。更新发布后只对事前绑定旧进程单次 TERM；托管 KeepAlive 按原批准 plist 自行拉起新 binary，GUI 不启动第二个子进程；等待新 PID/监听、同一策略和认证 `/status` 的 version/listenHost。手动控制台仅接受规范可执行路径与 webui 子命令、完整且各一次的固定参数键值对；--listen 与 --port 可交换顺序，进程原始 argv 的身份绑定不变，无托管 job/plist，TERM 后等监听消失再启动自有 Process。不用新磁盘 SHA 冒充旧进程映像 SHA，不 SIGKILL/bootout 共享控制台。普通退出保留托管控制台空闲，只 drain 自有子进程。新控制台只允许自有直接 Process、`0.0.0.0:18089`，预先检查 launchd 与端口，再验证自有子进程绑定。应用密码仅经匿名私有管道进入内存，登录后检查认证 `/status` 的版本和 listenHost，不写入文本框、偏好设置、日志或证据。普通启动不查询钥匙串；不再提供手动应用密码入口。只有上述精确验证的手动／托管既有控制台可复用，未知监听仍拒绝。

「退出并停止 VPN」及 Cmd-Q 经 NSApplication 的 terminateLater → 保留的 QuitCoordinator。即使看起来已停止，也须认证 STOP 的成功清理回执和停止读回；UNKNOWN/失败拒绝退出且不盲重试。成功后仅 TERM 自有控制台并异步有界等待退出，不杀共享控制台，助手保留安装且空闲。全新未安装退出须独立检查固定 helper/runtime/snapshot 不存在和两个固定 system launchd label 明确不存在；部分安装不走此例外。强杀不能保证收尾。

## 构建与手动使用

在装有 Apple Command Line Tools 的 Mac 上，从仓库根目录运行：

```sh
CORE=/absolute/path/to/qualified/arm64/anytls-macos bash scripts/build-menubar.sh arm64 ./macos/build
./macos/build/test/AnyTLSMenuBarTests
open ./macos/build/AnyTLSMenuBar.app
```

架构为 `arm64` 或 `amd64`，分别仅在对应原生 Mac 上构建和验包；拒绝跨架构／universal 核心，防止 App 与内嵌核心架构不一致。Intel 使用 `CORE=/absolute/path/to/qualified/amd64/anytls-macos bash scripts/build-menubar.sh amd64 ./macos/build`。必须提供显式本地 CORE，不下载。构建使用 Swift 6.1.2 的 Swift 5 语言模式、macOS 13 deployment target，无第三方依赖；先 ad-hoc 签核心、生成实际签后 SHA 清单，再签 App 并严格验证。**不是 Developer ID、公证或 Gatekeeper 放行证明**。

构建不执行安装或授权。App 为 LSUIElement，无 Dock 图标，不注册开机启动；核心版本来自显式 CORE 的纯 `-version`。发行包验证需 ZIP 解压后再次 codesign --verify --strict --deep。沿用 `org.anytls.menubar.candidate` 作为既有 bundle identity，不因其历史名称更换身份；这不表示当前 App 使用钥匙串，也不是 Developer ID 认证。对应源码附件为 `anytls-core-v2026-11-08-01-corresponding-source.tar.gz`（arm64）或 `anytls-core-v2026-11-08-01-darwin-amd64-corresponding-source.tar.gz`（Intel），许可证／NOTICE 随包保留。

## 无窗口自动连接

- 已完成安装且核心／助手匹配时，启动 App 自动验证本机控制台身份，通过 `desktop credentials` 的匿名私有管道取得应用凭据并建立内存会话；无需应用密码输入，不查询钥匙串，不读写剪贴板，不保存密码。
- 首次未安装、旧核心不匹配、旧文件布局或未知监听只显示菜单提示「组件待初始化」，用户须主动点「安装／更新组件…」。**移除的是 App 登录窗口，不是 macOS 原生管理员安装授权，也不是后端 HTTP／CSRF 或 helper UID 信任校验。** App 不获得 root 身份。
- 启动尝试一次；会话过期最多重新验证一次，失败不循环重试。所有连接尝试共享 singleflight 和 15 秒冷却；冷却后可主动「刷新状态」重试。pending／uncertain／退出及持久生命周期锁不能被自动登录清除。
- 没有 NSWindow／密码框／记住开关／粘贴入口／连接设置菜单；关于信息直接显示为菜单版本行。Finder reopen 不创建窗口。后台断网、恢复、睡眠／唤醒、路径变化、过期及迁移完成都只更新状态，不调用激活／modal。无法保证 Finder／OS 自己永不激活进程；验收计数限定 App 主动 presentation 调用。
- 显式启动／停止／重连／切节点／恢复及安装动作仍可立即显示必要确认。安装确认在用户点击时进行，而不是异步 inspect 完成后排队弹出。更新后 VPN 保持停止，点击「恢复 VPN…」后才确认并启动。
- 完整 Web 控制台仍在外部浏览器打开，其登录认证完全不变。默认控制台 `0.0.0.0:18089` 及回环管理连接不变。

登录采用隔离 ephemeral URLSession cookie store、CSRF token、Origin；流量请求同时携带 X-AnyTLS-Origin 与 Sec-Fetch-Site same-origin。URLSession delegate 拒绝所有 HTTP 重定向；不使用共享浏览器登录和缓存，不通过系统 HTTP 代理转发本机凭据。这里只接受本机回环 HTTP；并非对同机恶意进程的安全隔离。

## 状态与操作语义

- 原生客户端每 250ms 读取最新流量，已有请求未完成则不重叠；速率标签仅在显示值变化时重绘。配套核心按 250ms 节奏观察和有界变化发布，空闲心跳约 5 秒；旧核心约 5 秒采样，App 单独升级不改变旧核心采样。上述节奏不等于 UI 即时响应或最快性能承诺。显示 SDK 路由 payload 的采样区间平均速率，不是整机网卡。速率采用实际字节 / 单调时长，不用两次墙钟读取的差分。累计值先按 canonical UInt64 字符串精确校验，再将已验证的区间值转 Double 排版，保留超过 2^53 的累计精度。
- 仅显示 schema/header/source/instance/运行状态、区间、history 和 freshness 校验通过的未饱和流量；无速率、不可用、无效、未来时间或超过 15 秒即显示 `—`，绝不补零。提示可查看本实例精确累计字节。
- 状态、助手与节点约每 5 秒读取；每条路径只拥有一个未完成请求。GET / login 有绝对 7 秒本地 deadline（防慢响应体），服务修改约 188 秒；正常退出必须完成 STOP 和读回，再清理 timer/session。
- 确认运行后自动以系统 TLS／主机名验证访问 Google 与 Cloudflare 固定 HTTPS 204 端点，任一严格空体 204 通过则显示「网络已连接」，全部失败则显示「网络连接失败，请检查节点或网络」。拒绝重定向、响应体和不可信证书，不继承 HTTP 代理，不发送控制台密码／Cookie。检查为 OS 实际路由的网络连接，不能证明指定节点出口或 TUN 健康。检查最长 5 秒，不重叠，成功后至少 30 秒、失败后至少 15 秒再查；会话／服务变更取消旧代检查，启动／重连／应用后重新读取运行状态再查。助手不可用 / 状态未知 / 修改进行中时禁用修改按钮。
- 后台检查、断网、恢复、唤醒、网络路径变化和会话过期只更新菜单栏，不激活 App、不创建设置窗口、不弹警告或申请通知权限。网络检查失败时图标变红，菜单与提示保留失败原因；上传／下载仍显示。
- 菜单勾选表示**磁盘已保存的启动节点**，不是实时出口或所有分组的当前路由。需要同步默认组的节点可再次选。节点选择用读取时 JSON etag 作为 If-Match，确认后仍检查 session/etag；运行时由服务端自动应用，客户端**不额外发 reload**。停止时明确反馈“已保存，下次启动生效”。高级分组 / 规则通过完整控制台管理。
- 启动 / 重新连接 / 切换节点均显式确认潜在短暂断网及已有“跳过证书验证”配置风险，然后才发送 confirm_insecure；不会修改其他节点 TLS 策略。停止也需确认且 confirm_insecure=false。
- 同一时间一个修改。HTTP 200 本身不等于成功：分别校验 service loaded/running、SAVED_STOPPED、APPLIED、NO_CHANGE。202、断连、超时、无效回执、STARTUP_UNKNOWN、未证明应用等保持内存中的**结果未知锁**；绝不自动重试，也不因后续 plain running 状态就解锁。会话更新、旧 401 都不能覆盖新 session；过期时清 cookie/CSRF/观察值。
- 未知操作保留 startup_operation id（若有），但不把辅助 timeline 当权威成功证明；当前最小实现不自动读 trace 解锁。打开完整控制台核实并完成恢复；未知期间正常退出被阻止，不应靠退出绕过锁，也不能切换端点。请勿盲目重发。

## 安全隔离验收

```sh
# Foundation 模型、URLProtocol 传输与状态机测试；不运行 GUI 或核心
./macos/build/test/AnyTLSMenuBarTests
# 独立 URLProtocol 联网探测测试：无外网请求
./macos/build/test/ConnectivityTests
# 后台无抢焦点回归：真实生产 AppDelegate/AppKit，URLProtocol + 自有运行时／子进程；不触及正式钥匙串
./macos/build/test/FocusTests ./macos/build/focus-evidence
# 真 AppKit 离线 smoke：无登录、无 timer、无 API，只渲染 118×22 状态图标，不构造窗口
mkdir -p ./macos/build/smoke
ANYTLS_SMOKE_OUTPUT="$PWD/macos/build/smoke" \
  ./macos/build/AnyTLSMenuBar.app/Contents/MacOS/AnyTLSMenuBar --ui-smoke
```

smoke PNG 为 AppKit `cacheDisplay` 原生控件渲染，不是系统菜单栏实际屏幕截图，也不要求 Screen Recording 权限。真实 GUI 会话需要在 Mac 上运行；不能以 Linux 编译或截 HTML 替代。

另有 `AnyTLSMenuBarTests --integration`，由 opt-in `TestMenuBarNativeHTTP` Go fixture 启动，经 stdin 匿名管道接收 `{origin,password,evidence}`，只访问动态非正式回环端口（拒绝 18089）。它使用共享生产 APIClient 实际 URLSession；经真实 Go 路由验证 cookie/CSRF/Origin/ETag、精确流量、缺来源 403、停止时保存、启动、运行时自动应用、停止与读回。仅生命周期/遥测 seam 为合成测试；不安装、连接或控制正式 helper、VPN、launchctl。stdout 仅 `{ok:true,checks:N}`，具体断言保存在 fixture evidence 目录。

真实 Go 测试必须使用仓库现有 `scripts/go-patched.py` 与正确 build tags / Go toolchain；直接 `go test` 的 ACK patch 符号错误不是客户端业务失败。Intel x86_64 交叉编译成功不等于 Intel 原生运行验收；菜单命令真实 production VPN 端到端仍需用户明确授权后另验。

`Credentials.swift` 与 `CredentialsTests.swift` 只作为未编译的历史源码保留；shipping build 和本版本测试清单不包含它们。原生验证不涉及真实管理员授权、VPN、正式控制台、用户钥匙串或 WAN。
