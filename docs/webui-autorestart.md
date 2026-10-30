# 用户级 WebUI LaunchAgent 与更新重启

本功能只托管 Web 控制台；不安装/重载 helper，不启停或重载 VPN，不修改系统 DNS、代理或路由。开发验证不是正式部署。

## 首次启用（需用户明确执行）

先取得包含本功能的可执行文件。旧 WebUI 的旧内存代码不能因为磁盘升级就获得自动重启能力。保留配置、选择、密码以及更新器已有备份；通过原终端 Ctrl-C 或已核实的原 WebUI PID 停止旧控制台，**不要执行 VPN stop，也不要使用 pkill**。确认地址空闲后，以普通登录用户运行：

```sh
/path/to/anytls webui install-agent --listen 127.0.0.1 --port 18089
/path/to/anytls webui agent-status --listen 127.0.0.1 --port 18089
```

LAN/全 IPv4 绑定使用原来的字面 IPv4 和端口，例如 `--listen 192.168.1.20 --port 18089` 或 `--listen 0.0.0.0`；不会迁移旧监听或悄悄退回 loopback。HTTP 无 TLS，网络访问仍会明文传输凭据。动态 LAN 地址失效时应显式停用后重新选择地址。

安装仅使用 `gui/<当前UID>`，需要该用户已有 GUI 登录域；不使用 sudo、LaunchDaemon 或 system 域。程序路径解析符号链接后固定，配置是其同目录 `config.yaml`。label 是 UID、程序绝对路径、配置绝对路径的 SHA-256 前缀，因此不同隔离目录不会共享任务。

plist 位于 `$HOME/Library/LaunchAgents/com.anytls.webui.<摘要>.plist`，安装成功输出完整 `target` 和 plist 路径。文件为普通用户所有、私有权限；拒绝路径上的符号链接、group/world 可写目录/文件和 foreign owner。现有 plist 只有字节完全符合本工具生成合同才可复用；不会覆盖或删除 foreign/修改过的文件，不清理备份。通过同目录临时文件、fsync、无覆盖原子 link 发布。已加载任务会报错要求人工检查，而不是强制替换；占用监听地址也会报错，不杀进程。bootstrap 失败会保留 plist，不能把这解释为 WebUI 已运行。

## 停止与保留证据

`agent-status` 输出 JSON `target`、`plist`、`pid`、`restartManaged`。状态以实际 launchd 和文件核验为准，不以 PID 非零当成功。

停止自动拉起必须 **bootout**，使用安装输出的完整 target：

```sh
launchctl bootout gui/501/com.anytls.webui.<安装输出的摘要>
launchctl print gui/501/com.anytls.webui.<安装输出的摘要>
```

第二条应报告未找到任务。不要把上面的占位摘要照抄；使用真实输出。只发 SIGTERM 会被 KeepAlive 重新拉起。bootout 不删除 plist、配置、密码或备份；保留 plist 意味着下次 GUI 登录仍可重新加载。需要停用未来登录启动时，bootout 成功且确认精确任务未加载后，由用户明确将输出的 **这一个 plist** 移到 LaunchAgents 之外的私有备份目录；本版本不自动删除或移动证据。恢复时将原字节移回，再显式运行 install-agent。

## 网页更新合同

- 原有独立更新 CLI 子进程的 Run/wait、磁盘版本读回和 `actionMu` 均保留。断连不取消已开始的安装。
- `GET /api/v1/update-check` 追加布尔 `restartManaged`（每次实时核验）和 `restartScheduled:false`。已有需登录的 `/api/v1/version` 返回当前进程的内存版本。
- `POST /api/v1/update` 追加布尔 `restartScheduled`。仅 `updated:true`、`status:UPDATED`、`restartRequired:true`、`installed==latest` 且版本是合法稳定版本时才尝试重启。
- 启动及每次准备重启均核验本进程 PID 与 launchd 直接字段一致，并核验 plist 精确字节、程序/argv、listen/port、UID、配置路径、运行域、任务类型、running、KeepAlive/RunAtLoad。`--managed-agent`、HOME 和其他环境变量都是 locator，不是权限证据；手动伪造 flag 不能冒充任务。
- 原生守卫失败仍保留安装成功 HTTP 200/`updated:true`，并返回 `restartScheduled:false,restartError:RESTART_MANAGED_UNAVAILABLE`，旧控制台继续运行。手动启动永不自动退出。
- 成功准备后先序列化并 Flush；写入或 Flush 报错就撤销退出请求。Flush 只证明本地写入完成，不证明浏览器收到。发出异步请求后退出 handler，owner 停止新请求准入，等待所有已有 handler 结束，才执行 Shutdown；不在 handler 内等待自己，不调用 os.Exit，不自行 exec 第二个服务器。
- drain 每轮 15 秒，超时继续保留旧 listener/PID，拒绝新请求但等待已有动作安全结束；不会以超时为借口退出、遗弃安装子进程。plist `ExitTimeOut=0` 避免 launchd 默认 5 秒强杀已接收 SIGTERM 的活动安装。bootout 可能因此等待长任务，不能强制结束当作正常完成。
- 正常返回后 launchd KeepAlive/3 秒节流启动磁盘新文件。会话只在内存中，新进程会返回 401；重新登录后必须读回 `/api/v1/version==installed` 才能确认新版运行。安装成功、响应成功、进程重启和新版内存验收是不同结果。

## 已执行的原生开发验证

Darwin arm64、普通 UID501、独立 `/Users/lihaiyan/.ais2/webautorestart-dev01`、独立 HOME/程序/配置/loopback 高端口。通过仓库官方 `scripts/go-patched.py`、指定 Go1.27.3 和完整 canonical tags 构建/测试；没有 raw go build/test、正式安装或 VPN/helper 重载。

1. 手动构造器真实 HTTP 更新合同：旧代码缺 `restartScheduled:false` 的业务 RED；实现后 GREEN，原控制台继续可用。
2. 托管 hook 的业务 RED（未调 guard、未 Flush/未 schedule）→ GREEN；guard 失败保留安装成功。其余安全/边界测试为补充覆盖，不能统称 test-first。
3. 真正的独立 LaunchAgent：普通程序安装/实际 launchctl 直接字段核验、登录和内存 version、SIGTERM 后 KeepAlive 换 PID、伪造手动 flag 拒绝、bootout 后任务消失且 plist 留存。
4. 两个官方 wrapper 构建的 **测试专用** 可执行映像，真实 launchd+HTTP+更新器 Run/wait/readback+旧 server drain+进程退出+新 PID+登录/version 全链路。只替换外部网络安装 seam 为隔离映像原子替换（TestMain 仅在 `_test.go`）；未从网络下载正式发布。失败安装保持 PID39678；成功响应完整 `restartScheduled:true`，新 PID39739，旧 cookie401，新内存 v1.0.1。old SHA `fa99b3d71a4809bdc299f92ea1a7240c23e09b52dcd8c36d98ad26b2a5bdaf36`，new SHA `2a6825467b5257d3f1090adaf2365f2696bce020d9280d2f119b5f3cb4cd82af`。

历史生命周期验证的 `native-home` plist 未包含最终的 `ExitTimeOut=0`，加载任务显示 exit timeout=5。因此以下历史测试支持先前的重启链路，不构成最终超时策略的真实 launchd 验收；最终配置的活动请求保留和 bootout 行为须在新隔离 attempt 中另验。原失败与原件保留。

原始日志和回执保存在上述隔离根目录：`backend-red-business2.log`、`slice1-green.log`、`slice2-red.log`、`slice2-green.log`、`backend-runtime.log`、`backend-security.log`、`backend-build.log`、`native-*.log/json`、`acceptance-*-build2.log`、`acceptance-result.json`、`acceptance-protected-{before,after}.json`。早期 wrapper 参数拒绝日志单独保留，不算业务 RED。进程保护清单前后相同，两个隔离任务均已 bootout，配置和 plist 保留。该清单不等于 root 私有数据完整快照；正式服务/完整原生回归由独立总审查另做。
