# Web控制台托管与更新后自动重启实施合同

## 范围

用户确认开发此功能；基线83b88f8bbcca70c96aba43b7a07eaa502fa8d1c8。候选/workspace/anytls-webui-autorestart，分支feat/webui-managed-update-restart；不修改已发布版本，不在目标Intel或正式Mac上安装、迁移监听、更新helper、改配置/系统DNS、重载VPN、自动推送发布。用户级LaunchAgent的隔离验证允许用唯一label/目录/端口，必须收尾读回。

## 最小产品合同

- 新增显式一次性控制台托管CLI，采用gui/当前UID LaunchAgent，普通用户，无sudo。历史合同默认loopback，当前监听候选改为默认0.0.0.0（仅新建或省略参数；已有显式绑定不自动迁移）；原LAN监听地址和端口通过显式参数保留，禁止悄悄改变入口。旧手动进程占端口则报冲突，不自动kill任何PID。
- LaunchAgent固定程序argv/路径/label，KeepAlive和ThrottleInterval；命令只控制WebUI。注册前检查路径/文件owner/权限/symlink/foreign任务，原配置/选择/密码保持。
- 网页更新保留已有子进程wait、独立版本读回与actionMu；安装失败不退出，readback不确定不退出。成功后重新确认此进程确属预期launchd托管任务，才能返回restartScheduled=true并安全结束旧server；仅env/flag不得证明托管。
- 回复先序列化/flush，server停止接收新变更并graceful drain；不得在handler内os.Exit，不自行并行启动第二个Webserver。不以flush成功证明浏览器已收到。
- 手动/后台nohup进程不自动退出；明确仍需迁移托管/手动重启。KeepAlive单独不构成更新重启。
- 前端仅在实际返回restartScheduled时有界等待同源服务恢复；成功必须读回内存version==installed。401显示需重新登录，下一次登录再核version；不能把401/HTTP200/启动进程当新版验收。等待失败保留已安装状态，不自动重复安装。
- 会话/退出/新请求使旧异步回调失效；不把密码/token存URL或sessionStorage。仅可保存带到期时间的期望公开version用于重登录后验证。
- CLI普通update不暗中操控其他进程；本轮自动退出钩子在网页受管更新路径。第一轮旧版升级不能反向获得未存在的退出代码；文档说明首次启用托管步骤。

## 父批准的外部卸载边界澄清

独立裁决 `lifecycle-stop-decision/REVIEW.json` 建议最小方案 A，父接受：本次承诺是应用自身的更新重启和普通 SIGTERM 安全等待，不包含外部强制卸载、强杀、崩溃或系统关机。真实 bootout 已在 ExitTimeOut=0 下立即中断活动安装，原 FAIL/采样不可改判；CLI/文档必须在停止指引之前警示仅空闲使用且不构成原子安全停止。保持 Run/wait/readback、失败不退出、Flush 后调度、完整排空、会话重新登录和内存版本门禁不变。不新增 agent-stop/disabled-state 机制，未执行的替代停止方案不得宣称可用。

## 验收顺序

1. 每个行为切片先取得对应旧版业务RED，不以编译缺符号当RED；原日志保留。
2. backend/CLI实际Mac官方wrapperfocused和所有受影响测试；前端真实Node VM执行，边界和过期会话负例。
3. 合并冻结后完整原生test/vet/build、独立实现审查；若改动使freeze变化，重跑受影响门。
4. 隔离真实launchd/listener/HTTP/auth+更新→回复→旧PID退出→新PID→内存版本读回，失败路径不退出；protected生产前后相同。无GUI/domain不可用则明确NOT_RUN不能代称生产就绪。
5. 发布和正式安装另列，未执行不声称。

## 所有权

backend worker：main.go/webui.go、新webui_agent*.go及相应Go测试、docs/webui-autorestart.md。
frontend worker：web_assets/{app.js,index.html,API.md}、新scripts/web_update_restart_test.*。
父：本合同、统一review/nativecloseout。各worker只提交自有路径，不gitaddall，不改历史证据。

## 交付口径

代码、实际测试、冻结commit和限制；不得把计划、模拟LaunchAgent或未执行的重启包装成已交付能力。公开发行成功≠目标机已托管，受管控制台新版本≠VPN核心/助手新版本。
