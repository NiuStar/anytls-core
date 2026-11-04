# 节点卡片 R3 产品接入

- 设计基准：`/workspace/anytls-node-card-design-r3/index.html`，SHA-256 `70a24a48f7fcd8e0274d5d026faa50f897db74424f9f758eca07d47262c6def4`；仅提取视觉结构，不复制示例节点、协议、数量和延迟。
- `loadNodes` 仍是唯一列表读取者；搜索、请求/session 取消、配置失效、选择保存与启动回执沿用既有链。卡片按钮由 capture 层确认一次，取消不发选择 POST，确认仅发一次。
- 桌面 4 列，窄桌面 3 列，390/320 手机 2 列；完整节点名称换行；协议最小 12px；代理延迟与更多按钮最小 44×44。手机菜单改为 inline SVG。
- 更多对话框复用原编辑表单及 TCP 测试，不嵌套按钮。启动节点标签不声称当前在线。测速不选择、不连接/重载服务；仍为最多 8 并发、每节点 8 秒，阈值仍为 `<200 / <500 / >=500`。
- 测速返回 UNSUPPORTED/TIMEOUT/FAILED 独立呈现，不转换成零；实际 `0 ms` 保留。检查时间、模式及跳验风险在结果 title/aria-label 保留。
- 先前助手升级说明与 HELPER_CONFIG_MISMATCH 分支原样保留。

## 实跑证据

证据根 `/workspace/anytls-nodecards-product-ui-r1`：
- `red.log`：同一产品测试新增 cards 断言对旧 renderer 实际 RED。
- `green-final/results.json`：252 个合成前端断言、53 张截图、53 次实际 CJK 字体 readback、0 JS 异常。
- `cards-final/results.json`：85 个节点卡片专项断言，1440/390/320 三张截图、实际 Noto CJK glyph readback，0 JS 异常。覆盖真实阈值边界、pending、unsupported、长名、双列、44px、选择取消0 POST / 确认1 POST、测速不重连、If-Match 和搜索。
- `node-unit.log`：88 个既有/助手 Node 测试通过（原 77 + 助手 11）。
- `http-final/results.json`：真实认证 Go HTTP router 浏览器 127 个断言、35 张截图、0 JS 异常；保留原 121 断言，新增卡片、列数和启动语义共 6 项。
- `http-patched-r2.log`：精确 Go1.27.3 和既有 go-patched.py + 完整 tags 执行通过，19.84 秒。直接 go 测试缺少现有 ACK patch、通用工具链版本不符的失败日志均保留，不能作为通过证据。

## 已接入助手边界补丁

- 控制请求发送后身份不符保持 UNKNOWN，at-most-once 不自动重发；完整安装器严格校验八字段激活回执及 SHA／tag／path 并拒绝不合格回执。两项最小补丁专项独审 PASS，仅为该范围源码／定向证据，不是原生完整安装或 root 回滚验收。
- 普通 update 不替换 root 助手，三种 authority 分开；用户仍须本机完整安装／系统授权更新助手，再自行显式 reload／重连新版核心。严格 TLS、默认监听与无需 Go 的预编译安装路径不变。

## 保留的 HOLD / 边界

- 当前后端没有节点删除 API，旧节点页面也无删除按钮；本次不新增删除 API 或直接改写复杂 YAML。更多对话框明确提示删除需原始配置，不把未提供的删除功能列为本版已经实现。
- 390 像素产品截图父审 PASS；1440 像素旧菜单图标曾 HOLD，父任务已应用精确 SVG 修复并完成修复截图 PASS。旧证据不覆盖，不能把设计稿历史 PASS 或局部截图 PASS 代称最终候选整体通过；手机仍明确保持双列。
- “更多”保存旧owner已最小修复：成功仅关闭清空原session／route／dialog owner，失败留表单；配对RED→GREEN101项，重开TCP正常，延迟响应不关闭替换窗口。产品252、Node88及最终真实认证HTTP127项通过。
- DNS取消漏终结已修，Run在资源Close之后置CLOSED，Check-only不变；六场景与旧负例专项独审通过。本地第三轮full753顶层／2472子PASS、10SKIP、11包及vet/build通过，前两轮失败保留。连接复用扩展批次曾EOF，归因未定，后续新旧各20次通过不抹去失败；未修改重连语义。
- 所有 API mock 明确属于 SYNTHETIC_API_FRONTEND；真实 HTTP 测试仍仅将特权生命周期和订阅来源作为既有 fixture，不代表实际 VPN 网络验收。
- 本文为发布前证据快照：最终实现身份、native／打包、整体独立审查、CI、公开附件及独立版本执行 PENDING，后续另存绑定收据，不反复 amend 冻结快照；不表示网站恢复、正式 TUN 或完整停止恢复已通过。
