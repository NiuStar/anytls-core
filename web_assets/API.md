# 本机控制台契约

## 启动与密码

- 父入口挂接 `webuiCommand(args []string) error`、`passwordCommand(args []string) error`。
- `anytls webui [--port 18089]` 只 bind `127.0.0.1`；端口 1024–65535；root 拒绝。无 listen 参数，无公网监听。HTTP 无 TLS，禁止转发端口。
- `anytls password` 创建或真实读回应用专用密码；`anytls password reset` 轮换 24 个随机字节（base64url 32 字符）。固定账户 admin。路径为 `servicePaths()` 配置所在目录的 `webui.password`，0600；不接触 macOS/Keychain/sudo 密码。
- reset 后各请求重新读取凭据摘要并拒绝旧会话。会话仅内存，32 个随机字节，8h，最多 32 会话；Cookie HttpOnly、SameSite=Strict、Path=/。回环 HTTP 不设 Secure。密码摘要比较使用 constant-time SHA256，专用高熵密码可 CLI 恢复，不使用不必要慢哈希。

## 请求边界

允许 Host 恰为 `127.0.0.1:PORT`、`localhost:PORT`、`[::1]:PORT`。监听本身仍仅 IPv4 loopback。所有 POST/PUT（含登录）必须单个 `Origin: http://与Host完全相同`；无 Origin 的 API 客户端同样拒绝，不提供 CORS。敏感 GET 需登录且不缓存。

登录之外的 POST/PUT 必须 Cookie + `X-CSRF-Token`；令牌由登录或登录后 session GET 的 JSON 返回，未写 localStorage。JSON 请求需 Content-Type application/json；未知字段及多个 JSON 值拒绝。普通 JSON 上限 16KiB，完整配置 JSON 上限 24MiB（解码 YAML 再按既有 4MiB 上限）。登录每分钟 5 次失败后阻断一分钟。

所有错误为受控 `{ "error": "CODE" }`，不返回底层日志、配置片段或密码。原始配置是唯一明确展示节点密码的页面操作，仅已登录用户可读。普通节点只给 hasPassword，不给密码或逐密码摘要。

## API v1

统一前缀 `/api/v1`。静态 GET `/`、`/app.js`、`/style.css` 不需登录，不包含凭据。

| 方法/路径 | 请求/响应 |
| --- | --- |
| POST /login | `{username:"admin",password:"..."}` → `{csrf,expiresIn:28800,username}` + Cookie |
| GET /session | `{csrf,username}` |
| POST /logout | `{}` + CSRF；删除会话及 Cookie |
| GET /status | `{loaded,running,availability,pendingReload,pendingKnown,version,readiness:"NOT_OBSERVED",transport:"loopback-http"}`；实际只读 serviceState，不用 PID 冒充 ready |
| GET /nodes | `{nodes:[{name,type,server,port,hasPassword,selectable,skipVerify,sni,selected}],etag}` |
| POST /nodes/selection | `{name}`；实际 saveSelection + readback → `{ok,changed,pendingReload}` |
| PUT /nodes | `{name,server,port,password,sni}` + If-Match；空 password 保留；只编辑既有显式节点，保留未知字段/注释，拒绝共享 alias 目标 → `{ok,changed,etag,pendingReload}` |
| GET /groups | `{groups:[{name,type,choices,selected,resolved,valid}]}` |
| POST /groups/selection | `{group,choice}`；复用真实 saveGroupChoice + readback → `{ok,changed,pendingReload}`；同值不写 |
| GET /rules | `{rules:[原始规则字符串]}`，登录后明确读取，UI 以 textContent 展示 |
| GET /config | 显式敏感编辑操作 → `{yaml,etag}`，同时 ETag header；etag 是双引号包裹的完整原文件 SHA256 |
| PUT /config | `{yaml}` + `If-Match: "SHA256"`；无 header 428，冲突412，无效422；同目录0600原子写入并读回 → `{ok,changed,etag,pendingReload}` |
| POST /service/start, /service/stop, /service/reload | `{confirm_insecure:false}`；只布尔同意，不接收命令；原生授权及 launchd 状态读回 → `{ok,loaded,running,pendingReload,readiness}` |
| GET /version | `{version}` 是当前控制台进程版本，不假冒活动快照版本 |
| GET /update-check | 固定自身 `update --check` 有界子进程；解析真实 sibling contract `current_version/latest_version/update_available/source_only`，只输出 `{status,current,latest,available,sourceOnly,updated,restartRequired}` |
| POST /update | `{confirm:true}`；先固定自身 check，再 `update --version CHECKED_VERSION` 用户级子进程；丢弃输出，执行替换后自身 `version` 读回匹配才报告 UPDATED；不重启服务；失败503 UPDATE_UNAVAILABLE |

服务动作原生授权最长3分钟，检查升级30秒，安装更新10分钟。认证与状态读取不持有 action 锁；修改、服务动作、升级共用 TryLock，忙返回409 ACTION_BUSY，避免排队请求超时后意外执行。更新检查是只读，可与状态并行。

## 配置与运行边界

候选同一字节做单 YAML document/mapping、loadNodesBytes、真实 applyRoutingBytes（内部 resolveGroup、loadRuleSet、规则语法编译）校验。规则引用保持原配置目录相对路径，CA 沿原 buildNode 语义；绝不 chdir。校验允许配置显式 skip-cert-verify 以支持编辑既有配置，不构成运行授权，Start 仍要求独立 confirm_insecure。不启动核心、不写原文件直到通过校验；完整 YAML 按用户原字节保存，不 typed roundtrip。TUN 固定IP及实际选中节点的运行要求仍由现有服务预检负责，配置编辑允许合法但未完成的非活动节点。

启动前的磁盘配置与运行 root 快照不作虚假相等推断：pendingKnown=false；控制台成功 start/reload 后确认本次配置基线，后续配置/selection 指纹变化显示 pendingReload。root 快照从不由配置页面改写。

If-Match 是 WebUI 内互斥 + 外部文件乐观二次检查，不声称消除恶意同 UID/父目录替换或最后 compare/rename 间外部编辑竞态；既有 CLI 未接共享跨进程锁。

## 验证

`web_auth_test.go` 包含 httptest 与真实 TempDir 文件测试。遵守父任务约束，本子流未运行 Linux Go、Mac SSH、真实服务/真实配置或 Web server。Go/gofmt/Node 本地不可用；仅 tree-sitter Go/JS 语法解析，不等同编译或运行测试。父任务需 native gofmt、`go test -run '^TestWeb'`、完整 tests/vet，以及隔离真实浏览器桌面/窄屏验收。
