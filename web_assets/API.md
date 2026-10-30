# 本机控制台契约

## 启动与密码

- 父入口挂接 `webuiCommand(args []string) error`、`passwordCommand(args []string) error`。
- `anytls webui [--listen 127.0.0.1] [--port 18089]` 默认 bind `127.0.0.1`；端口 1024–65535；root 拒绝。显式 `--listen 0.0.0.0` 监听所有 IPv4 网卡，无需逐机地址配置；其他规范 IPv4（含公网）必须已分配给本机接口。拒绝 DNS、IPv6、前导零、zone、CIDR 和附带端口。HTTP 无 TLS，网络访问时凭据与会话未经传输加密；网络访问控制由部署环境管理。
- `anytls password` 创建或真实读回应用专用密码；`anytls password reset` 轮换 24 个随机字节（base64url 32 字符）。固定账户 admin。路径为 `servicePaths()` 配置所在目录的 `webui.password`，0600；不接触 macOS/Keychain/sudo 密码。
- reset 后各请求重新读取凭据摘要并拒绝旧会话。会话仅内存，32 个随机字节，8h，最多 32 会话；Cookie HttpOnly、SameSite=Strict、Path=/。回环 HTTP 不设 Secure。密码摘要比较使用 constant-time SHA256，专用高熵密码可 CLI 恢复，不使用不必要慢哈希。

## 请求边界

默认回环允许 Host 恰为 `127.0.0.1:PORT`、`localhost:PORT`、`[::1]:PORT`；显式其他回环地址额外允许该地址。显式非回环 IPv4 仅允许该监听 IP:PORT。`0.0.0.0` 通配监听接受语法有效的主机名或 IPv4 Host，端口必须精确匹配，无接口／IP／DNS 名称白名单；浏览器使用实际可达 IP 或主机名，不把 `0.0.0.0` 当作访问地址。不信任 Forwarded/X-Forwarded-Host。所有 POST/PUT（含登录）必须单个 `Origin: http://与请求Host完全相同`；无 Origin 的 API 客户端同样拒绝，不提供 CORS。敏感 GET 需登录且不缓存。

登录之外的 POST/PUT 必须 Cookie + `X-CSRF-Token`；令牌由登录或登录后 session GET 的 JSON 返回，未写 localStorage。JSON 请求需 Content-Type application/json；未知字段及多个 JSON 值拒绝。普通 JSON 上限 16KiB；仅 PUT `/api/v1/config` 和 POST `/api/v1/import/preview` 的完整配置 JSON 上限为 `6 × 32MiB + 16KiB`（最坏 JSON 转义及信封开销），解码 YAML 和转换输出均限制为 32MiB。转换输出超限返回 `CONFIG_CONVERSION_TOO_LARGE`，不删除或去重规则来缩小配置。登录每分钟 5 次失败后阻断一分钟。

所有普通错误为受控 `{ "error": "CODE" }`；连接记录通过认证后的分页/来源/助手错误使用共享严格 `{ "schema_version": 1, "error_code": "ENUM" }`（认证/Host/方法外层仍沿用普通错误）。不返回底层日志、配置片段或密码。原始配置是唯一明确展示节点密码的页面操作，仅已登录用户可读。普通节点只给 hasPassword，不给密码或逐密码摘要。

## API v1

统一前缀 `/api/v1`。静态 GET `/`、`/app.js`、`/startup.js`、`/style.css` 不需登录，不包含凭据。

| 方法/路径 | 请求/响应 |
| --- | --- |
| POST /login | `{username:"admin",password:"..."}` → `{csrf,expiresIn:28800,username}` + Cookie |
| GET /session | `{csrf,username}` |
| POST /logout | `{}` + CSRF；删除会话及 Cookie |
| GET /status | `{loaded,running,availability,pendingReload,pendingKnown,version,readiness:"NOT_OBSERVED",transport,listenHost}`；transport 为 `loopback-http` 或非回环（含通配／私有／公网）的 `network-http`，替代旧 `lan-http`；实际只读 serviceState，不用 PID 冒充 ready |
| GET /nodes | `{nodes:[{name,type,server,port,hasPassword,selectable,skipVerify,sni,selected}],etag}` |
| POST /nodes/selection | `{name}`；实际 saveSelection + readback → `{ok,changed,pendingReload}` |
| PUT /nodes | `{name,server,port,password,sni}` + If-Match；空 password 保留；只编辑既有显式节点，保留未知字段/注释，拒绝共享 alias 目标 → `{ok,changed,etag,pendingReload}` |
| POST /nodes/probe | `{name,mode:"tcp"或"https",confirm_insecure:true}` + If-Match；精确当前配置节点、8秒网络context；每控制台TCP/HTTPS共享最多8个活动名额，超额429 PROBE_BUSY，无排队；网络与同步清理不持配置动作锁，捕获／收尾共享读锁，配置／服务写锁冲突409 ACTION_BUSY，配置变化412；结果含mode/status/latency_ms/checked_at/config_etag，API保留浮点、UI显示整数分色；失败不返回虚假0ms，不保存或切换节点。TCP不等于AnyTLS认证／网络可用；HTTPS通过实际AnyTLS访问固定204目标，不是带宽测速。同步构建/Close不是OS级硬期限。 |
| GET /profiles | 私有方案元数据列表及当前config etag，不返回配置、密码或订阅令牌。 |
| POST /profiles | `{name}`；保存磁盘当前配置、选择与私有订阅为不可变方案，不包含未保存编辑草稿。 |
| POST /profiles/copy | `{id,name}`；复制已有方案为新ID，不改变当前配置或VPN。 |
| POST /profiles/switch | `{id,confirm_replace:true,confirm_insecure:true}` + If-Match；校验、备份、一起切换配置／选择／订阅、读回；失败回滚／不确定独立报告，成功沿现有saved/applied链。 |
| GET /groups | `{groups:[{name,type,choices,selected,resolved,valid}],etag}`；etag 来自解析策略组的同一份配置字节 |
| POST /groups/selection | `{group,choice}`；新控制台携带读取时的 If-Match，冲突返回412 CONFIG_CONFLICT且不写入／不调用服务；省略header保留旧客户端兼容。复用真实 saveGroupChoice + readback → `{ok,changed,pendingReload}`；同值不写 |
| GET /rules | `{rules:[原始规则字符串],etag,targets:[有效目标名称],rule_sets:[已审计标签],editable,edit_error}`；ETag 响应头与 etag 字段均为同次捕获配置的完整 SHA-256（含双引号）。旧 rules 字段不变，不返回 YAML、节点凭据或规则集路径 |
| GET /rules?view=list | 只读列表投影 `{rules,etag,editable,edit_error,view:"list",options_loaded:false}`；省略 targets / rule_sets，不读取外部规则集、不做 SDK 规则集检查或节点目标构建。与完整 GET 共用原始配置快照、顺序、重复项、layout 检查和 ETag；不是服务端分页 |
| POST /rules | 添加单条规则；完整合同见下文，复用认证 / 同源 / CSRF / actionMu 与保存后自动应用 |
| POST /rules/delete | `{index:0,rule:"原始规则字符串",confirm_insecure:true}` + 同次 `GET /rules` 的 If-Match；仅删除指定位置的一条规则，保留最终 MATCH；完整合同见下文 |
| GET /config | 显式敏感编辑操作 → `{yaml,etag}`，同时 ETag header；etag 是双引号包裹的完整原文件 SHA256 |
| PUT /config | `{yaml}` + `If-Match: "SHA256"`；无 header 428，冲突412，无效422；同目录0600原子写入并读回 → `{ok,changed,etag,pendingReload}` |
| POST /service/start, /service/stop, /service/reload | `{confirm_insecure:false}`；只布尔同意，不接收命令；原生授权及 launchd 状态读回 → `{ok,loaded,running,pendingReload,readiness}` |
| GET /connections | 连接记录只读页，必须 Cookie + 精确 `X-AnyTLS-Origin: http://Host` + `Sec-Fetch-Site: same-origin`；仅非回环网络 HTTP（含通配）允许 Fetch Metadata 完全缺失，仍强制精确自定义 Origin。空值／重复／cross-site／same-site 拒绝；可选 Origin 存在时同样精确验证。query 仅 after（canonical uint64 十进制字符串，默认0）、limit（1..500，默认100）、完整 instance_id/generation/manifest_id；拒绝未知/重复/部分绑定。无绑定仅发现无行；有绑定不回退最新。严格共享 PageResponse，≤1MiB，无 LIVE/connected 声明；失败400 INVALID_REQUEST、403 FORBIDDEN、409 BUSY/STALE_GENERATION、503 TELEMETRY_UNAVAILABLE/STORE_INVALID/UNSUPPORTED。认证先于 helper，no-store；不持 action 锁，不安装/更新/reload，不读当前 YAML 回填历史。 |
| GET /version | `{version}` 是当前控制台进程版本，不假冒活动快照版本 |
| GET /update-check | 固定自身 `update --check` 有界子进程；保持 sibling 五字段 CLI contract，只输出 `{status,current,installed,latest,available,sourceOnly,updated,restartRequired,restartManaged,restartScheduled:false}`。restartManaged 为本次检查确认的用户级 Web 控制台托管能力（不授权 VPN 操作）；旧服务可省略，前端按需手动重启处理。current 永远是本 WebUI 内存版本，installed 是磁盘 sibling 报告；不相同时 restartRequired=true，status=RESTART_REQUIRED（可安装更新时优先 UPDATE_AVAILABLE）。响应丢失后重查仍保留重启提示。 |
| POST /update | `{confirm:true}`；先固定自身 check，再 `update --version CHECKED_VERSION` 用户级子进程；丢弃输出，执行替换后自身 `version`（独立20秒期限）读回匹配才报告 UPDATED，installed=目标版本、restartRequired=true；成功响应始终增加 `restartScheduled` 布尔值，仅真实托管身份复核和安排成功才为 true；可附固定码 `restartError`（页面不透传其原始字符串）。先回复并 flush，再退出旧 Web server，由已验证的用户级 LaunchAgent 重启；不会重载 VPN、调用特权助手或系统授权。非托管、安排失败或旧服务省略该字段时，前端保留手动重启提示。失败503，只投影固定错误码 UPDATE_CHECK_FAILED(40)、UPDATE_PYTHON_REQUIRED(41)、UPDATE_BINARY_UNAVAILABLE(42)、UPDATE_DOWNLOAD_FAILED(43)、UPDATE_VALIDATION_FAILED(44)、UPDATE_PUBLISH_FAILED(45)、UPDATE_VERIFY_FAILED(46)、UPDATE_UNAVAILABLE(47/未知)。核验失败或超时不保证旧文件未变，不自动回滚，需独立核对磁盘版本、摘要和备份。 |

服务动作原生授权最长3分钟，检查升级30秒，安装接纳前请求期限10分钟；接纳后独立于HTTP取消同步等待CLI及版本读回，CLI以35分钟context kill并Wait唯一Python publisher。认证与状态读取不持有 action 锁；修改、服务动作、升级共用 TryLock，忙返回409 ACTION_BUSY，避免排队请求超时后意外执行。更新检查是只读，可与状态并行。

### 更新后的浏览器恢复与版本核验

浏览器只有在安装响应为 `UPDATED,updated=true,restartRequired=true,restartScheduled=true` 且 `installed===latest`、目标符合稳定版本格式时启动恢复等待。磁盘安装成功和已安排重启不等于新进程已经运行。仅 GET 同源固定 `/api/v1/version`（Cookie、no-store、拒绝重定向），每次最多 3 秒、最多 30 次、总计最多 90 秒，串行读取间隔 1 秒；网络中断、旧版/畸形/错误响应不得判定成功，也不会重发安装请求。等待超时保留“磁盘程序已安装”与“运行版本尚未确认”，提供手动刷新/登录核对指引。页面不盲目 reload。

`/version` 仍必须登录，未增加公开健康端点或放宽认证。401 仅表示控制台有响应且需要登录，可能仍为旧进程，不证明重启或目标版本；显示登录页及“尚未确认运行版本”。页面只在 sessionStorage 保存 `{tag:"WEBUI_UPDATE_TARGET",target,createdAt}`，15 分钟过期，校验格式和时间，绝不保存密码/CSRF/Cookie/URL。重新加载页面后仅在真实 session/login 成功时继续核验，且只有认证 200 的 `version===target` 才显示运行版本成功并清除记录；不依赖 `/status`、磁盘或登录页作成功证据。过期/无效记录与显式退出登录清除记录。退出、新登录、会话切换取消在途请求及定时器；代次/owner 检查拒绝迟到版本、401 和旧 finally 覆盖新会话。等待过程中保留退出登录入口。

`node --test scripts/web_update_restart_test.mjs web_rules_list_only_test.mjs` 实际执行 app.js（Node builtin VM/assert/test），最小合成 DOM、HTTP、时钟与 sessionStorage，不是浏览器、真实 HTTP 或 macOS/LaunchAgent/VPN 验收。核心等待、401 后重登录、托管确认文案、退出取消和登录 supersede 切片均观察到业务 RED 后实现 GREEN；其余负例为补充回归。真实浏览器和 native 集成由父任务独立验收。

## 配置与运行边界

### 停止完成与网络恢复警告

STOP 以新鲜的服务作业已卸载为停止证据；路由／DNS 与旧基线不同、基线缺失／损坏或网络探针失败，不再单独阻止停止或下一次启动。恢复未证实仍为 `restoration=FAILED/UNKNOWN`，绝不提升为 VERIFIED。失败恢复快照原子移动到同父随机0700 `.service-recovery-*` 目录的 `snapshot`，同时保留先前诊断原字节与本次恢复摘要；不自动删除归档。START 对已确认卸载的遗留快照自动执行同样归档后继续，拒绝未知／仍加载作业、快照符号链接、身份替换及不安全所有权／权限。

成功的 helper、时间轴 mutation 和 HTTP 手动操作／保存自动应用响应可以带既有11字段严格 `diagnostics`，其 `outcome=SUCCEEDED,stage=NONE,reason=NONE` 与 `restoration=FAILED/UNKNOWN` 合法共存。页面对该组合显示明确恢复警告，而不是只报成功；RELOAD 保留 STOP 的恢复警告并继续 START。真实 bootout、作业读取、归档／清理或诊断收尾失败仍失败关闭；失败 START 的主错误与 rollback 恢复错误继续保留。只读 CLI status 区分 stopped 与先前恢复未验证，不把归档或历史回执当作网络恢复成功证据。现有 DNS／路由／TLS 策略及就绪预算不变。

候选同一字节做单 YAML document/mapping、loadNodesBytes、真实 applyRoutingBytes（内部 resolveGroup、loadRuleSet、规则语法编译）校验。规则引用保持原配置目录相对路径，CA 沿原 buildNode 语义；绝不 chdir。校验允许配置显式 skip-cert-verify 以支持编辑既有配置，不构成运行授权，Start 仍要求独立 confirm_insecure。不启动核心、不写原文件直到通过校验；完整 YAML 按用户原字节保存，不 typed roundtrip。TUN 固定IP及实际选中节点的运行要求仍由现有服务预检负责，配置编辑允许合法但未完成的非活动节点。

启动前的磁盘配置与运行 root 快照不作虚假相等推断：pendingKnown=false；控制台成功 start/reload 后确认本次配置基线，后续配置/selection 指纹变化显示 pendingReload。root 快照从不由配置页面改写。

If-Match 是 WebUI 内互斥 + 外部文件乐观二次检查，不声称消除恶意同 UID/父目录替换或最后 compare/rename 间外部编辑竞态；既有 CLI 未接共享跨进程锁。

## 连接记录终态语义（用户批准的保守修订）

每个 `/connections` PageResponse 的 `coverage.continuity` 固定为 `UNKNOWN`，不能声明 `CLOSED` 连续性。磁盘 `collection=CLOSED` / `closed=true` 仅保留最后保存的停止采集状态，不能证明最终目录 Sync、锁关闭、完整收尾或成功。对于已保存的 closed 历史，保留已提交前缀、身份和来源归属，但公开页必须 `freshness=UNKNOWN`、`coverage.gap=true`，`pending`、`lost_total`、`loss_epoch` 及全部 `loss_reasons` 值为 null；不虚构丢失数量。此规则也适用于正常 Shutdown 成功的历史，且不随时间过期。`counter_saturated` 仅为原存储观察。

共享 Validate/严格编码和解码拒绝任何 continuity CLOSED，或 closed 页的非 UNKNOWN freshness、gap=false、已知 pending/loss 计数及原因；磁盘 State 的既有 CLOSED/已知零兼容性不变。进程内 Shutdown 仍按真实错误返回 IO_FAILED/cleanup UNKNOWN，保留 once-close、锁实际生命周期、前缀与禁止自动删除的合同。UI 始终显示“完整收尾未验证／连续性 UNKNOWN”，CLOSED 另注明仅最后保存的停止采集状态，不代表完整收尾或成功。



## Add-only pinned subscriptions (candidate, native validation pending)

`POST /api/v1/import/preview` accepts `mode:"append_nodes"`; omitted mode remains
`replace_config`. Choose exactly one input. Add-only supports YAML or a one-shot
URL, not `use_saved`. Response includes `mode`, `added_nodes`, counts and warning.
Commit uses the preview token, CSRF and full If-Match with
`confirm_append:true,confirm_insecure:true`; `confirm_replace` alone cannot
approve add-only. Conversion differences still require `accept_conversion:true`.

Trusted server handoff links have exactly this form:
`https://<public-numeric-IP>[:port]/subscribe/<43-char-unpadded-base64url-token>#anytls-cert-sha256=<64-lowercase-hex>`.
The token encodes exactly 32 bytes. IPv6 uses brackets. No DNS names, userinfo,
queries, percent-encoded ambiguities, extra fragments, redirects, proxies or
non-public addresses are accepted. Numeric port must be canonical 1..65535.
The fragment never reaches HTTP. TLS >=1.2 compares the SHA256 of the active
leaf DER before any HTTP request/token is sent. This is **pin-only identity**,
not public-CA/hostname validation plus a pin. Obtain the complete link over a
trusted channel; certificate rotation requires a new independently trusted link.
The existing ordinary HTTPS:443 PKIX/DNS-bound fetch remains unchanged; pinned
links cannot be used to replace configuration or saved as subscription metadata.
Node `certificate-public-key-sha256` is a separate canonical base64 SPKI digest,
not the URL leaf digest. It does not turn on insecure verification.

Add-only validates every incoming AnyTLS node, including inactive nodes, before
conversion can skip unsupported entries. It imports no groups/rules/providers
and never fetches their resources. Remote CA file references are rejected before
file validation. New nodes are appended via YAML AST to one explicit nodes or
proxies sequence. Ambiguous keys/merge/alias targets fail closed. Existing
comments, scalar tags, unknown fields, groups and rules are retained semantically;
formatting can change. Same-name semantically identical full node maps are no-op;
different values fail the entire preview with `IMPORT_NODE_CONFLICT`. Unsafe AST
returns `IMPORT_APPEND_UNSAFE`.

Selected-file and saved-subscription bytes **and existence** remain untouched,
including stale selections and absent files. There is no implicit selection or
saved append source/automatic refresh. A config-changing commit uses existing
backup, ETag/session/TTL/readback/rollback and automatic-apply protections; saving
may briefly interrupt a running VPN, and does not start a stopped VPN. The UI
has a separate “从此订阅仅添加节点” button and explicit add-only confirmation.

## Single-rule add contract

`POST /api/v1/rules` requires JSON, authenticated session, exact Origin, CSRF and exactly one full `If-Match` from `GET /rules` (missing 428 `IF_MATCH_REQUIRED`, mismatch 412 `CONFIG_CONFLICT`, busy 409 `ACTION_BUSY`). Body:

```json
{"type":"DOMAIN","value":"example.com","target":"DIRECT","no_resolve":false,"position":"before_match","confirm_insecure":true}
```

Required fields: `type`, `value`, `target`, `no_resolve` (boolean, not null), `position`. Types: DOMAIN, DOMAIN-SUFFIX, IP-CIDR, GEOIP, RULE-SET. GEOIP accepts exact `CN` only; RULE-SET accepts only an existing label whose configured local content passes the existing SHA audit and real embedded `engine.Check` decode/construct/close, never a supplied path/URL. The inventory excludes SDK-invalid sets, and POST validates every activated set before disk mutation; this check never calls Start or binds a listener. Optional `no-resolve` is supported only for GEOIP/RULE-SET. MATCH cannot be added. Values are preserved exactly, not case-corrected or normalized; empty, leading/trailing whitespace, comma, CR/LF/NUL and native-invalid values are rejected. Native-accepted Unicode domains remain supported. Targets are DIRECT/REJECT or an existing resolvable group/node whose terminal node passes buildNode; existing skip-cert-verify is not changed. Optional `confirm_insecure` defaults false and UI sends true per existing policy; no new checkbox.

Position is `before_match` (default UI selection), `first`, or `index`. For `index`, supply integer `index` in [0, rules.length-1], meaning insert **before** that existing 0-based item. UI displays 1-based rule numbers and subtracts exactly one. For other positions index must be omitted or null. Never insert after final MATCH. Earlier rules remain higher priority.

Response is existing finishConfigSave fields plus `inserted` boolean, `index` (0-based inserted/existing item), canonical `rule`, and current `etag`/ETag header. A duplicate after trimming each existing comma-separated component is NO_CHANGE at its existing index, regardless of requested insertion position; no rewrite/reload. Different targets/flags remain different rules. Save is read back before applying; APPLIED, SAVED_STOPPED, APPLY_FAILED, STATE_UNAVAILABLE remain distinct. No stopped VPN is started.

Only an explicit nonempty ordinary block `rules` sequence of scalar rules with one final MATCH is locally editable. Flow/alias/merge/anchored target sequences, aliased keys/items, multiline scalar rules and missing MATCH return 422 `RULE_EDIT_UNSUPPORTED`; GET sets editable=false and UI directs users to the original editor. Unrelated anchors are preserved. Saving inserts one single-quoted line into original UTF-8 bytes with the target line's indentation/newline style; all original bytes, comments, scalar spelling, unknown fields, other rules, selection and subscription are unchanged. Existing comments immediately above the target remain byte-identical above the new line. This add action reuses atomic config save, not the import backup transaction; export/save a named profile first for a manual backup. UI keeps an already-open raw draft but revokes its stale save ETag; copy and reread/merge before saving it.

Validation errors return only fixed codes, never raw native errors: 422 RULE_INVALID_INPUT, RULE_VALUE_INVALID, RULE_TARGET_INVALID, RULE_POSITION_INVALID, RULE_EDIT_UNSUPPORTED. Same read/validate/recheck/write/readback and in-process action lock as existing saves; not an OS-wide lock against external editors.

The UI uses actual select controls for type, target, position, GEOIP country (CN only) and audited RULE-SET label. DOMAIN/DOMAIN-SUFFIX/IP-CIDR use text, the displayed rule number uses a numeric input, and no-resolve uses a checkbox. Inputs are locked while committing. A preview cannot re-enable save while another operation is busy. Session/config generations reject stale list/save/refresh results after logout or profile invalidation; authoritative saved/applied feedback remains visible even if subsequent list or status refresh fails. Browser fixture evidence uses real Chromium with synthetic API responses, not a live Mac/helper/VPN acceptance.

New native tests: `TestWebImportPinnedURLAndTLS`,
`TestWebImportAppendAuthenticatedPreservesState`,
`TestWebImportAppendRejectsAmbiguityAndInactiveBadNode`,
`TestWebImportAppendTransactionBoundaries`,
`TestWebImportPinnedNoRedirectAndCancellation`,
`TestWebImportAppendRemoteAndPublicBoundaries`. They use isolated synthetic
config and a loopback TLS dial seam, not production or public deployment.
Go runtime tests and Mac/browser acceptance are pending; local syntax checks do
not constitute passing Go tests.

## Single-rule delete contract

`POST /api/v1/rules/delete` requires authenticated Cookie, exact Origin, CSRF, JSON and exactly one full `If-Match` captured from the same `GET /rules` or `GET /rules?view=list` snapshot. The default GET schema remains unchanged. Body:

```json
{"index":0,"rule":"DOMAIN,example.com,DIRECT","confirm_insecure":true}
```

`index` is a required zero-based integer selecting exactly one existing row; `rule` is the required exact original decoded string at that position, including whitespace. Do not trim, canonicalize, match by value alone or delete every duplicate. The UI shows the corresponding one-based number. Optional boolean `confirm_insecure` follows existing save policy (UI sends true); it never changes any node's TLS settings.

Missing If-Match is 428 `IF_MATCH_REQUIRED`; stale configuration is 412 `CONFIG_CONFLICT`; shared action lock contention is 409 `ACTION_BUSY`. Invalid index/string or a positional string mismatch is 422 `RULE_DELETE_INVALID`. Deleting the unique final MATCH is 422 `RULE_DELETE_PROTECTED`. A noneditable flow/alias/merge/anchored/multiline or ambiguous rules layout, or missing unique final MATCH, is 422 `RULE_EDIT_UNSUPPORTED`. Existing `CONFIG_*` validation/read/write errors remain controlled errors, not raw native diagnostics. Failed validation must not save or apply.

Only a provable single physical block-sequence scalar line is deleted, including its own inline comment and line ending. Other bytes, standalone neighbouring comments, CRLF/LF style, unknown fields, unrelated anchors, selected-node file and saved subscription remain unchanged. Candidate validation includes remaining active RULE-SET native checks and a fresh source-byte recheck. This action uses the existing atomic save/readback chain, not bulk deletion, reorder, edit, import backup or an OS-wide lock.

Success uses existing `finishConfigSave` fields plus `deleted:true`, original zero-based `index`, original `rule` and current `etag`/ETag header. APPLIED, SAVED_STOPPED, APPLY_FAILED and STATE_UNAVAILABLE remain distinct: a successful disk save with failed/unconfirmed apply is not a failed deletion. A stopped VPN is not started; a running VPN follows the existing controlled apply once. `/rules/delete` participates in existing startup observation using the SAVE_RULE source, not a new enum or a client-issued reload.

The existing ordered list has one delete control per rule. MATCH is disabled with “保留唯一兜底”; all delete controls are disabled when `editable=false` or busy. Before sending any request, confirmation displays the one-based number, exact rule and running-apply/stopped-save implications; cancellation sends no API request. Each handler captures its original index, string, ETag, session and list generation, checks freshness before and after confirmation, and cannot submit from a reloaded list, switched profile or old session. Concurrent double submissions are guarded. Save/list/status responses and operation cleanup are owner-fenced so old work cannot overwrite a newer operation's feedback or enable its controls. Existing raw YAML drafts are preserved, but their stale save ETag is revoked after a changed save. Saved/deleted feedback remains authoritative when subsequent list/status refresh fails, with a separate refresh warning. All API rule strings use text nodes/textContent, never innerHTML.

Local evidence: `/workspace/anytls-rule-delete-evidence/ui_vm_test.cjs` exercises the actual app functions in Node VM with a deliberately minimal DOM and synthetic transport. The first list-control/cancel test was observed RED on the baseline and GREEN on the candidate; added boundary checks are test-after. This is not browser, real HTTP, Mac/helper/VPN or production acceptance. The parent owns independent desktop/mobile browser verification; this UI change does not deploy, restart or publish anything.

## 已加载规则列表导航

浏览和保存后的列表刷新使用 `GET /rules?view=list`，仍一次返回完整 `rules[]`，不增加分页参数或改变配置/导入配额。仅显式打开新增表单读取旧 `GET /rules` 完整选项；默认 GET 仍执行完整目标构建、规则集摘要与原生校验，且不新增模式元数据。非空 query 只支持单个 `view=list`；未知键/值、空值、重复 view、非法转义及分号语法返回 400 `INVALID_INPUT`，不带 ETag；空 query 等同旧 GET。

列表快照可删除但不能新增：保存按钮和表单处理器都检查选项已加载；完整新增快照使用自身 ETag。请求、会话与配置代次拒绝两种模式互相迟到覆盖。`CONFIG_WRITE_FAILED` 与 `CONFIG_READBACK_FAILED` 分别显示中文不确定性警告：磁盘配置可能已改变/保存，必须重新读取并核对，不自动重试；不宣称原文件一定未变。保存 API、原生 mutation 校验及原始 YAML 草稿规则不变。

页面每页只创建最多 100 个规则行及其删除按钮；首页、上一页、下一页、末页仅切换当前快照视图。中文计数区分总数、匹配数和匹配结果中的当前显示范围；无匹配与配置无规则分别提示。

搜索对整份已加载快照的原始规则字符串执行 `trim().toLowerCase()` 查询与 `toLowerCase().includes()` 字面子串匹配，不解释正则，不限当前页、不请求服务器、不去重或重排。列表 `li.value` 始终是原始一基序号，筛选后的第几条不是删除索引。原始序号跳转仅接受 1..已加载总数的规范正整数（无前导零、空格、小数或指数），清除搜索并明确提示后跳到该原始位置所在页。

翻页/搜索不替换规则快照或请求代次。所有删除闭包仍捕获原始零基 index、精确原文、完整 ETag 和会话/列表代次；重复内容按所选原始位置分别删除。搜索/翻页/跳转及重绘后的删除按钮在 busy/提交期间禁用，处理器另有状态检查。重新读取、保存后刷新、配置切换及登出均清空搜索并重置第一页；冲突导致快照失效后导航和变更控件禁用。新增、最终 MATCH 保护、取消零请求和原始 YAML 草稿保护沿用原有合同。

本次证据 `/workspace/anytls-rule-list-ux-evidence/ui_navigation_test.cjs` 使用真实 app.js 的 Node VM + 最小 DOM/合成传输。先在基线观察 91,983 行全部渲染（要求最多 100 行）的业务 RED，再观察候选仅创建 100 li / 100 删除按钮的 GREEN；导航和跳转另有观察到的业务 RED/GREEN，额外安全边界为 test-after。该计数不是浏览器性能计时、真实 HTTP 或 Mac/helper/VPN/生产验收；父任务负责真实浏览器验证。旧删除/新增 VM 回归单独运行。

## 验证

### ST1 页面启动日志（独立候选）

`GET /api/v1/startup-trace[?operation_id=<32 lowercase hex>]` 只读当前 WebUI 最近服务操作。无 query 仅用于发现，有 ID 时绝不跳到另一操作；未知／重复 query、空或非规范 ID 返回 400，替换返回 409。与 connections 完全相同的 Host、Cookie、精确 `X-AnyTLS-Origin`、可选 Origin 及 Fetch Metadata 政策；非回环 HTTP 才允许 Metadata 缺失。响应 no-store/no CORS；不拿 actionMu、不读取 serviceState、records、安装或日志文件。返回前重新验证会话、配置绑定和操作所有者。响应是共享 `startuptimeline.ReadResponse`，严格固定 DTO，最多 768 KiB；不返回自由错误或原始配置。

手动 service 动作及八种实际保存自动 reload 使用服务端 crypto/rand ID，客户端不生成 ID、不另发 reload。所有保存共用 finishConfigSave；IMPORT_APPEND 使用受控 context source 区分同一个 import/commit 路由。成功、失败（包括 saved=true/applied=false）附 `startup_operation: {timeline_schema:1,operation_id:string|null,availability:AVAILABLE|UNSUPPORTED|UNAVAILABLE}`。同值、未运行、状态不可用或保存校验拒绝不建立新日志，明确 `startup_operation:null`；此前最近服务操作不因此改成保存审计。

新 helper 能力发现先于 mutation；仅精确 legacy INVALID_REQUEST（由 backend `startupUnsupported` 识别）或未发送 mutation 的能力超时可执行一次 legacy。坏帧、未知 schema 或其他错误绝不降级。mutation 已发送后丢失回复绝不重发，Web 返回 UNKNOWN 并仅按 ID 查询。原 error-only `webControlAction` 和注入 `serviceAction` seam 保留；注入旧 seam 不暗连真实 helper。生产依赖 backend owner 的精确函数 `startupRead` / `startupControl` / `startupUnsupported`，本候选没有伪生产实现。

概览日志每 2 秒最多一个 GET，操作／会话 owner 绑定，页面隐藏、切页、logout、替换时 abort；迟到 401、GET 或旧 POST finally 不能改写新会话。UTC 开始时间、helper elapsed、最后收到 core 阶段／缓存年龄、STALE/GAP、lifecycle/helper/web/receipt 分开显示。完整导出按 process clock 分组，保留全部有界 events、轮次、rollback、receipt、provenance 和固定 DTO，不用 notice 文本作为复制数据。FINISHED 是历史快照，不授权 ready；运行中可复制 partial。

浏览器和 HTTP 均严格验证 DTO。复制仅点击后调用 Clipboard；不安全 HTTP、无 Clipboard API 或拒绝均展开 readonly textarea、选中完整文本，明确“未复制，请手动复制”，不谎报成功。日志仅内存，不写 localStorage。

`web_startup_browser_test.mjs` 在真实 Chromium 1280/390 使用显式 synthetic API，不是 backend/Mac/helper/TUN 验收；缓存字体通过 test-only FONTCONFIG_FILE 提供。覆盖完整复制精确相等、fallback、注入 Clipboard 成功/拒绝、严格负例、所有 source 标签、真实 service 按钮失败引用、2s 单在途、迟到 GET/401、新旧会话和旧 finally、隐藏 abort、终态停 poll。`web_startup_test.go` 的认证 HTTP／真实保存关联 Go tests 已写，等待父 integration 合入 backend 后在授权环境执行；本地仅 gofmt parser，不声称编译或 Go 测试已通过。

早期 `web_auth_test.go` 包含 httptest 与真实 TempDir 文件测试，其当时本地工具限制不代表本次 ST1 验收。ST1 本地已使用缓存 Node/Chromium 和 gofmt parser；没有运行 Linux Go 编译／Go tests、Mac SSH、真实服务／正式配置或正式 Web server。父任务仍需合并 backend 后执行 `go test -run '^TestWeb'`、完整 tests/vet 与 native 集成验收。
