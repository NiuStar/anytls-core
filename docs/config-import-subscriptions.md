# 配置导入与 HTTPS 订阅



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

New native tests: `TestWebImportPinnedURLAndTLS`,
`TestWebImportAppendAuthenticatedPreservesState`,
`TestWebImportAppendRejectsAmbiguityAndInactiveBadNode`,
`TestWebImportAppendTransactionBoundaries`,
`TestWebImportPinnedNoRedirectAndCancellation`,
`TestWebImportAppendRemoteAndPublicBoundaries`. They use isolated synthetic
config and a loopback TLS dial seam, not production or public deployment.
Go runtime tests and Mac/browser acceptance are pending; local syntax checks do
not constitute passing Go tests.

## 本次范围

在“配置与规则”页增加本地 YAML 文件、粘贴 YAML、HTTPS 订阅地址入口。首版只接收本工具兼容的配置（AnyTLS 节点、select 策略组与既有分流规则），不声称兼容所有 Clash/Mihomo 特性；不支持的协议、分组或 provider 必须明确拒绝，不能静默过滤。URI 列表、Base64 和 Surge profile 暂不转换。

先预览、再明确确认备份并导入。预览只显示解析计数、候选启动节点、来源域名和警告，不保存配置、不执行 VPN。订阅地址仅在确认导入成功时私有保存；可手动刷新已保存订阅，无后台定时更新。本地导入默认保留已保存订阅，不自动拉取。

## API 合同

所有入口复用既有 loopback／Host／Origin／登录／CSRF／动作锁：

- `GET /api/v1/subscription` → `{configured,host}`，不返回完整 URL 或查询令牌。
- `POST /api/v1/import/preview`：`{yaml}`、`{url}`、`{use_saved:true}` 三选一。成功返回 `{token,etag,nodes,groups,rules,selected,source_host?,warning}`。
- `POST /api/v1/import/commit`：`If-Match` 使用预览 etag，body `{token,confirm_replace:true,confirm_insecure:true}`。返回现有 saved／changed／applied／apply_status 契约。

预览候选仅在内存暂存，有期限、会话及原配置／选择身份绑定。输入变化、过期、其他编辑器改动或跨会话不得悄悄提交。替换前备份当前配置、选择与已有订阅资料，私有权限，读回核对；候选保留原始 YAML 字节，不经通用 map 重写注释和标量。

保留旧启动节点仅当新配置仍有该完整可选节点，否则预览明确展示新的启动节点。配置提交与选择迁移必须共同处理，避免新配置配上失效选择文件。提交失败尽可能恢复，恢复无法确认则明确报告不确定状态；自动应用失败则仍为“已保存但未生效”，不伪装配置没有改变。

## 网络与凭据边界

订阅仅 HTTPS，默认／显式443，验证服务器证书，禁用环境代理，不携带应用 Cookie、系统认证或来源页面凭据。不接受用户信息字段／fragment，每次重定向重新检查，限定重定向次数。解析出的地址必须为公网可用地址，拒绝 loopback、私网、链路本地、组播和元数据地址；连接绑定已校验 IP，保留原域名用于 TLS 验证，避免 DNS 重绑定。

网络失败仅返回受控错误，不把包含 token 的 URL 或响应配置原文带入普通日志／列表。响应体复用既有配置大小约束与有界网络超时。远程 YAML 不得请求读取本机 CA 或规则文件；所需本机文件须用户自行配置，不能由订阅隐式指定。

## 生效和验证

运行中确认导入会沿既有保存链自动应用并短暂重连；停止时仅保存、不自动启动。单纯打开或预览不应用。正式18089与现有VPN本轮不修改；先在隔离候选中以合成配置／网络夹具验证安全、失败和恢复路径，再做Mac原生测试、预览与读回。

## 已完成验证（尚未上线）

- Mac原生新增12个导入测试入口全部通过；完整套件223顶层／447子测试PASS、3SKIP、0FAIL，vet/build通过。构建候选SHA256：`8c6387a1460f6f371f30c43e14f4e1b90a50e7d5c2353e935d78a13e2a5735c1`。
- Chromium＋合成API覆盖文件／粘贴／URL／已存订阅、预览不提交、输入改变失效、确认字段／CSRF／If-Match、冲突、退出清密与草稿清空；1440/390/360无溢出、JS错误0。既有四保存路径和八刷新失败反馈回归通过。
- Mac独立目录＋真实候选HTTP：实际登录、预览未写、确认后配置注释及数字形字符串原字节保存、启动节点迁移、旧配置备份读回通过。使用合成节点，不使用真实账户／订阅凭据。
- 正式助手对隔离配置返回`HELPER_CONFIG_MISMATCH`，实际API准确显示saved=true、applied=false、APPLY_FAILED，磁盘导入仍成功且pending保留；没有停止／重载正式VPN。前后正式程序／配置／选择／密码SHA和VPN launchd PID/program/runs/state一致。
- 真正公网HTTPS抓取官方示例YAML后，按远端CA文件引用规则拒绝，未覆盖本地配置。DNS绑定、重定向、私网和超时其他负例为Go网络边界替身，不冒称全部真实互联网端点验收。
- 真实HTTP夹具端口18092执行完成后，已terminate并wait本次子进程；18091旧UI预览及18089正式入口未替换。

独立后端审查通过；前端首轮发现UI-IMPORT-P2-001草稿丢失问题，已修复为提交期间冻结输入，真实浏览器RED/GREEN和独立12项延迟提交矩阵通过，旧失败报告保留。

## 本机正式部署

用户明确要求更新正式环境后，部署`v2026-10-21-04`用户程序并安全重启18089 WebUI。程序SHA256：`861a2494eff1846608d2e91ae1ec94484f728445dd7acf8d4c08a003548da18a`，产品源码提交`0d5c15e`，78项产品输入与Mac实际构建树逐项一致。原程序、配置、选择与应用密码备份在用户Mac私有目录 `~/.anytls/backups/before-v2026-10-21-04`，未上传备份。

实际读回：WebUI PID16877→21457；真实登录、version、导入HTML入口、JS/CSS字节、17节点／8组、subscription状态均通过；助手available且仍为已安装v2026-10-21-03，未更新root助手。前后VPN PID/program/runs/state、配置／选择／密码SHA、DNS／proxy摘要完全一致，未执行VPN stop/start/reload或真实配置导入。

本机正式部署不等于GitHub新版二进制Release已发布：公开最新附件仍需单独发版核验。视觉API504仍记UNAVAILABLE；用户要求上线作为本次部署授权，不改写为视觉PASS。
