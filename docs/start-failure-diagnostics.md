# 启动失败可诊断性：修复规格（待审，未实现）

## 已确认问题与未确认事实

当前特权助手 execute 丢弃 start 返回的具体错误，统一响应 START_FAILED，WebUI 仅显示“新配置启动失败，请检查 VPN 状态和连接配置”。这是已从代码确认的诊断缺陷；不能据此断言用户此次为证书、系统代理、路由、节点认证或其他原因。不得为诊断先重启／停止正式 VPN。

## 最小修复范围

1. 保持既有 UID／socket／配置绑定、授权、actionMu、超时、TLS、网络／恢复和保存应用语义。绝不向 HTTP 透传 err.Error、工具输出、路径、节点密码或订阅。
2. 在实际生命周期分支产生类型化、固定枚举的诊断原因，而非匹配自由文本。至少区分：作业状态不可读／已加载；快照存在／创建复制或资源预检失败；系统代理启用／代理状态不可读；节点服务器路由不可读／非物理出口；公共路由、DNS 基线失败；plist 校验／launchd 注册失败；进程未运行、TUN 路由未接管、出口 HTTPS 的 DNS／连接／超时／TLS／响应／未知失败；就绪过程中进程或路由变化；恢复／清理失败。
3. primary 原因与 rollback/cleanup 分开保留；errors.Join 中恢复错误不得盖掉原启动原因，且不能在恢复证据不足时声称“已恢复”或“未影响 VPN”。取消及读取诊断失败也不得覆盖原始失败。
4. 助手通过受控字段传递枚举与本次操作结果；若需要扩展响应，解码器必须显式兼容旧助手无新增字段的响应、拒绝未知／重复／畸形字段，身份验证仍在传递请求之前。不得默默强制已安装旧助手接受新协议或将旧泛化码伪造为新原因；旧助手明确显示“旧版助手未提供详细原因”，升级仍需本机系统授权。
5. HTTP 保留已有 error/apply_error 与 saved/applied/pending 契约，新增固定诊断投影需单独白名单校验。手动启动、手动重载、保存自动应用三入口均展示：错误码、具体失败阶段、仅证据支持的原因、已知恢复状态和对应可执行建议。未知保留未知。使用 textContent，不把返回字段当 HTML。
6. 只读历史 service-diagnostic.json 可辅助用户排查，但其 root 私有权限、mtime、缺请求关联与 UNTRUSTED_DIAGNOSTIC 必须明确；不得将旧回执当本次请求权威或用它取代新助手内存原因。不为读取它新增 root 任意文件／命令接口。

## 精确传输合同（v1）

### IPC 与 HTTP

- 八个既有响应字段 `ok/code/message/loaded/running/helper_version/helper_sha256/config_identity` 仍必需，类型及验证不变。请求与 registration schema 完全不变，单 JSON＋EOF、4096 字节上限不变。
- 响应可增加且仅增加可选对象 `diagnostics`；缺席表示细节不可用，不能由版本字符串推断支持。存在时不得为 null，必须精确包含下述全部字段，不允许其他字段；外层与嵌套层均逐键检查未知、重复、null和类型，不能仅用 json.Unmarshal 结构体解码代替严格检查。

```json
{"schema":1,"operation":"START","outcome":"FAILED","stage":"PROXY","reason":"SYSTEM_PROXY_ACTIVE","rollback":"NOT_ATTEMPTED","restoration":"NOT_ATTEMPTED","cleanup":"VERIFIED","receipt":"WRITTEN","job":"NOT_OBSERVED","tun":"NOT_OBSERVED"}
```

- `schema` 只能为整数1；其余均为固定枚举字符串。`operation`: START/RELOAD/STOP；`outcome`: SUCCEEDED/FAILED/CANCELLED/UNKNOWN；`stage`: NONE/HELPER_PREFLIGHT/JOB/SNAPSHOT/CONFIG/PROXY/SERVER_ROUTE/PUBLIC_ROUTE/DNS/BASELINE/PLIST/BOOTSTRAP/READINESS/HTTPS/STOP/DIAGNOSTIC/UNKNOWN。`job`: NOT_OBSERVED/RUNNING/NOT_RUNNING/UNLOADED/UNKNOWN；`tun`: NOT_OBSERVED/TUN/NOT_TUN/UNKNOWN。
- `rollback/restoration/cleanup` 各自使用 NOT_ATTEMPTED/VERIFIED/FAILED/UNKNOWN；`receipt`: NOT_ATTEMPTED/WRITTEN/FAILED/UNKNOWN。VERIFIED 必须有本次操作内对应证据，未执行与执行未证实分开；启动前清理成功不证明网络恢复。没有保留观察时用 NOT_OBSERVED，读取错误用 UNKNOWN。
- `reason` 只能取下表之一，stage与reason必须匹配。NONE只与stage NONE及outcome SUCCEEDED匹配；SUCCEEDED只能是NONE/NONE或DIAGNOSTIC/RECEIPT_WRITE_FAILED；FAILED不得为NONE；CANCELLED只能为CANCELLED原因，stage保留取消发生处。UNKNOWN只能为UNKNOWN/UNKNOWN。成功 `ok:true` 可省略 diagnostics；若携带则必须SUCCEEDED/NONE/NONE。错误响应允许outcome SUCCEEDED且仅限DIAGNOSTIC/RECEIPT_WRITE_FAILED，表示业务成功而诊断落盘失败。其他不相容组合拒绝为无效协议，不降级成legacy。
- 诊断对象来自同次内存执行证据，不含自由文本、URL、IP、接口名、路径、时间、密码或原始工具输出。HTTP边界再次校验完整对象，不反射helper Message。手动服务失败维持原HTTP状态与 `{error:原粗粒度码}`，可附 `diagnostics`；保存自动应用仍HTTP200，原saved/applied/pendingReload/pendingKnown/etag/apply_status/apply_error保持原义，可附同名 `diagnostics`。无细节时不伪造原因；UI保留粗码并显示“助手未提供详细原因；可能为旧版助手”，而不是断言一定旧版。

### 有限分支映射

下列列出唯一允许的 stage:reason 组合（CANCELLED另适用于任意非NONE的当前stage）。所有原因必须在实际生产分支设置；不通过err.Error匹配、不把底层相同文本等同可信类型。

| stage | reason 与证据来源 |
| --- | --- |
| HELPER_PREFLIGHT | PREFLIGHT_REJECTED：助手preflight返回失败；无更细类型时只说预检拒绝 |
| JOB | JOB_STATE_UNAVAILABLE：state读取失败；JOB_ALREADY_LOADED：启动前loaded或running；JOB_NOT_LOADED：reload要求loaded而未loaded |
| SNAPSHOT | SNAPSHOT_EXISTS：Lstat成功存在；SNAPSHOT_UNAVAILABLE：Lstat其他错误；SNAPSHOT_STAGE_FAILED：stage失败；SNAPSHOT_IDENTITY_FAILED：owned获取／check失败 |
| CONFIG | CONFIG_COMPILE_FAILED：staged outbounds或baseline内编译失败，不能推断语法／密码错误 |
| PROXY | SYSTEM_PROXY_ACTIVE：checkProxyInactive实际发现HTTP/HTTPS/SOCKS enable=1并返回专用typed标记；PROXY_STATE_UNAVAILABLE：scutil执行失败，不能因通用proxy seam错误断言启用 |
| SERVER_ROUTE | SERVER_ROUTE_UNAVAILABLE：route读取失败；SERVER_ROUTE_NOT_PHYSICAL：实际iface非physical；SERVER_ROUTE_CHANGED：实际旁路比较不符 |
| PUBLIC_ROUTE | PUBLIC_ROUTE_UNAVAILABLE：读取失败 |
| DNS | DNS_STATE_UNAVAILABLE：读取失败；DNS_EVIDENCE_EMPTY：实际返回空列表 |
| BASELINE | BASELINE_INVALID：validBaseline或baseline读取／验证失败（未标为CONFIG者）；BASELINE_WRITE_FAILED：Marshal／Write失败 |
| PLIST | PLIST_CREATE_FAILED：生成／独占创建失败；PLIST_WRITE_FAILED：写或关闭失败；PLIST_INVALID：plutil失败 |
| BOOTSTRAP | LAUNCHD_BOOTSTRAP_FAILED：bootstrap工具失败，不推断权限或系统根因 |
| READINESS | READINESS_JOB_UNAVAILABLE／READINESS_ROUTE_UNAVAILABLE：对应读取失败；READINESS_CHANGED：HTTPS前后或重试前实际job/完整utun身份变化；PROCESS_NOT_RUNNING／TUN_NOT_READY／PROCESS_AND_TUN_NOT_READY：16次观察耗尽，分别按最后可信job和route组合；保留job/tun两个观察，读失败直接归读取失败，不合成耗尽；READINESS_UNKNOWN：缺乏可信观察 |
| HTTPS | HTTPS_DNS_FAILED：typed curl ExitCode=6；HTTPS_CONNECT_FAILED=7；HTTPS_TIMEOUT=28；HTTPS_TLS_HANDSHAKE_FAILED=35；HTTPS_CERTIFICATE_FAILED=60；HTTPS_HTTP_FAILED=22；HTTPS_EMPTY_RESPONSE=52；HTTPS_RECEIVE_FAILED=56；HTTPS_RESPONSE_INVALID：成功响应无法解析为IP；HTTPS_FAILED：其余退出码／未知错误；不可推断为AnyTLS密码错误或节点证书错误 |
| STOP | STOP_FAILED：原stop链失败；只表示停止／恢复链未成功，详细恢复由独立状态呈现 |
| DIAGNOSTIC | RECEIPT_WRITE_FAILED：本次r.write失败且无业务主错误 |
| UNKNOWN | UNKNOWN：未覆盖的可信阶段无法确定，不从普通错误文本猜测 |
| NONE | NONE：仅成功 |

curl分类只用 errors.As ExitCode，原重试集合6/7/28/35/52/56、次数、期限、目标与TLS均保持不变；新增60/22只是说明观察，不加入重试。建议必须是“检查／核实”而非已证实根因，不建议关闭证书校验、删除快照、反复重试或直接停止VPN。

### 主错误、恢复与落盘顺序

- 每次生命周期维护调用私有的结构化状态／typed carrier，保留业务错误链。首个导致本次业务终止的失败固定为primary；恢复defer追加错误仅更新rollback/restoration/cleanup，不从errors.Join任意errors.As遍历重选primary，errors.Is/As原原因身份保留。
- HTTPS可重试中间失败不成为终止primary；最后一轮失败或下一轮前状态／路由／期限检查失败才是终止primary，阶段以实际终止处为准。若是取消，stage为取消发生处、reason CANCELLED，不能倒称旧DNS错误是本次终止根因。恢复中的取消不覆盖已经固定的业务primary。
- reload停止失败保留外层STOP_FAILED，start禁止执行；停止成功后的新start失败，operation=RELOAD，primary取新start。旧连接已停止不能声称已自动恢复旧VPN；rollback仅指新start自己的回滚。无本次网络恢复验证时restoration不得VERIFIED。
- rollback VERIFIED需原逻辑确认整个新启动回滚成功；restoration VERIFIED仅对应既有完整路由／DNS恢复核验；cleanup VERIFIED仅对应本次自有快照成功删除或确认本次无需快照且为空，不通过不存在快照推断网络恢复。执行失败与证据不可读分别FAILED／UNKNOWN，未尝试NOT_ATTEMPTED。
- r.finish前固定业务结果，r.write成功后receipt WRITTEN，否则FAILED；无需额外写回执以更新receipt字段。若业务已失败，write失败仅为附属receipt状态，不盖掉primary。若业务成功但write失败，diagnostics outcome=SUCCEEDED,stage=DIAGNOSTIC,reason=RECEIPT_WRITE_FAILED；保持当前返回错误／保存pending行为不变，页面显示“启动操作已成功，但诊断保存失败，应用状态仍须核实”，不假报业务启动失败、不新增回滚。

### 兼容与授权方向

- 新客户端读取旧助手八字段响应（diagnostics缺席）兼容；新客户端读取新助手严格校验上述对象。旧客户端读取新助手不承诺兼容：当前旧解码器拒绝未知字段。本轮不新增协议协商，不默默绕过该校验。
- 发布程序更新与已安装root助手升级是不同步骤；只在用户本机明确执行现有授权安装流程后更新助手。HTTP不安装／重启／注册助手，诊断改动不授权操作正式助手或VPN。旧助手不提供细节时仅提示此限制及可由用户选择的本机升级流程。
- 历史service-diagnostic.json只属文档给出的可选本机只读辅助，不新增HTTP/file/log接口，不变更权限、不为它提权。其mtime、历史与不可信性质须保留；文件不可读就记不可用，不依赖读取它来通过本功能验收。

## 验证门

- 全链测试只使用临时目录内的自建 Unix socket、合成UID／生命周期工具seam和敏感标记；禁止连接已安装助手或运行launchctl控制、修改路由／DNS／系统代理、真实VPN启停或sudo。规格审查及本地schema测试不使用SSH；随后获既定开发授权的Mac原生编译／测试仅经SSH操作隔离候选，不因此授权生产控制。
- 先建立相同测试在旧代码的业务 RED；真实生命周期入口注入具体阶段错误，经 execute→真实 Unix IPC→webControlAction→认证 ServeHTTP 验证结构化原因和脱敏，而非只测分类 helper。
- 覆盖相同文本不同错误身份、原始敏感标记、未知码、重复键、旧新助手协议、primary+rollback 两错误并存；保存失败反馈仍区分已保存未生效。
- 浏览器分别验证手动服务失败与保存应用失败的可读原因和风险／恢复提示；不能只改一条文案冒充后端可诊断。
- Mac 隔离 native full/vet/build、独立精确 SHA 复审后再按既定流程新版本发布；不覆盖现有 tag，不执行正式 VPN/helper 安装控制来构造失败。

本规格待独立审查，未宣称实现或用户故障已解决。用户机器本次原因仍需只读状态／诊断证据。
