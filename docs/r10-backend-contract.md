# R10 backend contract（实现中，字段已固定）

现有Host/Origin/session/CSRF认证，POST JSON严格拒绝未知字段。GET `/api/v1/profiles` 原精确projection不变；新UI用 `GET /api/v1/profiles?detail=1`，新增顶层 `active_id`，每项新增 `version`（完整私有记录摘要，只作opaque并发版本）、`linked`。`current` 在detail模式表示稳定活动ID，旧模式仍表示三文件精确相等。保存/复制名称碰撞409；POST `/profiles/rename` `{id,name,version}`；POST `/profiles/delete` `{id,version,confirm:true}`，活动方案拒绝删除。完整switch CAS固定：detail新增顶层 `switch_version`（opaque `switch-v1-<hex>`）；新产品POST `/profiles/switch` 必须提交 `{id,snapshot_version:detail.switch_version,confirm_replace:true,confirm_insecure:true}`。snapshot_version绑定active ID与config/selected/subscription三文件存在性及精确bytes，actionMu内校验，错误412且无副作用。也接受If-Match带引号的switch_version；与YAML etag严格分离。提供snapshot_version时优先且失败绝不退回YAML If-Match。旧调用仅YAML If-Match兼容但不宣称完整snapshot CAS；新UI不得走此兼容路径。原confirm_replace/confirm_insecure保留。

GET `/api/v1/subscriptions` => `{subscriptions:[{id,profile_id,profile_name,source_host,auto_check,last_check,next_check,last_updated,result,busy,version,candidate_version,target_version,conflict,selection_invalid,has_previous}],interval_seconds:3600}`。id就是稳定profile ID；URL仅私有0600方案文件保存，公开只host，不返回路径/query/raw YAML。时间RFC3339Nano，尚未检查为空字符串。忙只在进程内，不伪造离线检查。

POST `/api/v1/subscriptions/preview` `{url,name}`（name可空自动取不重名“订阅方案”）=> `{token,name,source_host,nodes,groups,rules,conversion}`，10分钟、会话CSRF绑定，取消只需不提交。POST `/subscriptions/import` `{token,name,confirm:true,confirm_insecure:true,accept_conversion:true}` => `{ok,id,name}`，创建独立方案，不激活。name可在确认前改，碰撞拒绝。

POST `/subscriptions/check` `{id}` 同步等待真实网络，期间不持action锁；同源单任务409；返回上述单个公开订阅DTO。自动检查与手动相同链路。非活动无人工冲突且选择身份有效可以自动保存；当前/人工冲突/失效选择进入候选。失败保旧内容。

POST `/subscriptions/options` `{id,auto_check:true,version}`；`version`使用GET subscriptions对应version。POST `/subscriptions/apply` `{id,target_version,candidate_version,confirm:true,confirm_insecure:true,accept_conversion:true}`，两版本必须与GET精确一致；失效选择可另带 `selected` 指定候选内有效节点，不自动按同名猜测。当前方案使用既有保存/应用链，停止时不启动。POST `/subscriptions/restore` `{id,version,confirm:true}` 只将前版本准备为候选，再通过apply确认完整目标与候选。POST `/subscriptions/unlink` `{id,version,confirm:true}` 保方案删除关联及候选，不动网络。所有POST路径前缀 `/api/v1`。

POST `/subscriptions/apply` 失效选择时必须带 `selected`，GET每项的 `candidate_choices` 提供候选可选节点名数组（仅名字，不含凭据），不能只提示“稍后重选”而不给合法提交路径。若策略组旧选择身份失效，候选保留提供商本身明确的组选择，但必须人工确认，不自动保留同名旧选择。

后台：WebUI真正服务生命周期启动独立worker、退出context取消，进程常驻每小时（每分钟扫描已持久化next_check）。重启只对已到期任务执行一次，不补造停机期间记录。保存/编辑同步只有确切active_id，不覆盖其它同内容方案。
