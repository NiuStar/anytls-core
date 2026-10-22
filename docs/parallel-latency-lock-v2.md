# 并发测速读写锁修订 v2（待审）

前置：docs/parallel-latency-and-routing.md 的A规格已通过，但其排他TryLock收尾在真实认证HTTP→TCP→广播结束夹具中，40次结果仅16个200、24个409；没有外部mutation。这是产品体验阻断，不以符合旧规格免除。本修订仅替换A的动作锁所有权，8名额、前端整数/颜色/取消、认证与ETag、TLS/目标/期限合同均不变。B路由不改。

## 最小变更

- webConsole.actionMu由sync.Mutex改sync.RWMutex。所有现有配置／服务mutation及原GET保护仍走现有Lock/TryLock/Unlock的排他语义，不给任何写操作改用RLock。
- 只有POST /nodes/probe的入口捕获和最终发布两个短阶段使用TryRLock/RUnlock，均不等待锁。多个probe允许同时读；mutation持有写锁时返回409 ACTION_BUSY，无样本。网络与同步Close仍不持读锁。
- 入口读锁内解码、捕获配置、校验If-Match并解析精确节点；最终读锁内重读ETag、复核取消／期限与响应写入。当前/等待writer按Go RWMutex既有语义阻止新读者；不自造调度器或重试队列。
- probeSlots仅初始化一次：独立sync.Once创建固定容量8 channel；初始化不能再依赖排他actionMu，也不能在共享读锁内未同步写同一字段。所有TCP/HTTPS共享该channel，名额一直覆盖同步Close实际完成及最终响应，所有返回路径defer释放。
- 响应阶段持读锁维持当前合同；不是任意慢客户端硬实时保证。短锁仅表示不覆盖网络探测，不承诺32MiB解析耗时固定。

## 行为验证

1. 保留初始旧串行RED和旧排他收尾缺陷记录，不改写旧PASS或旧规格审查。新要求测试在当前v1 backend必须业务RED，不能用编译失败代替。
2. 同步广播8个真实TCP已完成的请求，5轮每轮必须8个HTTP200/OK且latency非负，总40个200/0个409；每轮第9个返回429且无网络。不得错开放行或重试掩盖竞争。再用入口同时发起fixture验证无writer时不会因probe互斥409。
3. 保留入口writer占锁409、最终writer占锁409无样本、ETag改变412、全部8名额+取消恢复、取消但Close阻塞仍占名额、认证/CSRF/Host/Origin与method拒绝矩阵。
4. 完整Mac native full/vet/build与真实loopbackHTTP门；可用同源CGO启用的定向race测试独立检查同步，若工具链不支持明确未测，不以CGO0不支持冒充race通过。精确源码独立QUALITY复审后才允许发布。

此修订没有放松与mutation的互斥；消除的是只读probe彼此的排他争用。既有8测试中未断言并行样本全部发布的条目保持不变，新的强断言补齐真实用户目标。
