# DNS 聚合观测：CLI 使用契约

## 显式启用，完成后汇总

仅 `embedded_core` 构建的前台 `run` 支持 `--dns-metrics`。所有 flags 放在命令前，例如在 macOS 上：

```sh
anytls --config /path/to/private.yaml --node example --dns-metrics run
```

默认关闭；省略该 flag 或使用 `--dns-metrics=false` 不创建 DNS observer、不写 DNS metrics 日志。不会修改服务配置、LaunchAgent、helper、WebUI 或后续运行的默认行为。没有环境变量、远程接口或持久化开关。

`--dns-metrics check|list|select` 在读取配置前明确拒绝；非嵌入构建的 `--dns-metrics run` 明确报 `requires embedded_core`，不会静默忽略。命令缺失和既有 `--core` 校验仍保持原有优先级。`run` 的平台限制及其他参数校验不变；`anytls help` 和 flags 帮助提供该入口。

## 输出及错误契约

- 一个前台 run 独占一个 observer，沿既有 runtime context 传递，不覆盖取消信号或 startup timeline。
- 只有进入嵌入式 engine run 后，才在 run 返回时向 **stderr** 尝试写一条 JSON 行；正常返回、取消或 engine 错误均执行该 finalizer。配置准备失败、参数拒绝和未进入 engine run 不产生汇总。强制杀进程、崩溃或 stderr 不可写时不能保证有输出。
- 顶层字段固定为 `event` 和 `metrics`；`event` 固定为 `dns_metrics_final`，`metrics` 为 SDK `DNSMetrics.Snapshot()` 的固定结构聚合快照，不是嵌入的 JSON 字符串。
- 不增加 stdout 输出。stderr 仍可能同时包含既有日志或主错误；消费者应逐行筛选 JSON 的 `event`，不可把整个 stderr 当作单一 JSON 文档。
- 快照不包含查询名、域名、查询 payload、原始 error、完整配置或凭据；仅提供受限标签及聚合数据，不暴露 token。
- 汇总写入失败不重试、不 panic、不替换 DNS/清理的主错误或退出码；只尽力写受控的 `dns metrics summary unavailable` 提示，不打印底层写入错误。

这是**完成后一次性汇总**，不是实时监控。没有定时器、周期 goroutine、HTTP metrics endpoint、自动文件输出或 WebUI 面板。普通 stderr 写入是同步的；调用者应确保 stderr 持续可写，不应把无人读取的管道作为输出端。

## 解读边界

仅能依据实际 SDK 快照及其受限分类解读。HTTP 503 若没有可靠的 typed error，不应被推断为独立 HTTP 状态类别；普通错误不等价于已观察到 503。缓存命中与 coalescing 若当前接缝不可观测，结论必须记为 `NOT_OBSERVED`，不能把缺失观测显示为零命中或零合并。空闲运行的零计数也不是性能收益证明。

本节仅定义 CLI 入口与输出契约，不声称已经完成原生 macOS、真实 DNS 请求、协议回归或性能验收；实际测试结果及最终证据由验收报告另行追加。
