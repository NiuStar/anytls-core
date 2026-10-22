# 配置大小上限：32 MiB

配置上限统一为 `32 << 20` 字节（33,554,432 字节），不再使用 4 MiB。适用于本地配置读取、服务快照、WebUI 原始配置保存、文件／粘贴导入、订阅响应读取及转换后的 YAML 输出。远端 provider 也复用现有有界抓取；展开后最终配置仍须满足同一上限。

- 文件和粘贴入口按 UTF-8 字节计数，不是字符数。
- `PUT /api/v1/config` 和 `POST /api/v1/import/preview` 的 JSON 请求预算为 `6 * snapshotConfigLimit + (16 << 10)`，容纳每字节最多六字节的 JSON 转义及信封开销。该传输预算不提高解码后的 YAML 上限。
- 其他 JSON 请求仍限制为 16 KiB，未知字段和多个 JSON 值仍拒绝。
- 订阅响应／导入原文过大沿用 `IMPORT_TOO_LARGE`／`IMPORT_INVALID` 等已有入口错误；转换器原文或序列化输出超限使用 `CONFIG_CONVERSION_TOO_LARGE`，前端明确提示 32 MiB，不再将序列化超限描述成格式无法识别。循环或非法 YAML 仍为 `CONFIG_CONVERSION_INVALID`。现有 alias 展开工作量保护保留；其无效／超预算判定不改成按输出字节的承诺。
- 转换 writer 保留取消原因，调用者可用 `errors.Is(err, context.Canceled)` 等与超限区分；HTTP 不返回底层细节。
- 不通过规则去重、删除、重排或合并来绕过配置上限。既有不支持内容处理策略不变。
- 节点选择、单个规则文件、CA、引用数量及其合计上限均未改动。

## 回归覆盖与执行边界

`config_size_limit_test.go` 覆盖大于 4 MiB 原生输入的原字节保留、远端 provider 展开到大于 4 MiB 后全部重复规则及顺序保留、32 MiB + 1 原文拒绝、转换 writer 边界及取消原因、最坏 JSON 转义信封可达和其他控制请求的 16 KiB 限制。已有快照超限测试改用共享常量，避免仍按 4 MiB 构造负例。

本次准备环境无 Go／原生 macOS 工具链，Go 测试、gofmt 与原生验证须由父任务执行；不得把这些回归的源码准备当作已通过的运行结果。
