# WebUI 状态按钮与自动应用修订

基线正式版 v2026-10-21-02 / 02bf743；分支 fix/webui-auto-apply。

## 用户要求与实施契约

- 运行中隐藏“启动 VPN”，未运行时显示；未加载且未运行隐藏“停止 VPN”。loaded但不running保留启动及停止以便清理，状态未知隐藏所有服务动作。
- WebUI 的配置 YAML、节点参数、bootstrap选择、策略组选项保存且内容变化后：若 VPN 正在运行，同一个服务端动作锁内自动调用现有 reload；未运行仅保存，不启动。
- 同值保存不写、不重连；保存校验失败不重连。
- TLS 跳验仅来自用户勾选本次明确授权，不因自动应用隐式允许；checkbox放在各配置视图都可见位置。仍需要 macOS 原生管理员授权，不接收系统密码。
- 自动 reload 非无缝热更新，会短暂重连。保存成功但自动应用失败要显示“已保存但未生效”，保持pending，不让用户以为文件未保存或连接成功；保留仅在pending且running时出现的重试按钮。
- 自动应用以实际服务状态、命令成功、重载后的状态和配置fingerprint复核为准；失败或配置并发变更不清pending。不能因HTTP断开提前释放动作锁。
- 不加入外部文件watcher；CLI或外部编辑器改文件仍使用现有reload命令，页面提示明确区分。

## 验证状态

- Chromium + synthetic API 已验证 running/stopped/unavailable按钮、四保存接口发送confirm_insecure、授权用后清除、成功反馈、390px无溢出和无JS异常。这是前端交互测试，不是真实VPN重载。
- 后端认证 handler 的四路径自动应用、状态矩阵、TLS 授权、同值／拒绝不触服务、失败保留 pending、并发配置更改及 HTTP 取消持锁回归通过；服务动作是测试替身，不是正式 TUN。
- Mac 原生定向及全套通过：172 顶层／386 子测试 PASS、3 顶层 SKIP；vet/build rc=0。源码、日志和二进制 SHA 已独立读回。二进制 SHA256 `c121549c38a8f06b079e921ec8bbaac6afd17c87d822eade88c21505a27ef914`，VERSION 仍为基线值，不代表新增 Release。
- 首轮独立审查发现保存成功后列表刷新失败会丢失保存／应用结果并保留已使用的 TLS 勾选；已修复为组装请求时消费本次授权、响应后立即展示结果，后续刷新失败仅追加警告。四入口 × APPLIED/APPLY_FAILED 共八个真实浏览器合成 API 回归通过，下一次保存确认不复用授权；旧实现同一回归业务失败，日志保留。
- 修复只改嵌入 JS，Go 后端未变，保留原172/386/3skip测试与vet证据；最终页面重新在Mac构建，build rc=0，二进制SHA256 `65a6794aa7dc30c396def55b0f9a332c2c8db4e909d3ecfbd20e0c92fe0602b8`。最终独立复核 `PASS_SCOPED_QUALITY`，原 FAIL 保留；六源码及最终 Mac build log／binary SHA 已由父独立读回一致。
- 本轮尚未替换正式程序或重启正式WebUI/TUN。
