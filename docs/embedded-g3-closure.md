# G3 收口：用户已接受的有限覆盖

状态：**G3 PASS WITH USER-ACCEPTED LIMITATIONS**。2026-10-20，用户在会话 `e79522211f04` 对紧邻的完整限制提案回复“接受”。该决定只收口 G3 并推进 G4 准备，不授权正式切换、launchd 停启或 TUN。

## 实际证据

- 固定 Go1.26.8、darwin/arm64、CGO0，保留 gVisor/uTLS；A 为匹配外部 CLI+官方核心，B 为同应用全注册，C 为最小注册。架构标签差异明确，不作纯 registry 因果归因。
- C 二进制 30,002,914 bytes，B 53,967,186 bytes。离线真实安装与 staged snapshot 合计逻辑字节：A 123,306,338、B 107,982,614、C 60,054,070；不等同 APFS 增量或 G5 完整发行包。
- 安装42、v6矩阵14、微基准36、生命周期23，共115份精确回执重新核验长度/SHA；canonical 71份源码内容未变。
- 原生 CPU 经验校准确认 Mach ticks、timebase125/3；A/C 完整生命周期单次 wait4 CPU 为0.191104/0.121205秒，不据单次结果推断统计改善。
- 162连接、41,949,184 bytes 完整性通过，严格TLS负例零新增业务，进程回收通过。FD恢复 A14→14、C8→8；C engine 10次Check、10次Run取消后 goroutine 均回到baseline5。

## 明确接受的限制

1. canonical A/C CLI 内部 goroutine 不可观测，C engine 测试进程仅为有限补证。
2. cold 仅指新进程空会话，不含系统页缓存 cold；cold connect 与 warm 已建流交换计时边界不同，不作完整同口径比较。
3. RSS 通过预注册有限预算，但晚期仍正增长；不宣称零斜率、RSS平台或无限期无泄漏。
4. 保留 v5 不利尾延迟；v6当前主p95约C/A +0.92%仅为该固定方案的有限结论，不证明旧问题根因已消除。
5. 实际XNU与公开参考源码版本未匹配；本机CPU单位靠前向校准，不追溯换算历史v6原始CPU。

旧 HOLD、失败尝试、不利样本和审查均不改写。机器收口记录、输入SHA和完整准则映射保存在私有证据 `NEWg3-approved-closure/closure.json`；独立最终资源审计为 `NEWg3-lifecycle-resource-audit/REPORT.md`。这些私有回执不随本文件公开。

## 下一阶段

G4.1先隔离无特权候选、PTY组选择、完整规则与业务命中；真实配置只留Mac。G4.2须先核验当前root私有运行身份、完整回退集，并确认维护窗口及Mac本机权限后才可有界TUN验收。G5源码/许可完整发布、正式入口切换仍未完成。
