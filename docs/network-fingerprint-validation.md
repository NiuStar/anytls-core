# 默认 TLS 指纹候选：隔离验收

本说明记录候选，不表示已发布、安装或切换 VPN。生产 v2026-10-24-03 及其不可变附件保持原样。候选未提高 VERSION，执行 version 仍报03，必须按 SHA 区分，不能冒称公开03已包含默认值改动。

## 改动与边界

仅中央 buildNode 的 TLS 指纹默认策略改变：未填写时用现有 Chrome/uTLS，精确 `golang` 使用标准 Go TLS，其他显式值保持原字节。所有旧节点中未填写指纹的项也受影响；不只作用于新订阅。CA/SPKI、跳验授权、密码、路由、DNS、TUN、空闲会话及 SDK/依赖锁未变。

不改 ALPN、分片、填充或时序，不增加假 HTTP，不删许可证或构建身份，不声称检测率或不可识别。详情：[网络指纹最小化](network-fingerprint-minimization.md)。

## 真实证据

- 相同测试字节绑定旧源码取得行为 RED，再验证候选 GREEN；既有依赖、wrapper 和两份补丁身份一致。
- Linux 完整 tracked 源码：399 主测试 PASS、800 子测试 PASS，5 SKIP；无 uTLS 定向3主／29子 PASS。Linux 最终 vet/build 真实磁盘写满失败，保留原始日志，不计成功。
- Mac Go1.26.8：405 主测试、811 子测试 PASS，3 SKIP；vet/build 成功。缺 uTLS 时默认路径明确拒绝，显式 golang 成功构造，无静默回退。
- 真实 buildNode→embedded engine→mixed SOCKS→AnyTLS→自有回环 echo，在 CA 和 SPKI 两种身份策略下，默认、显式 Chrome、显式 Go 共六例成功；TLS 服务端实际收到 ClientHello。
- 默认／Chrome：GREASE cipher/curve 均有，16 cipher、3 supported-version，ALPN offers 为 h2/http1.1；Go：无该 GREASE、13 cipher、2 supported-version、ALPN offers为空。它们只是观察到的预设信号，不证明完整浏览器指纹一致，也未记录协商 ALPN，不把 AnyTLS 称作 HTTP。
- 对端 TLS 解密后的 Settings 实际确认 client= 为空、不带引擎品牌；只输出布尔分类，不保存口令或原始解密载荷。此前源码判断已得到本轮实际观察支持。
- 新候选 CLI 对正式 anytls-go v0.0.28：默认／Chrome／golang 三种模式各正常、错误 SPKI、错误密码，共九例 PASS。三个正例精确回显114字节，六个负例目标零连接、零载荷；子进程已 wait、echo线程 join、端口回收。
- Python 安装器与 wrapper 回归通过。独立 SPEC 和最终 QUALITY 通过，父任务重新核源码／回执／原生产身份；生产配置、密码、进程、DNS/proxy未变。

## 候选产物

Mac 私有路径：`/Users/lihaiyan/anytls-network-privacy-v1-20261024/privacy-candidate`

SHA-256：`34a89cc8006f8ce25af14fe8deec2510522a66f7fde60a1b47784e33d2d58018`

这是未安装的隔离候选；没有创建新 Release、没有覆盖18089、没有升级助手或重连 VPN。切勿按文件名或相同 version 输出与正式程序混淆。发布需要新版本及对应构建／CI／附件门；生产启用需要明确授权。

原始审查、测试、失败与父级读回：`artifacts/network-privacy-v1/`（不随源码公开）。
