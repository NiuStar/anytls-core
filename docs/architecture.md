# 架构与边界

版本 v2026-10-19-01 使用独立 sing-box 核心；未复制或内嵌其实现。

```text
anytls command (Go)
  ├─ YAML 节点/策略组/规则解析及严格验证
  ├─ TTY 交互选择
  └─ sudo → launchd 系统任务（非开机自启）
       └─ service/anytls-macos run
            └─ service/sing-box run -c service/runtime.json
```

- 用户入口解引用符号链接后寻找同目录 config.yaml、sing-box。
- start 先解析配置、核对引用节点物理路由、拒绝已加载服务，生成当次服务快照。
- service/ 复制程序、核心、YAML、选中状态、SHA 校验过的规则文件；路径改写到快照。
- root 快照与用户目录更新隔离；改配置需要显式 stop/start，不自动热切换。
- 不以进程存在代替启动成功：检查公网 TUN 路由、服务器旁路与 HTTPS 响应。
- stop 仅卸载固定 label 的本工具任务，并对比路由与 DNS 基线。恢复核对失败须人工检查。

## 分流转换

配置规则按原顺序转换。域名嗅探、DNS 劫持与反向映射提供域名可见性，不保证所有应用目标都有可见域名。select 组使用显式 selected，而非偷偷采用第一个成员。RULE-SET 仅引用已转换的 JSON 文件，校验 SHA 并内联到运行时。

离线迁移流程：固定原源字节/SHA → 用官方 Mihomo `convert-ruleset domain mrs` 或 `ipcidr mrs` 解码 → 严格域名/CIDR/classical 白名单映射 → sing-box compile/match/check。工具、原始规则集和节点数据没有提交到本仓库。未知语法不得静默跳过。远程规则集 interval 更新尚未实现。

## 后续内嵌核心方向（未实现）

先固定依赖版本，自定义最小协议注册，再研究 Box 生命周期集成；保留 AnyTLS、TUN、选用的网络栈、DNS、DIRECT/REJECT、规则与 TLS/uTLS。裁剪大小、内存节约和兼容性须实测，不能预先承诺。深度源码分叉不是本版本内容。

## 法律与安全

独立 sing-box 上游：https://github.com/SagerNet/sing-box/tree/v1.14.3 。其 LICENSE 为 GPL-3.0-or-later，另有名称/关联限制，应保留并核对；本项目不代表上游官方。不要将上游核心重命名后宣称为独立原创实现。未来复制/链接核心须重新核对上游和传递依赖许可。

不保存 sudo 密码；不提供提权绕过；不记录节点密码。配置可普通读取不代表秘密受到保护。skip-cert-verify 只是显式兼容选项，没有服务端身份保证。没有 kill-switch，网络故障或崩溃后不能保证无泄漏。
