# Changelog

## v2026-10-19-01

首个源码版本，冻结现有 macOS AnyTLS CLI 实现。

- Go CLI：start、stop、status、config、list、check、run。
- 通过独立 sing-box 1.14.3 管理 macOS TUN、DNS 与 AnyTLS TCP/UDP 数据面。
- launchd root 服务快照、服务器旁路、启动路由/HTTPS 出口检查与停止恢复检查。
- 终端节点和 select 策略组选择，Enter/Space 确认。
- 有序分流、SHA 固定本地规则集、显式 DNS resolve 时点。
- 单元测试、macOS plist 检查测试、无凭据的配置示例。

不包含：内嵌或瘦身 sing-box、真实节点密码/配置、在线规则数据、自动刷新、kill-switch。此次为源码与 Git 标签，不是签名/公证的 macOS 应用发布。验收范围见 README。
