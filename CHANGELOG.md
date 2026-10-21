# Changelog

## v2026-10-21-03

- 增加 macOS arm64 预编译包、一键下载校验安装脚本，以及对应源码／依赖源码和许可证附件；不要求普通用户本机编译。
- 一次本机系统授权安装受限 root 助手，之后 WebUI 通过内核 UID 认证的 Unix socket 控制固定服务动作，不保存系统密码。
- 网页保存配置自动应用，按运行状态显示按钮；TLS 跳验只显示风险提示，仍遵循节点明确配置。
- 分阶段返回助手／配置／停止／启动错误；配置身份绑定、安装事务就绪验收与失败回退。
- Mac 原生211顶层／427子测试PASS、3SKIP，vet/build通过；真实root安装与VPN自动应用仍需用户本机授权验收。

## v2026-10-21-02

- 策略组选择保存改为 YAML 局部编辑，保留未知字段、标量类型和注释；同值不写。
- 新增 `reload`：当前磁盘配置预检后受控 stop/start；允许连接运行期间保存下一次配置。不是无缝热重载，启动失败不保证恢复旧连接。
- 新增源码一键安装与 `update [--check] [--version TAG]`、固定工具链、旧程序备份与配置保留；源码升级不自动重启 VPN/WebUI。
- 新增普通用户本机 WebUI（127.0.0.1:18089）、admin 应用凭据、`password [reset]`、会话/CSRF/Host/Origin、防爆破和原生系统授权；网页不接收系统密码。
- 新增节点、策略组、规则及原始配置编辑；区分磁盘配置与运行快照。
- Mac 原生 166 顶层／332 子测试通过，3 项跳过，vet/build、浏览器与隔离真实安装／重装通过；本轮特权 TUN reload 留给用户本机测试。

## v2026-10-21-01

- 默认发布构建改为 Go 内嵌精简 sing-box 核心，保留 AnyTLS、gVisor、Chrome uTLS 和外部对照模式。
- 加固共享配置编译、规则／CA 私有快照、生命周期及停止恢复检查。
- 修复单次 HTTPS 探测的脆弱性：明确瞬时 curl 错误最多三次，保留路由检查和失败恢复。
- Mac 原生 114 顶层／252 子测试通过，3 项跳过；vet、build 通过，真实代理 HTTPS 通过。
- 固定源码 Release；不包含私有配置、测试日志或二进制附件。最新修复版持续 TUN 体验待验证，不声称所有间歇故障已解决。

## v2026-10-19-01

首个源码版本，冻结现有 macOS AnyTLS CLI 实现。

- Go CLI：start、stop、status、config、list、check、run。
- 通过独立 sing-box 1.14.3 管理 macOS TUN、DNS 与 AnyTLS TCP/UDP 数据面。
- launchd root 服务快照、服务器旁路、启动路由/HTTPS 出口检查与停止恢复检查。
- 终端节点和 select 策略组选择，Enter/Space 确认。
- 有序分流、SHA 固定本地规则集、显式 DNS resolve 时点。
- 单元测试、macOS plist 检查测试、无凭据的配置示例。

不包含：内嵌或瘦身 sing-box、真实节点密码/配置、在线规则数据、自动刷新、kill-switch。此次为源码与 Git 标签，不是签名/公证的 macOS 应用发布。验收范围见 README。
