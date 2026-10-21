# 安装后自动切换 WebUI

## 当前契约

- 公开二进制安装器在下载校验、材料保留、助手安装、程序备份及替换成功后，自动启动默认 127.0.0.1:18089 的新版 WebUI。
- 只关闭默认端口上已确认属于本工具、当前用户、完整命令匹配的 WebUI；PID 文件只是提示，不能单独授权发送信号。
- helper 失败不关闭旧 WebUI；外来监听者、身份不明、旧进程无法退出或新版无法就绪均明确报错，不冒称安装全完成。
- 仅 WebUI 重启；VPN label、快照、PID、路由、DNS、已有配置和密码不随此动作改变。新网页进程的会话需要重新登录，应用密码不变。
- 首次安装无旧 WebUI 时直接启动；check-download 不执行、不启动、不关闭任何进程。
- 本改动仅公开可信 Python 安装器与文档，不改变 v2026-10-21-03 的不可变二进制附件。

## 实施和验证门

1. 实现及 UNIT 回归、旧版缺少自动切换的敏感度见证。
2. 父规格核对与独立质量复审。
3. Mac 隔离普通用户目录，用已验证官方二进制实际首启／切换并请求 HTTP，原生监听进程 UID／完整命令／PID 读回。
4. Mac 正式 WebUI 获本次指令授权切换，前后 VPN PID/program/runs 与配置／密码摘要不变；不得调用 VPN stop/reload。
5. 提交推送 main、公开脚本精确读回，报告真实验证范围和失败边界。

## 验证结果

- 已审安装器 SHA256：`3834d42c33e291961a7cea2c6ec1e3fcec42a5f2dd2982b009b26f6126b3a3cb`。独立 SPEC／QUALITY PASS，未发现范围内 P1/P2。
- Linux 本机通过：46 项 binary installer、24 项 source installer、6 项 packaging UNIT；Mac Python 3.9 上46项 UNIT通过。UNIT 的进程／网络边界为模拟，不称真实完整安装。
- 原生预检准确识别正式 WebUI 的当前用户、完整启动命令及 PID。真实 Mac 上 `lsof -Fp` 会返回文件描述符行，已改 `lsof -t` 并实测；旧版夹具缺陷和原生 `/var`／`/private/var` 单侧 resolve 失败日志保留，修复后另次通过。
- 使用上述原字节安装器的 WebUI 生命周期代码，实际关闭正式旧 WebUI PID5361，启动官方 Release03 程序，监听 PID15057。首页就绪、真实登录、version API `v2026-10-21-03`、helper API available 均已验证。
- 切换前后 VPN 的 launchd PID／program／runs／state、正式程序与config／selected／WebUI密码摘要、scutil DNS／proxy摘要完全一致。没有执行 VPN start/stop/reload，也没有重装助手。
- 用户已在本机真实运行旧安装器完成 root helper 安装和普通程序替换；本轮验证的是已审新脚本的真实 WebUI 切换阶段，没有重复整个需系统授权的安装过程。
- 本轮未单独占用生产默认端口再做隔离首装。首次无旧进程路径由 UNIT覆盖；正式旧进程退出到新版绑定及登录已原生实测，不冒称完整首次安装实测。
- 进程身份来自多次 ps 与秒级启动时间，只用于当前受控用户环境下的正常误操作防护，不抵御恶意同 UID／任意 PID 重用；失败仅明确报错，不声称全流程原子回退。

运行中的会话因 WebUI 重启需重新登录，密码保持不变。安装自动切换仅针对默认18089端口；其他自定义端口不自动迁移。
