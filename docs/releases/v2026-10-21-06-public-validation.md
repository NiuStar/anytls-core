# v2026-10-21-06 公开发布验证

- Release：https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-21-06
- 不可变tag源码提交：`31dd6d35a1137eb4ed0a334a35113e805d32d48f`。
- 官方Binary Release运行`39699316666`：原生macos-15 arm64、macos-15-intel amd64与唯一publisher全部成功。两架构完成Python工具测试、Go全测、vet、构建和程序version执行后发布。
- 公开latest稳定版读回为v2026-10-21-06，draft=false、prerelease=false；6附件完整：两个二进制归档、应用源码、两个独立对应源码归档、SHA256SUMS。
- 六附件实际下载，5归档逐项SHA256匹配。应用源码140文件逐字节匹配tag提交；两架构Mach-O CPU/filetype、BUILD-INFO平台和提交、CCS BUILD-IDENTITY及各37实际链接模块ZIP SHA均通过。公开main shell及两Python安装组件逐字节核对。
- 官方arm64程序SHA：`007f70c0e17d13106315a7385fa241859cf505b54b2f788ee0ac29fd03951599`。
- 官方amd64程序SHA：`468f1162e2a73bae5ec1b735aba16f6b93d72b3f972b03145cc01af5f3b1e13e`。

## 固定本版安装

在目标Mac本机终端运行，不加sudo：

```bash
curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/NiuStar/anytls-core/main/install-control-helper.sh | bash -s -- --version v2026-10-21-06
```

自动检测Intel／Apple Silicon，下载校验预编译包，不本机编译。完整保留源码／许可后安装受限助手；系统密码仅本机终端处理。保留配置、选择、密码，备份旧程序并安全切换WebUI，不自动启动或重载VPN。

打开http://127.0.0.1:18089，账户admin；应用专用密码可在本机运行`~/.anytls/anytls-macos password`查看。导入页先预览订阅、确认跳过清单，导出不应用；确认导入会保存并在VPN运行时尝试自动重连。

## 保留的失败与边界

首轮Intel CI因check-download契约测试失败保留，后继修复和独立复审通过；正式最终CI和发布run均成功。首次Mac读回CCS中途截断至12MiB，与API约96MiB长度不符，未记成功；当前主机重新实际下载六附件并校SHA成功。这不是网络速度或长下载已根治的声明。

尚未代用户执行本版完整系统授权安装→真实订阅→真实TUN使用；Intel原生runner测试不能替代用户机器的授权、路由、DNS、TCP/UDP生命周期验收。现有Mac正式WebUI仍是同版先前已验的本机构建，不能冒称与官方附件SHA相同；本次发版没有重装该Mac、更新root助手、导入配置或重启VPN。用户将自行验证安装到使用。没有Apple签名/公证；SHA256SUMS信任GitHub HTTPS，不是独立签名。
