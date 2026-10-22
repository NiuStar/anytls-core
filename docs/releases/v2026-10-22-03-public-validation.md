# v2026-10-22-03 公开分发核验

- Release：https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-22-03
- Release ID：`420366844`；稳定版、非草稿，核验时为 latest。
- 不可变源码提交：`41959024f3bce2e652c8f9f8bbf4e37bb424c15f`。
- [Binary Release 39732298297](https://github.com/NiuStar/anytls-core/actions/runs/39732298297) 成功；Apple Silicon 与 Intel 原生作业均完成测试、vet、build、版本核验和实际打包，单一 publish 作业成功。

## 公开附件

六个附件全部实际下载；五份归档的集合、字节数和摘要与公开 SHA256SUMS 及 API 身份一致。

| 附件（统一前缀 `anytls-core-v2026-10-22-03-`） | SHA256 |
| --- | --- |
| `darwin-arm64.tar.gz` | `15173c07ea71ac028e2654585dd8c6f943e0e0043afeb7196d816cebb06e2611` |
| `darwin-amd64.tar.gz` | `81cbd2ff9f6fea4acc3b00b8f5408456c1b6b7531e7bcb32da5a35ee09f66021` |
| `source.tar.gz` | `9d70f4c54015ddd8b1585cafe1f1fde2e9f7975c789c261668e88f91d63c340d` |
| `corresponding-source.tar.gz` | `b3f73b05fd897a3f268f337de23b27d86547e7706bf23b7e8f44f02a5cb90d31` |
| `darwin-amd64-corresponding-source.tar.gz` | `3f62c94c25f9f2feca4730cec87529da1f238043fc7377cc1cff0446f7f6bbb2` |
| `SHA256SUMS`（不加前缀） | `86d0278b0b2679890bbe4b72ffc127b25082e5b17fbbcfc299d3f0cd7f13332b` |

源码归档精确匹配提交的全部 165 个受跟踪文件。两个二进制实际 buildinfo 均为 Go1.26.8、CGO=0、trimpath、精确提交和 vcs.modified=false；Mach-O 架构分别为 arm64／amd64，保留 gVisor、uTLS、embedded_core 与认证清理补丁。

每架构 CCS 对应 37 个实际链接模块；重新计算 ZIP SHA、标准 Go h1 与 go.mod h1，对照源码 go.sum。每架构 67 份依赖许可材料与二进制包字节一致，BUILD-IDENTITY／wrapper 输出摘要与对应程序一致。这是规定范围的材料核验，不是无限法律完整性担保。

## Mac 公开入口检查

在隔离目录实际下载公开 `get.sh` 执行 `--check-download` 成功；另下载公开 arm64 程序执行 `version` 返回 `v2026-10-22-03`。只读下载模式没有执行安装程序、系统授权或助手控制，未使用正式配置目录。

## CI 限制必须保留

同一源码提交的开发分支 CI `39732298072`、main CI `39732298729` 成功，二进制发布双架构作业成功。但标签 CI [39732298817](https://github.com/NiuStar/anytls-core/actions/runs/39732298817) 的 Intel 全套测试步骤退出 1，随后该轮 vet/build 跳过、arm64 取消。公开注释只有退出码，详细日志需要登录；具体失败测试与根因仍未知。不能据其他成功作业抹去该失败，也不宣称整体 CI 全绿。

发布及安装可用性与这项未定位 CI 失败分别报告。无 Apple 签名／公证；SHA 校验基于 GitHub HTTPS，不是独立真实性签名。未在本轮操作正式 VPN、特权 TUN 或验证用户机器安装后的持续稳定性。
