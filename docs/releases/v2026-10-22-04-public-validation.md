# v2026-10-22-04 公开发行核验

- Release：[v2026-10-22-04](https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-22-04)，ID `420437587`。
- 不可变应用源码提交：`7aae5721d9fdff7fdd7bf52cc404d9e2a61f0750`。
- 六个公开附件已实际下载，精确集合、大小、API digest 与 SHA256SUMS 一致；源码归档172项 tracked 文件逐项对比该提交原字节一致。
- 两架构 Mach-O、Go1.26.8、四项功能 tags、CGO=0、trimpath、精确 revision 与 `vcs.modified=false` 核验通过。每架构37个链接模块 ZIP 与 go.mod 标准 h1 对提交 go.sum 重算通过；对应源码 BUILD-IDENTITY、67份依赖许可、133个许可／通知成员与 SOURCE-NOTICES 字节一致。

## CI 与原生发行

| 工作流 | 运行 | 结果 |
| --- | --- | --- |
| main CI | [39741970611](https://github.com/NiuStar/anytls-core/actions/runs/39741970611) | Linux／macOS arm64／Intel 全部成功 |
| feat/surge-style-console CI | [39741970579](https://github.com/NiuStar/anytls-core/actions/runs/39741970579) | 三平台全部成功 |
| tag CI | [39742731222](https://github.com/NiuStar/anytls-core/actions/runs/39742731222) | 三平台全部成功 |
| Binary Release | [39742731091](https://github.com/NiuStar/anytls-core/actions/runs/39742731091) | arm64／Intel 原生构建及 publish 成功 |
| Source Release | [39742731019](https://github.com/NiuStar/anytls-core/actions/runs/39742731019) | 按仅允许三个旧标签的显式策略跳过；当前版本由 Binary Release 负责 |

上述为本次发行提交的结论，不倒改03历史标签的 Intel CI 失败。

## 公开附件 SHA256

统一文件名前缀为 `anytls-core-v2026-10-22-04`，SHA256SUMS 除外。

```text
b224cf03306bf274406578c90214459723d4d644c8e1113ca288cbd8e1736e78  anytls-core-v2026-10-22-04-corresponding-source.tar.gz
760ecda6d033de7b1bb14615b3bc844eb4d0889ea45a0d1fadfefe4b1d55c96c  anytls-core-v2026-10-22-04-darwin-amd64-corresponding-source.tar.gz
317f56373398911a96a68bcbf05d4c29e3bce127df78107e0bcd2fe312ad7fa3  anytls-core-v2026-10-22-04-darwin-amd64.tar.gz
51dd30e96bc388bbc7e3a03758ea0099c2534763109aa2f52346da9081fe2676  anytls-core-v2026-10-22-04-darwin-arm64.tar.gz
1760c6cd076620d39ef10b970aab08bc5e73224ef963d9485b7003c0ba511276  anytls-core-v2026-10-22-04-source.tar.gz
04d0dbe5a63d34ca22b5a97e10004decee5588a6708bd032b52dd7069e0acc72  SHA256SUMS
```

公开包内二进制：arm64 `2cd516d0925feda985fe05a1fa5ce7e6128579655689dd9aee8589e51de76572`；amd64 `db81551ecd3f45d0b5accbdcd901d61a33da5b7ccb73fdbc8f044c650636ad3a`。它们绑定各自 CI 构建，不要求与另一隔离构建逐字节一致。

## 安装入口实测与边界

Mac arm64 隔离 HOME 实际执行官方 `get.sh --check-download --version v2026-10-22-04`，rc=0、download_verified=true、executed=false；随后单独运行公开包内二进制 `version`，rc=0、输出该版本。未安装、未访问已安装助手 socket，未执行 sudo、launchctl 或正式 VPN 控制。Intel 原生执行证据来自上述 CI，不是本地 Mac 下载核验。

一键安装命令不变：

```bash
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash
```

详细诊断需程序与受限助手配套更新；助手更新仍需在用户本机完成既有系统授权。安装保留配置与应用密码，不启停或重载 VPN。本轮没有确定此前用户启动失败的实际根因，发布诊断改进不等于证明该故障已消失。

SHA 校验基于 GitHub HTTPS／API／发行清单信任，不是独立签名、Apple 签名或公证；许可材料核对不冒称无限范围法律审计。私有核验报告 SHA256：`f33986a8c3f6fd25533147a71f80ce184165fc17d90798f062ad02afed29aa6a`；原始错误与工具修正记录保留，不随公开产品源码分发。
