# v2026-10-23-01：公开发行核验

## 不可变身份

- Release：[v2026-10-23-01](https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-23-01)，ID `421379154`，公开稳定版，非 draft／prerelease。
- 标签对象 `e6d9ef71efde0e0db603faa1d3d59e5861910aed`，发行 commit `6c30343d58175ef1cc570dd5c707bdc2d6d4c89e`。
- `latest` 已独立读回指向本版。后继文档提交不移动该标签或替换附件，文档 HEAD 的 CI 与发行提交分开记账。

## CI 与原生执行

下列运行的三个平台作业均已成功，父级独立读取实际 jobs，而非继承单一成功摘要：

- [候选分支 CI 39886368000](https://github.com/NiuStar/anytls-core/actions/runs/39886368000)：Linux、Apple Silicon、Intel。
- [main CI 39886790605](https://github.com/NiuStar/anytls-core/actions/runs/39886790605)：Linux、Apple Silicon、Intel。
- [标签 CI 39887282005](https://github.com/NiuStar/anytls-core/actions/runs/39887282005)：Linux、Apple Silicon、Intel。
- [双架构 Binary Release 39887281993](https://github.com/NiuStar/anytls-core/actions/runs/39887281993)：arm64 build、amd64 build、publish 全部成功。
- Source Release 被既有 whitelist 策略跳过，本标签由唯一 Binary Release 发布者管理附件；不把 SKIP 当作源码作业成功。

Mac arm64 干净 `.git` 候选：385 顶层／773 子测试通过，2 项既有跳过，显式 reference core／CLI parity 已运行；vet、trimpath build、打包通过。实际 Go 1.26.8、CGO=0、四 tags、精确发行 revision、`vcs.modified=false`。未变化的原生 Python 144 PASS 证据保留，未冒称在最终重建时重复运行。定向 race 与 Chromium 终态／分页／筛选结果绑定对应产品字节；浏览器 API 使用合成夹具，不替代真实助手／TUN。

旧候选 `79e2a00` 的 Linux CI 失败记录保留。两处本地复现的测试夹具缺陷（超限 Unix socket 未读尾部、umask 过滤权限负例）经独立审查及 Linux／Mac 双 umask 回归修正；旧线上日志不可读，因此旧 CI 的具体因果仍 UNKNOWN，新提交成功不倒改旧结果。

## 公开附件

API 已核对六件唯一 asset ID／name／size／digest。总校验文件含恰好五份归档：

| 附件 | 字节 | SHA256 |
| --- | ---: | --- |
| `anytls-core-v2026-10-23-01-source.tar.gz` | 480613 | `1498a85657f5931686dbd3ea425309bb537e675d56ddd73a24f71364784d1fb1` |
| `anytls-core-v2026-10-23-01-darwin-arm64.tar.gz` | 16564127 | `d84f0800017ab7f66e28b8f05d306179bcb3898b574aeaa439f8f78edca0a4a2` |
| `anytls-core-v2026-10-23-01-darwin-amd64.tar.gz` | 17489506 | `27808b069b3814d0c984aff8ec520ad91d92897120c3ed7ab03b6b8c17622a05` |
| `anytls-core-v2026-10-23-01-corresponding-source.tar.gz` | 97040176 | `5cc6456e20bda7dfb2c42dae5ccdedae038540f9dc68aca6160c8cb0d5ddf328` |
| `anytls-core-v2026-10-23-01-darwin-amd64-corresponding-source.tar.gz` | 97037724 | `b80008a702cb1ee469c56dbd9f67a8948c8612cd841244fb75df589643d4e795` |
| `SHA256SUMS` | 588 | `7cfeb44c36ddca9e4ad1c6e9c214d086d89ab90f0b7518991ddea42dee8526a5` |

六件附件已实际完整下载，父级重算全部长度／SHA，与 API digest 及五行 SHA256SUMS 精确集合交叉一致。源码归档 217 个文件逐项对精确标签核对 bytes／mode；两个官方包的 Mach-O／构建身份和程序 SHA 一致。专项审计对每架构实际 37 个模块 ZIP 重算标准 h1 与 go.mod h1，核对嵌套源码与公开 source 原字节、完整 Go 源材料、重建的许可／NOTICE；通过范围为非执行归档审计，不是法律或上游签名担保。首轮审计的工具断言失败与修正版结果均保留，没有重复下载或改动发行附件。SHA256SUMS 属于相同 GitHub HTTPS 信任下的完整性校验，不是独立签名、Apple 签名或公证。

## Mac 公开入口实测

公开 raw `main/get.sh` 与受版本控制字节相同，SHA256 `3a282868f35d48beca124249e1588eb50093ea9de4ed4c3ba41965542f9d15cc`。

在独立 HOME／TMPDIR、无 Go 的 PATH 下运行公开 `bash get.sh --check-download`，未指定版本：解析 latest 为本版、下载和校验 binary／source／CCS，退出 0，明确 `executed=false`。另行从校验过的公开 arm64 包提取官方程序，仅执行 `version`，退出 0 并输出 `v2026-10-23-01`；该单独步骤为 `executed=true`，不与下载检查混淆。官方 arm64 binary SHA256：`9b01954e73fff6ebe1eada7d0c63661b7f635fa82bc4d4e4d9afdcf5074d532b`，实际 revision 与发行提交一致，`vcs.modified=false`。

受检正式程序、配置／密码、WebUI／helper／VPN、DNS／proxy 前后不变。无安装、系统授权、helper 控制或 VPN 重连。root 私有 authority／助手动作计数不可读取的维度保留 UNAVAILABLE；上述不构成完整特权安装或 TUN 验收。

## 用户更新与剩余边界

在目标 Mac 本机终端运行，不额外加 sudo：

```bash
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash
```

保留配置和应用密码，系统授权只在本机 sudo 提示中输入。普通网页更新只更新用户程序，真实连接记录还需配套 root 助手及运行中的新版 VPN；安装不自动重连 VPN。`CLOSED` 只表示最后保存的停止记录状态，完整收尾未验证、连续性 UNKNOWN。ROUTED 不证明连接成功；DNS／REJECT／早期错误有覆盖缺口，历史为空不证明无流量。目标 `172.16.51.184` 尚未由本任务连接／安装／验收，DIRECT 慢的实际用户问题仍未定位。
