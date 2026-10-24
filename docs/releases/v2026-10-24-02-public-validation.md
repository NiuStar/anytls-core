# v2026-10-24-02 公开发行核验

## 已公开身份

- Release：<https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-24-02>；ID `422471597`，已读回为非 draft、非 prerelease 的 latest。
- 源码提交：`4d94ba7cc901aadae68fedc3fb39cb42517efd50`。
- 不可变 annotated tag：`38f232b5e637e4dc56efc5297f6beaa8c020a262`，解引用与上述提交一致。
- 分支 CI `40054089994`、main CI `40054458697`、标签 CI `40054710942`：Linux、Apple Silicon、Intel 三平台全部成功。
- Binary Release `40054710956`：arm64／amd64 原生测试、构建、打包与 publish 全部成功。Source Release `40054710925` 按显式 whitelist 跳过，不冒充成功。

## 六件公开附件

已真实下载并与公开 API 的 ID／长度／digest、SHA256SUMS 及安全归档成员交叉核对。总下载 226,833,395 字节。

| 附件 | 字节 | SHA256 |
|---|---:|---|
| SHA256SUMS | 588 | `b71a96d1fd52da6d8d262beb0cca74fcf22b67da6040c9de69de622dcda58a5c` |
| anytls-core-v2026-10-24-02-source.tar.gz | 499308 | `ff3ab28f919483c76d96724007cc05a78efdeaa20d8abce4d34edd924c4df76b` |
| anytls-core-v2026-10-24-02-darwin-arm64.tar.gz | 16021902 | `8359858ddc3e90d3f19ce1c614f7d74ebedf34ae207c04cab6fb6b465932350b` |
| anytls-core-v2026-10-24-02-darwin-amd64.tar.gz | 16910841 | `aa1b3420262f93f18f03a88ce6c6e5d9b4a0f48720aac94ca04dd0d78695977a` |
| anytls-core-v2026-10-24-02-corresponding-source.tar.gz | 96703274 | `d7e479a04ea6b6db1c50f55862e8085294ad412676453ae878e9981ac70062fd` |
| anytls-core-v2026-10-24-02-darwin-amd64-corresponding-source.tar.gz | 96697482 | `ebf79d5b09ed813b136d5aef03ffae71de5e50242805ed2092b2eb52c6d3f56f` |

源码包 228 文件、16 目录，完整字节和 modes 与精确提交的 `git archive` 相符。两架构程序均为目标 Mach-O，可读构建信息为 Go 1.26.8、CGO=0、四个既有 tags、trimpath、精确 VCS commit 和 modified=false；保留符号／DWARF，非符号剥离瘦身。

对应源码各包含实际链接的 35 模块，逐 ZIP 标准 Go h1／go.mod 对可信锁认证；没有 bbolt／chi，gVisor fork 与 uTLS 保留。两架构各 130 个许可／notice 文件从真实来源重建核对。Go 工具链源文件分别为 15,021／15,022，与同架构历史认证材料全量字节／mode 一致；Intel 额外 setup.sh 保留实际身份，不强制不同架构文件数相同。

从归档原 SDK 和两层补丁独立重建最终文件：

- box.go：`00f3a0ae747cafea89123aac2f4aff2bc5a04046225a5252d5fc4a3b54c99da0`
- debug_http.go：`13832fb094c2bbab38704b0b97781075fbe5eb70e5845d734f600acf91582a9f`

Mac Studio 独立下载同一公开 arm64 包和校验和，私有暂存程序实际执行 `version` 返回 `v2026-10-24-02`、rc=0；包内程序 SHA256 为 `ff053629103ebeae9d0f2499bad928ad549c41cdfd08a2bc33cab82a05a3150a`，29,955,954 字节。

## 原失败与边界

- v2026-10-24-01 标签 CI 成功，但双架构发布在 pre-Go Python 阶段失败，没有公开 Release；原标签／失败保留。02 仅修复干净源码夹具和版本材料，SDK／运行逻辑不变。
- 发布监督脚本在成功发布后拒绝 GitHub 的同仓库数字 ID 分页 URL，原 FAIL 保留。父级核对仓库 `1425804352` 和固定 Release ID 后，独立读回 3 页共 6 个唯一附件，完成只读补证，未重推标签或重构建。
- Mac Studio 已有同最终 SDK 的候选真实 TUN、HTTPS、旁路／DNS 观察及旧版恢复实测；其旧 argv 不覆盖新版助手／record-service 控制链。程序／WebUI 替换、root 助手更新和运行中 VPN 切换分别核验，不能互相替代。
- 用户 Intel 目标机的真实 TUN 体验仍由用户测试，不能从原生 Intel CI 推断其 START_FAILED 已修复。
- SHA256SUMS 不提供独立签名、Apple 签名或公证。原始配置、密钥、密码及实验日志不在公开源码中。
