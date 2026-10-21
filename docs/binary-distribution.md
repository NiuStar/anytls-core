# 预编译二进制分发包草案（尚未完成许可证验收）

本草案核对基线：`feat/privileged-control-helper`，commit
`856a4a970fbad54c2db863c7423195a35d4e22ff`。仅核对仓库中的 LICENSE、
THIRD_PARTY_NOTICES.md、licenses/sing-box-LICENSE、补丁说明、构建 wrapper 与
模块锁；未取得目标 Mac 二进制、实际链接模块 ZIP 或 Go 工具链许可证树。
**本文不是“全部许可证已完整”的结论，也不授权上传二进制。**

交付方向是 Release 提供现成的 darwin/arm64 二进制，由安装脚本下载；
普通用户安装不编译。以下源码包是发布者同时提供的对应源码，不是安装时编译要求。

## 1. 已确认与尚未确认

- 根 LICENSE 是 GPLv3 全文；仅凭该全文中的示例段落不能证明项目声明了
  “or later”，应保留并核对项目实际授权声明。与 sing-box 组合的覆盖作品应按
  适用 GPL 条款分发，不能把静态链接第三方误称为独立程序聚合。
- 仓库所附 sing-box LICENSE 明确为 **GPL-3.0-or-later，不是 BSD**，并附有
  禁止未经同意使用其名称或暗示关联的句子。保留原文、版权和独立项目说明，
  不自称官方或获背书；本文不对该额外句子的法律效力作扩张判断。
- 固定上游是 sing-box v1.14.3，commit
  `7054cac5124465ffdb145870d7c01885566711b1`；wrapper 对私有副本实施
  Box.Start cleanup-error 补丁，并通过临时 replacement 构建。
- go.mod 声明 `go 1.25.5`、`toolchain go1.26.8`；wrapper 要求精确 go1.26.8。
  这些是源码要求，不替代目标二进制实际 build info 和成功 END 回执。
- THIRD_PARTY_NOTICES.md 的其他依赖许可仅是摘要，不是逐模块许可认证；
  gVisor 的文件级例外、uTLS 的继承代码与 Go runtime/std 的通知尤其不能略过。

## 2. 建议的最小 Release 资产

同一 Release 同时提供下列资产；名字是模板，不代表文件已经生成：

```text
anytls-<version>-darwin-arm64.tar.gz
  bin/anytls
  LICENSE
  THIRD_PARTY_NOTICES.md              # 发布版须补充已核实的完整通知
  licenses/                          # 二进制分发所需版权/许可/NOTICE 原文
  SOURCE-LOCATION.txt                # 同 Release 对应源码资产的明确地址

anytls-<version>-corresponding-source.tar.gz
  app/                               # 与实际产物对应的完整自有源码快照
    go.mod, go.sum, scripts/, patches/, docs/, ...
  modules/                           # 精确版本原始 Go module ZIP + .mod
  toolchain/                         # Go 源码，或经论证的获取说明（见下）
  BUILD.md                           # 可执行的构建/安装说明与环境记录
  MODULES.json                       # 模块、归档、许可路径和完整性状态
  LICENSE-INDEX.md                    # 逐项版权/许可/NOTICE 的可定位来源
  BUILD-IDENTITY.json                 # binary/source/patch/toolchain 的对应关系

SHA256SUMS
```

可把 app/ 单独做成源码资产并由主源码包清单精确引用，但不要只给浮动 Git 分支链接。
完整自有源码包括实际使用的构建/安装脚本、生成器输入、资源和必要接口文件；
仅 `*.go` 或单一 patch 不够。排除真实凭据、私有配置、实验日志和缓存。
若实际构建树 dirty 或来自 shadow，Git commit 本身不足以代表对应源码，须保存
实际文件快照并比对全部构建输入。源码新添本文不意味着旧二进制由新 commit 构建。

采用 GPLv3 §6(d) 的网络分发路线：在二进制旁提供免费、等效访问的对应源码，
维护其可用性。无需强迫用户同时下载源码；不要把“提供网址”误写成 §6(b) 的
三年书面要约，也不要把只属于物理产品路线的条件套到普通网络 Release。

## 3. 模块集合与源码闭包

1. 以父任务取得的目标二进制 build info 建立实际模块集合，记录目标 OS/架构、
   CGO、tags、flags、工具链和每个 replacement。对所有发布的可执行文件分别做表。
2. 每个实际链接第三方模块提供精确版本完整 ZIP，而非仅 LICENSE 或二进制。
   sing-box 必须提供未修改上游 ZIP、补丁 JSON、identity.json、完整 wrapper
   与修改说明（包含相关修改日期）。明确如何由原始上游生成实际 patched box.go。
   临时 replacement 路径已删除不表示可省略源码，也不能把其无 sum 状态当原始身份。
3. build info 是闭包核对起点，不是完整 CCS 的自动证明。另核对生成/嵌入资源、
   本地替换模块、CGO 非 Go 代码和控制构建/安装的材料；缺任何必需材料即未闭合。
4. 不因 go.sum 有记录就捆绑全部历史/测试/其他平台模块 ZIP。反过来，不能因为
   模块未链接就排除生成源码所需工具或构建输入。为模块图加载所需但未链接的
   `.mod` 元数据可随包保存，不必因此下载这些模块的全部源码 ZIP。
5. 模块路径必须精确匹配，包括 `/v2` 等后缀和嵌套模块；父模块 ZIP 不保证含
   嵌套模块源码或其许可证。`golang.org/x/sys` 等需逐个实际 ZIP 检查，不以 Go
   总项目 LICENSE 或相邻版本推定许可文件存在。

## 4. 完整性与许可证是两套独立检查

每项至少记录 module/version、ZIP 路径/字节数/SHA-256、期望与实测 Go `h1`、
锁来源、`.mod` 的 SHA/h1、发现的版权/许可/NOTICE 路径和状态。

- ZIP SHA-256 只证明本次归档字节身份；同目录 `.ziphash` 与 ZIP 自洽不等于
  独立来源认证。必须把重新计算的模块内容 `h1` 对到可信基线 go.sum 中该精确版本
  的**非 `/go.mod`**记录；再单独验证 `.mod` 对应的 `/go.mod` h1。
- Go HashZip 是对排序的 ZIP 完整成员名和每项内容摘要计算 Hash1，并非压缩字节
  SHA。实现须对照精确工具链/x/mod 的算法；不能未经核对就排除显式目录项。
  当前 wrapper 的 stage_archive 排除目录项，不能把它泛化成全部依赖 ZIP 的认证器；
  对 ZIP 有无显式目录项应实测，若有则另按标准 HashZip 核验，不在本任务改 wrapper。
- 摘要匹配不证明许可完整、授权合法或源码确实生成目标产物；需分别保留状态。
- ZIP 中可以保留原始 source-level 许可与 NOTICE，而不改写 ZIP。但必须提供索引，
  说明解压后准确位置。对要求二进制文档携带的版权/免责文本、Apache NOTICE 等，
  还须将适用内容放进二进制包的 licenses/ 或第三方通知中；只藏在可选源码 ZIP
  不能自动满足所有二进制分发条件。
- 检查不应只匹配根 LICENSE：同时检查 COPYING、NOTICE、AUTHORS、版权头、
  第三方子目录以及文件级例外。文件名存在也不能当作兼容性已验证。
- 若任一实际分发第三方材料没有可确认的授权，标为 `UNRESOLVED`，必要时从其
  精确上游版本补取许可/通知并说明来源；不能用相近版本、仓库摘要或自造许可填补。
  **未解决前不上传包含它的二进制。**

## 5. Go 1.26.8 与系统库边界

GPLv3 §1 排除符合定义的 System Libraries，以及不属于作品、未修改使用的
通用工具；不意味着所有 `golang.org/x/*` 模块或静态链接 runtime/std 自动排除。
未修改的 Go 编译器通常可作为通用构建工具处理，但二进制包含的 Go runtime/std
仍需核对其版权、BSD 类条款及内含第三方通知。

稳妥且容易核查的方案是随源码包收录精确 Go 1.26.8 官方源码归档，保留其
LICENSE/PATENTS 与适用第三方许可/通知，并将所需二进制通知复制到 licenses/。
若决定不捆工具链源码，BUILD.md 至少记录实际 `go version`、官方获取入口
`https://go.dev/dl/`、精确版本源码地址候选
`https://go.dev/dl/go1.26.8.src.tar.gz`、官方校验信息来源及排除依据。
本次未联网，未验证该精确地址的可访问性或源码摘要；不能声称已提供了有效官方要约。
仅写版本或网址不能代替已确定属于 CCS 的材料，也不能代替 Go 二进制通知义务。
对确认为系统库的 macOS 组件记录排除理由，无需随包携带 Apple 系统源码；
若 CGO 状态未知，不先声称“无其他本地库”。

## 6. 上传前验收（当前均待父任务取得实物后裁定）

- 实际二进制 SHA 与成功 wrapper END、源码快照、补丁和 build info 精确绑定；
  不声称要求逐字节可复现，亦不以 build info 路径替代来源证据。
- 每个实际模块已覆盖，所有 ZIP 的 SHA 与可信 go.sum h1 分别核验；
  所有源码/构建输入缺口已关闭，必要 `.mod` 元数据齐全。
- 每项适用版权/许可/NOTICE 已阅读并定位，二进制文档携带义务已落实，
  第三方许可兼容性和项目授权声明无未解决项；适用交互界面法律通知另行核对。
- 使用普通解压工具验证归档可读，核对清单/摘要/成员并确认没有私密材料；
  至少检查文档配方确实可从包中找到全部必要输入，不把“归档成功”写成重建成功。
- 安装脚本下载预编译包并校验摘要，保留许可材料；发布说明在二进制旁明确链接
  对应源码。普通软件网络下载与随 User Product 转让的情形区分；若后者适用，
  另满足 GPLv3 §6 安装信息要求，不设置阻止合法修改版本的额外限制。
- 实际上传后读回 Release 资产、摘要及源码访问地址，才能报告“发布完成”。

本草案只给出工程交付门槛，不构成法律意见或已完成的全许可证审计。
