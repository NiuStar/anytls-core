# v2026-10-22-06 公开核验与交付边界

发行提交：`42db62a9bc9b9ff95ef6a2b5a9f2c84884c846ca`。

发行地址：[v2026-10-22-06](https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-22-06)，Release ID `420822354`。父任务重新下载核对六个附件，SHA256SUMS 精确覆盖五个归档；186个源码文件逐字节匹配提交。双架构程序 Mach-O、BUILD-INFO 与对应源码 BUILD-IDENTITY 一致。SHA256SUMS 共用 GitHub HTTPS 信任，不是独立签名。

| 归档 | SHA256 |
|---|---|
| darwin-arm64.tar.gz | `79f9fbea2b4ddc1aad13fd747bdcc9d2e3a2c77e5038354da322468855900783` |
| darwin-amd64.tar.gz | `02854f85ca178751f8b2961568bc9be6147d2cfb6261d3f58a3addfbeec0325a` |
| source.tar.gz | `3b62ea1daadb111ba45df389e61b3bf8b2f7681649fa34b15127a51b377b1000` |
| corresponding-source.tar.gz（arm64） | `ffcef69902140daec66d7adebfdf406da1e5b940388e9caddc0756ad5b8944e9` |
| darwin-amd64-corresponding-source.tar.gz | `58bce48d1f287054fb2d70f0d09600ae06afb1795395a67137dd4ea07cfb27df` |

表内均为 `anytls-core-v2026-10-22-06-` 前缀的完整附件。公开包内 arm64程序 SHA：`942723809e3890be3aaca7c86e1339e966408eb548589535a22e49c3dcb870dd`；amd64：`8078dbd018abecf5d18e2290e46f3d5ec5e86d927f1a80633d9014601913995c`。

## 验证

- 双分支同提交三平台CI已独立确认全部成功：[main](https://github.com/NiuStar/anytls-core/actions/runs/39789943228)、[开发分支](https://github.com/NiuStar/anytls-core/actions/runs/39789945419)。
- Mac原生干净构建310顶层／591子测试通过、3项既有跳过，Python144项全部通过，vet/build/package通过；源码clean、精确VCSrevision。前一驱动错误地沿用Linux skip预期而中止，原失败保留，只读认证后接续未执行门，不重跑已成功测试。
- Mac公开入口仅下载检查成功，隔离运行官方程序 `version` 返回06；未借此执行系统授权或正式安装。
- 真实HTTP和Chromium实际点击更新已证明新实现无需Go可安装官方预编译包，程序／材料／备份摘要吻合，重复检查保留内存／磁盘版本区别。测试覆盖04→公开05，不冒称本发行06的构建身份。

## 标签状态冲突

标签 [CI](https://github.com/NiuStar/anytls-core/actions/runs/39795006569) 的三个必需测试作业已分别观察成功，但运行聚合仍显示进行中；[Binary Release](https://github.com/NiuStar/anytls-core/actions/runs/39795006575) 聚合及HTML显示成功，作业API却仍显示进行中。六个附件已实际公开且验真，但**不能从公开附件或聚合成功推定所有标签检查已终态成功**。Source Release 对该二进制标签按既有白名单跳过，不替代Binary Release。

正式用户程序切换使用已独立验收的本机 clean-native 产物，同一发行提交、clean VCS，SHA `212b8b529d46a170d6180257cbe2868fe6a110c19827e24f99b2b7048c84e335`；它与CI公开包内二进制是各自绑定构建环境的不同产物，不声称字节相同。已在用户明确授权后备份替换并重启WebUI，独立认证读回内存／磁盘06及预编译检查通过；VPN和root助手、配置、选择、密码、DNS／代理不变。此本机交付不豁免公开标签元数据冲突，后者继续保留待核对状态。

该版本不关闭此前用户反馈的DIRECT实际故障，不将更换用户程序视为root助手或VPN运行快照已更新。
