# v2026-10-24-03 / anytls-go v0.0.28 公开核验

## 不可变身份

| 项目 | 版本 | 源码提交 | Release ID |
|---|---|---|---|
| anytls-core | [v2026-10-24-03](https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-24-03) | `d77d3666966088a77adf2a045173e45263d49a85` | `422573453` |
| anytls-go | [v0.0.28](https://github.com/NiuStar/anytls-go/releases/tag/v0.0.28) | `2baedc2b92cfc992692fd3049a0613dabe6f25d1` | `422571661` |

双方 main、标签、最新稳定 Release 及完整附件集合已真实读回；不是只凭工作流退出码宣告公开。后续文档提交不会重写上述发行提交或标签。

## 必需 CI

父任务另经目标 Mac 的无代理公开 HTTPS API 读取实际 job 终态与矩阵：

- core 分支 `40071481772`、main `40071836554`、标签 CI `40072102565`：各 Linux、Mac arm64、Mac Intel 三项成功。
- core Binary Release `40072102522`：双架构构建、打包与 publish 三项成功。Source Release `40072102691` 按既有白名单策略跳过，不替代 Binary Release。
- server 分支 `40071713155`、main `40071936988`：各 Linux、Mac 两项成功。
- server Release `40072075064`：测试、16 个程序归档构建、smoke 与公开发布成功。

## 实际下载及材料验真

### core

六件附件实下载合计 **226,947,515 字节**。五条归档校验和逐一与实际文件及 Release API digest 一致。

| 附件 | 字节 | SHA-256 |
|---|---:|---|
| SHA256SUMS | 588 | `82666c8aa9205b1a682f1ddbf781737dee35f4b0047c506fe2fabdb3880fa1d3` |
| arm64 程序包 | 16043815 | `42cd99707b916793f40e7eb37c12405b74d2898ce0d3888f3c66d74d7eaaf8dd` |
| amd64 程序包 | 16939558 | `eae2d30201b0d1216107d67b3e720213ddb1272029241bf8f99824724e361a0f` |
| 应用源码 | 518026 | `a4942f4733f29c06267001914b82f1df61cfaeaaea64666a454f7e9eb2df41ae` |
| arm64 对应源码 | 96723396 | `545d835ba0ad5bc28ab538437820b53d18c0e005b93ba84e5034c263eb669b2e` |
| amd64 对应源码 | 96722132 | `4cacb2c015da2dcda3298d1a0b05504b4a557fd95f33017d9033de696d68849d` |

应用源码 236 个常规文件、16 个目录与精确提交的 `git archive` 字节及模式相符。两个架构分别核验 35 个链接模块、模块 ZIP h1、认证 SDK 补丁重建、工具链源码和公共构建元数据。工具链常规文件按架构分别为 15,021 / 15,022；每架构程序包包含 130 个许可文件。非链接缓存元数据只作为对应架构库存比较，不升级为所有内容均独立上游认证。

公开 arm64 程序 SHA-256：`1e43cabcbe99dc39a61ba78a297393086cfddd282920a64dce218de0ca803b01`。Intel 程序 SHA-256：`c9700579e93c3a72b687727c826a12bad16ebb8ece1c1de689787a306f3ccdc6`。

### server

21 个附件实下载合计 **70,242,240 字节**；16 个归档、4 个脚本和 checksums.txt。20 条校验和全部匹配，归档单个可执行文件路径、类型和 ELF/Mach-O/PE 架构、嵌入版本与提交均核验。新版服务端安装脚本与发行提交精确相同；其他三个管理脚本沿用既有 v0.0.23 材料，不宣称已改写。父任务另核对全部 21 个 API digest 与实际字节。

## 真实执行

- Mac 原生第二版候选：core 401 主项、776 子项 PASS，3 SKIP；server 232 主项、7 子项 PASS，无失败；双方 vet/build、Python 及 wrapper 回归通过。
- 最终 core 干净 Git 提交另跑全套、vet/build，`vcs.revision` 精确、`vcs.modified=false`、version03。
- 两边**公开下载的正式程序**在 Mac 上实跑 std／Chrome uTLS 各正常、错误 SPKI、错误密码六例，全部通过；正例目标完整回显 114 字节，四个负例均目标零连接、零载荷。测试进程已 wait，所有端口回收。
- 真实服务端 HTTPS payload 经客户端生产 pinned fetch（明确公网 IP→回环测试 dial seam）获取，再经真实认证 preview/commit 保存节点通过；侧文件存在性与字节不变。
- 公开 Linux 程序实际运行 config edit、subscription、config run、check-active；自签证书 pin 在发送 token 前校验，固定节点内容、DER/SPKI 区分、HEAD／错误令牌／方法／查询拒绝、0600 私有配置与无密码令牌 argv 均核验，退出0并回收端口。
- 最终桌面 1440 与手机 390 的真实 Chromium＋认证后端添加／重复 no-op 通过，零 JS 错误、无横向溢出；仅 URL 获取输入做本地 YAML 适配，不能称浏览器已走公网 pinned TLS。selected/subscription 存在性、SHA、长度、模式不变，测试控制端禁用服务操作。
- Mac 默认公开 `get.sh --check-download` 实际选择03：`download_verified=true, executed=false`，只获取校验和与 arm64 程序包，没有请求源码包；已核公开脚本逐字节一致，前后生产进程、配置、密码、DNS/proxy 无变化。

## 保留失败与边界

早期格式预检、工具链目录移除、驱动环境类型和 Git 标签 SSH 指纹错误均保留原始失败；修正后的成功回执单独存在，不倒改旧记录，不重复部署。安装器特殊密码 Shell 执行和端口非规范化问题则有真实业务 RED→GREEN 和最终独立复审。

本次完成源码与正式发行，不代表在用户公网服务器安装、systemd 重启或云防火墙验收，也没有更新生产助手或重连现有 VPN。Intel CI 原生成功与用户 Intel 机器实际体验不同，后者仍由用户测试。固定证书／公钥是 pin-only 身份认证，不是公共 CA＋域名验证；完整订阅链接必须私密可信交付。

详细使用：[公网 IP 私有订阅](../public-ip-private-subscription.md)。原始本地审计位于 `artifacts/anytls-go-integration/`（不随源码公开），包含候选 pins、独立审查、各次失败、公开下载及父级独立读回。
