# v2026-10-22-05 公开发行核验

- Release：[v2026-10-22-05](https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-22-05)，ID `420546256`，公开稳定版。
- 不可变应用源码提交：`c389fc33c555b740f81c1338986dac62f4f64663`。
- 六个公开附件已实际下载，大小、API digest 与 SHA256SUMS 精确匹配；五份归档集合完整。应用源码180个受跟踪文件的字节和归档权限匹配该提交。
- 两架构 Mach-O、Go1.26.8、四项功能 tags、CGO=0、trimpath、精确 revision 与 `vcs.modified=false` 核验通过。各37个实际链接模块的 ZIP h1 和 go.mod h1 匹配提交 go.sum；对应源码 BUILD-IDENTITY、补丁及 replacement、每包133个许可／NOTICE文件逐项核验通过。

## 功能与执行证据

- 最多8路并发，结果逐项更新；延迟四舍五入为整数，按同一显示值分色：小于200ms绿色、200–499ms琥珀色、500ms及以上红色。失败不显示假0；取消／未测与探测中状态另行标识。
- 全体取消、配置／会话变化及取消后立即重开均隔离旧结果；后端只在配置捕获和结果发布阶段持短读锁，写操作仍排他。
- Mac arm64 干净提交：Python125项通过；Go305项顶层、552项子测试通过，3项既有跳过；vet、build、package成功。参考核心对照5子例通过。
- 真实HTTP→TCP同步收尾5轮×8请求：40/40成功、0次彼此争锁busy；入口并发8/8；取消、写锁竞争及ETag回归通过。定向CGO=1 race在此前同字节产品候选上通过，不把它记为本次CGO=0完整套件的race结果。
- Chromium桌面／手机的并发、逐结果更新、整数阈值及computed颜色、取消和迟到隔离复审通过；不等同Safari或像素美学验收。

## CI 与原生发行

| 工作流 | 运行 | 结果 |
| --- | --- | --- |
| main CI | [39755878210](https://github.com/NiuStar/anytls-core/actions/runs/39755878210) | Linux／macOS arm64／Intel 全部成功 |
| feat/surge-style-console CI | [39755878345](https://github.com/NiuStar/anytls-core/actions/runs/39755878345) | 三平台全部成功 |
| tag CI | [39757448100](https://github.com/NiuStar/anytls-core/actions/runs/39757448100) | 三平台全部成功 |
| Binary Release | [39757448135](https://github.com/NiuStar/anytls-core/actions/runs/39757448135) | arm64／Intel 原生构建及publish成功 |
| Source Release | [39757448049](https://github.com/NiuStar/anytls-core/actions/runs/39757448049) | 按既定旧标签白名单跳过；本版由Binary Release发布 |

结论仅绑定本次发行提交，不覆盖历史失败记录。

## 公开附件 SHA256

```text
388bd41a37e6914d469fd1ef2a3a9bba9ddbc53403999e048e6878ff6772b310  anytls-core-v2026-10-22-05-corresponding-source.tar.gz
660cd04d9ac635850e82a1de116ecf9a9e56a4e3d1cbaf67d052ac2bc5e8fd53  anytls-core-v2026-10-22-05-darwin-amd64-corresponding-source.tar.gz
894685886090b284a2d1d035e51bc76c4160909a81276a935773762948b94b56  anytls-core-v2026-10-22-05-darwin-amd64.tar.gz
e56448bbdf8e38bb69f3c654f2220d71cead8aff2dc9c8f5b320f6ed04b13fca  anytls-core-v2026-10-22-05-darwin-arm64.tar.gz
205a7f7828e387a1817a60fc35dc53531b0b43a5e8424670a893d9294917cdee  anytls-core-v2026-10-22-05-source.tar.gz
5d238e0dff21f52f35670dbd150b19babf9a5844f56a8cc5ee3db3bbd7e5fad3  SHA256SUMS
```

包内二进制SHA256：arm64 `60d1d6fe46201d63c776eeda4e83624a6b9019e3ddc930a27360f594613c93ab`；amd64 `226a180133417c215bd2c7cef7e4e26c693212b18dc900403cfe2ada5b1b3b80`。各自绑定CI构建，不要求与另一隔离构建的二进制摘要相同。

## 安装入口实测与未关闭问题

Mac arm64隔离HOME实际执行官方 `get.sh --check-download --version v2026-10-22-05`，rc=0、download_verified=true、executed=false；随后单独下载、核验并运行官方arm64程序 `version`，rc=0、输出该版本。父任务独立重算六附件、180源码文件及权限、双架构二进制摘要，并SSH读回Mac检查结果与程序摘要。本轮未安装，未访问已安装helper socket，未执行sudo、launchctl或正式VPN控制。Intel原生执行证据来自CI。

```bash
curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash
```

安装保留配置与应用密码，备份旧程序；系统授权仍在用户本机完成，不自动停止／重载VPN。

**DIRECT实际故障仍未定位。** 真实配置编译器→mixed/SOCKS合成业务的9个路由子例通过，不证明用户当前机器／配置／正式TUN正确；本版没有修改路由、DNS、TLS或网络栈策略。仍需具体应直连域名／IP及故障机器信息，不索要密码或完整订阅地址。测速受真实网络超时及同步清理影响，不承诺所有慢节点秒完。

SHA基于GitHub HTTPS／API／发行清单信任，不是独立签名、Apple签名或公证；许可材料核对不是无限范围法律审计。私有公开验收报告SHA256：`fbaab5191d6b8cf67b83e6f96224502a9068e05f1f03a396f882f834c3375df5`。原始工具错误及修正记录保留，不随公开产品源码分发。
