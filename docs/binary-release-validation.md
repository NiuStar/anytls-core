# v2026-10-21-03 发布验证

## 来源和公开交付

- 标签解引用：`5627590e985fc1368fdbbc4d2d652f4c08b79446`。
- [正式 Release](https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-21-03)，已读回为 latest、非 draft、非 prerelease。
- [官方 Binary Release 成功](https://github.com/NiuStar/anytls-core/actions/runs/39609266453)。main CI、标签 CI 均成功；旧 Source Release 按条件跳过，不存在两个工作流覆盖 SHA256SUMS 的竞态。
- main 中 README、公开 shell 和两个可信 Python 安装器已经通过真实 raw URL 下载，逐字节核对提交。

## 已执行验证

- 本机 Python：原安装器24、二进制安装器29、打包工具6项测试通过；shell语法、git diff检查通过。UNIT-SIMULATED 安装测试不是真实特权安装。
- 用户 Mac 的干净独立 Git checkout：Go 1.26.8、darwin/arm64、CGO=0；211顶层／427子测试PASS、3SKIP、0FAIL，vet和认证wrapper build成功。
- 同一 checkout 实际打包通过：应用源码115个文件与commit逐一一致；37个实际链接模块的ZIP标准h1及.mod h1对go.sum核验；CCS含原始模块ZIP、必要元数据、应用源码与补丁／构建脚本、Go源码和成功wrapper身份回执；二进制包133个许可／通知成员。
- 官方发布后，全部四个附件真实下载，三归档对SHA256SUMS核验通过；应用源码115项与标签提交一致，CCS嵌套应用源码与源码附件一致，37模块和Go源码存在，binary manifest及实际程序摘要相符。
- 当前主机直接执行可信安装器 `--check-download --version v2026-10-21-03` 成功，`download_verified:true`、`executed:false`。
- Mac 从公开raw下载shell、再由shell下载可信Python和真实Release附件，隔离HOME执行相同检查成功（约16秒）；正式程序、config、selected、WebUI密码SHA不变。第一次检查220秒超时，无成功声明；之后只读确认无遗留校验进程，连接探针正常后另次执行成功，旧失败保留。
- Mac 另行真实下载官方二进制附件，验证归档和程序SHA后隔离执行 `version`：rc0，`v2026-10-21-03`。未执行VPN动作。

## 正式附件身份

| 附件 | SHA256 |
|---|---|
| `anytls-core-v2026-10-21-03-darwin-arm64.tar.gz` | `5687a994d8d4bc31a29d00642a14ec4935ccc9e7b49d8616c6bf19f383592237` |
| `anytls-core-v2026-10-21-03-source.tar.gz` | `eedd0b259d154704b05d1f6cea718ffe7f8a0c8d653fa9e5343e67f6ca79e846` |
| `anytls-core-v2026-10-21-03-corresponding-source.tar.gz` | `900717957f347309492188a7aa3c20595617a8f564f68387cf76f49464bf01dc` |
| `SHA256SUMS` | `fe2a7e414292197f2d0390745abb28805e619ed3bbdd2e0b92267d9a6144a3e4` |

官方程序SHA256：`9c6aeec07cd56af13124d1c2ea04ab619fb914147bfb9445eab592b3d1c86409`。
本机原生构建与CI二进制不同，未宣称逐字节可复现；二者各有成功构建身份，不互换摘要。

## 未执行和边界

- root helper 的首次真实系统授权安装、安装后真实start/stop/reload与自动应用，仍需用户在Mac本机执行并验收；发布不等于已安装到用户正式环境。
- 未停启既有VPN、未替换正式用户程序、未重启WebUI。运行中的旧WebUI须在安装后手动重启，已有VPN快照不随安装改变。
- `reload` 是受控重连，不是无缝热更新；长期网络稳定性和历史间歇DNS/TLS超时不由发布验收证明根治。
- 包含许可原文和来源明确的通知材料不构成无限范围法律审计；源头许可详见对应模块和Go源码。通知提取有启发式边界，不作普遍完整性保证。
- HTTPS及SHA提供本交付链的完整性，不是独立签名、Apple签名／公证，也不抵御发布权限或恶意同UID受控环境。
