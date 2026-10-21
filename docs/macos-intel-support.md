# macOS Intel / Apple Silicon 二进制发布

`Binary Release` 保留 tag push (`v*`) 触发，不在本次修改中创建 tag 或发布 Release。双架构工作流需经真实 GitHub Actions 运行后才能称为 CI 验收通过。

## 原生构建矩阵

| 发布架构 | GitHub runner | 必须匹配的 `uname -m` | Go 目标 / CPU 基线 |
| --- | --- | --- | --- |
| Apple Silicon | `macos-15` | `arm64` | `darwin/arm64`, `GOARM64=v8.0` |
| Intel | `macos-15-intel` | `x86_64` | `darwin/amd64`, `GOAMD64=v1` |

两边均固定 Go **1.26.8**、`CGO_ENABLED=0`，显式设置 `GOARCH`，检查 `GOHOSTARCH`，不使用交叉编译或 Rosetta 冒充原生测试。每个 runner 先运行 `scripts` 下三个 Python `*_test.py` 套件，再运行相同 tags 的 Go test、vet、certified wrapper build，执行所得二进制核对版本，最后调用打包器 `--arch "$GOARCH"`。打包器须按各自真实链接模块捕获、验证对应源码及许可材料；不能借用另一架构的链接清单。

### Runner 与最低系统要求的官方依据

本次实现已通过官方页面正文核对以下标签，而不是依赖 `macos-latest` 的历史架构：

- [GitHub：Choosing the runner for a job](https://docs.github.com/en/actions/writing-workflows/choosing-where-your-workflow-runs/choosing-the-runner-for-a-job)：标准 runner 列表明确列出 Intel 的 `macos-15-intel`，以及 arm64 的 `macos-15`。
- 对应镜像说明：[macOS 15 Intel](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-Readme.md)、[macOS 15 arm64](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-arm64-Readme.md)。后续标签变更须再次核对官方列表；架构 guard 失败时停止，不能静默切换为交叉编译。
- [Go 官方 Minimum Requirements](https://go.dev/wiki/MinimumRequirements)：Go 1.25 / 1.26 要求 **macOS 12 Monterey 或更新版本**。
- [Go 1.26 Darwin release notes](https://go.dev/doc/go1.26#darwin)：Go 1.26 是最后支持 macOS 12 的版本，Go 1.27 将要求 macOS 13。

上述 macOS 12 是工具链最低系统要求，不代表本项目已经在 macOS 12 实测；工作流的原生测试环境是 macOS 15。`GOAMD64=v1` 限制 CPU 指令基线，不降低 Go 的最低 macOS 要求，也不等于所有历史 Intel Mac 均已验收。尚未声明旧系统、真实 TUN 或用户 Intel 机器实测通过。

## 发布附件与合并门

每个构建 job 仅具有 `contents: read`，上传独立 artifact：`binary-release-arm64` / `binary-release-amd64`。两边都包含自己的二进制包、对应源码包、相同 commit 的公共源码包及各自 `SHA256SUMS`。最终唯一的 `publish` job 依赖整个 build matrix 成功，独占 `contents: write`。

对 tag `TAG`，最终必须恰好包含以下五个归档和一份 `SHA256SUMS`：

1. `anytls-core-TAG-darwin-arm64.tar.gz`
2. `anytls-core-TAG-darwin-amd64.tar.gz`
3. `anytls-core-TAG-corresponding-source.tar.gz`（保留 arm64 历史名称）
4. `anytls-core-TAG-darwin-amd64-corresponding-source.tar.gz`
5. `anytls-core-TAG-source.tar.gz`（公共应用源码，仅保留一份）

发布前分别拒绝缺失、额外文件、目录、符号链接、非法/重复/遗漏的清单条目及摘要不符。公共源码须逐字节相同才去重；其他重名一律拒绝。只在所有检查通过后生成 `dist`，按文件名排序重算覆盖五个归档的唯一 `SHA256SUMS`。

发布 tag 必须符合稳定的 `vMAJOR.MINOR.PATCH` 或项目 `vYYYY-MM-DD-NN` 格式，并与 `VERSION` 及 checkout commit 一致；打包器另检查 tracked 源码 clean 和二进制 VCS 绑定。已有 Release 仅追加附件，不使用 `--clobber`；重跑遇到既有同名附件会失败，避免替换不可变产物。仅允许稳定 tag；新建稳定版仅由唯一 publish job 设置 latest，项目日期版不是 prerelease。发布后读回 tag 与附件名/大小。Release 本身可能由独立源码发布工作流先创建；本工作流保留这种情况的追加行为，不重写已有 Release 元数据。

## 验收边界

本地 YAML/嵌入 Python 检查和合并正负例只能证明工作流静态结构及合并逻辑，不等于 Actions runner 可调度、Go 原生 test/vet 成功、双架构许可包完整或 Release 已公开。`scripts/package-binary.py --arch` 及其架构专属名称必须与本工作流同批落地；在两边原生 CI 完成前，不创建发布 tag、不宣称 Intel 二进制已交付。
