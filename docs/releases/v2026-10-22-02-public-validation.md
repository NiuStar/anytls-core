# v2026-10-22-02 公开发布验证

- 发布源码：`47b85b1535224ea459da50119c4a21b5cdfb08ed`。
- [双架构原生发布工作流](https://github.com/NiuStar/anytls-core/actions/runs/39719103992)：arm64／amd64 原生测试、vet、构建、对应源码打包及单一发布者全部 success。
- [公开 Release](https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-22-02) 为稳定版，latest API 返回同版本。
- 六个公开附件完整下载，五个归档逐一匹配 SHA256SUMS。两种二进制 manifest 的提交、架构和程序 SHA256 均匹配；公开 arm64 程序实际执行 version 返回 `v2026-10-22-02`。
- 公开应用源码全部149个普通文件逐字节匹配精确提交；两架构 CCS 内 application-source 同样逐字节匹配。原有依赖／许可收集逻辑不变；这不是无限法律完整性声明。

## 程序摘要

| 架构 | 程序 SHA256 |
|---|---|
| darwin-arm64 | `d017acd7ed3dc6abf44acad57bd22d3989d3697cfb175b4d59a4ad1c762830ed` |
| darwin-amd64 | `9a9e1672b3a35b973aa833fed577fa3b4d8f782a08eb7c6563795a228fb8ea58` |

## 交付边界

配置上限32 MiB；真实私有订阅认证预览及导出已在同逻辑Mac候选通过，输出4,459,074字节、18个可用AnyTLS节点，未提交导入且配置不变。用户Intel机器的新版完整安装、导入和TUN联网留本机验收。没有为本次发布修改用户配置、密码、已运行VPN或正式WebUI。旧v06及失败的01标签不移动，未以旧附件冒充新构建。校验和依赖GitHub HTTPS，不是独立签名；无Apple签名／公证。
