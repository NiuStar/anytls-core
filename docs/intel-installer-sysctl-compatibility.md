# Intel 安装器：缺失 ARM sysctl 键兼容修复

用户在公开 v2026-10-21-06 安装命令中，组件下载后得到 `cannot establish native macOS architecture`。失败位置在安装器硬件检测、发行附件下载和助手操作之前；不是已完成安装或VPN变化。

旧 `sysctl -in hw.optional.arm64` 会把不存在的键吞为rc0空输出。macOS Apple Silicon实测：虚构不存在键用-in得到0/空，用-n得到rc1及精确unknown oid。Apple官方Rosetta文档将proc_translated的ENOENT区别于其他失败；不能将permission失败默认Intel。未获取用户机器探测输出，因此仅确认代码缺陷和相同症状回归，不声称用户实机根因已独立认证。

修复为-n保留诊断；直接arm64进程或arm/translated成功值1选arm64；成功arm capability0沿既有Intel路径；ARM能力键明确不存在且翻译键为0或明确不存在时，追加成功x86_64能力1正控才选Intel。权限失败、错误键名、rc0空或畸形输出不默认Intel。检查下载仍无子进程，实际安装不接受架构强制覆盖。

验证：新增缺失键测试对旧安装器真实运行返回同款ValueError，修后全工具103测试PASS。Mac Python3.9三套工具回归通过，并用真实sysctl确认AppleSilicon优先arm；x86 process标签+真实ARMsysctl仅是识别路径探针，不是Rosetta执行或Intel实机安装。完整Intel安装流程为mocked process/transport UNIT，不能外推系统授权成功。

本修复只更新可信main下载安装器和测试，不重写v2026-10-21-06 tag、二进制或对应源码附件。核心未改，不重启生产VPN。发布状态待独立复审、主分支推送及公开入口字节读回另记。

官方依据：https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment
