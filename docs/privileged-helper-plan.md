# 本机受限特权助手

用户选择一次系统授权安装、后续自动控制。此修订不保存macOS密码，不改sudoers，不让HTTP以root运行。

## 信任与部署边界

- root LaunchDaemon 单独固定label，与VPN label分开。root-owned `/Library/PrivilegedHelperTools/com.nousresearch.anytls-control/` 保存助手可执行文件及0600授权记录；来源为一次安装时用户明确授权的本工具，不执行请求给出的路径或shell。
- Unix socket 位于root-owned助手目录的`run/`子目录（0711），专用授权UID的socket0600与内核peer UID校验；无TCP监听。只接受固定 status/start/stop/reload 和布尔allow_insecure，无路径、shell、脚本、环境、更新代码请求。
- 授权记录固定一个普通用户UID及其实际安装配置路径。控制器使用root-owned固定自身程序，复用现有TUN lifecycle与原路由/DNS恢复检查；不将用户目录可变程序当root helper执行。
- 现有用户配置仍由该用户编辑，助手读取固定授权配置路径。这授权用户控制自己的VPN配置，不是抵御恶意同UID的完整沙箱；CA/规则读取沿现有范围，不扩成全系统写API。
- 所有变更动作互斥，HTTP或客户端断开不释放服务端动作所有权；请求不能排队很久后意外启动。返回明确错误阶段，不输出原始配置或密码。
- helper更新/卸载需新的系统授权，不接受普通IPC替换root可执行文件。普通anytls update只替换用户程序，不悄悄更新root helper；版本与源码pin分开显示，不把客户端升级当助手升级。

## 安装与兼容

- `anytls helper install` 在Mac终端发起一次sudo（原生输入，不收密码）；或用户本机运行生成的一键安装.command。验证用户/绝对路径/源码regular、检查目标祖先rootowner与不可写、备份已有helper，再原子发布并bootstrap。
- 初次安装不停止VPN。现有root service路径及label保留，助手可控制已运行旧VPN；安装成功须从普通用户读回socket peer认证的status及helperSHA。
- WebUI优先且仅走助手服务动作；未安装返回明确需要本机执行helper install，不再逐次AppleScript。不自动降级回无GUI授权。
- 保留CLI现有sudo路径作为回退；可在助手可用时复用，但非本修订必要条件。
- 不发布未经原生测试的root部署。开发隔离测试socket/错误/调用语义；Mac native tests/vet/build；独立审查绑定SHA。首次root安装留用户本机权限，SSH无sudo不索取密码。

## 验证

真实临时Unix socket覆盖合法UID/拒绝UID、无效动作/路径字段、busy、不因disconnect释放锁、权限与缺helper、状态响应/错误脱敏、安装目标/参数/回退，原生peer UID/原生plist lint。root LaunchDaemon与实际VPN自动应用未执行不得宣称完成。
