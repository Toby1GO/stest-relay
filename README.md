# STest Relay

一个中心面板（C）管理多对入口 client（A）和出口 server（B），支持 TCP、SOCKS5 UDP、规则热更新与按端口计量。

### 1. 安装中心面板

准备一台全新的 Linux amd64 / arm64 服务器，使用 systemd，并安装 bash、curl、OpenSSL 1.1.1+、Python 3 和 sha256sum。在 **C 的 root 终端**执行：

```bash
curl -fsSL https://raw.githubusercontent.com/Toby1GO/stest-relay/v1.2.0/install/center.sh | bash
```

脚本打印 HTTPS 地址和证书指纹。若自动识别的出口 IP 不是面板入口，安装时将末尾改为 `bash -s -- 你的公网IPv4`。使用自签证书时，首次访问请核对终端中的指纹。

新安装默认 **账号 admin，密码 admin**。首次设置前，安全组仅允许管理员 IP 访问管理端口。登录后必须同时更换账号和密码（至少 12 个字符），再用新凭据登录一次才能进入控制台。旧版升级保留原面板密码作为首次迁移凭据。

### 2. 安装一对节点

在面板点击 **安装一对节点**，填写 A、B 的标识和公网 IPv4。先在 **B 的 root 终端**运行 server 命令；成功后，再在 **A 的 root 终端**运行 client 命令。

v1.2.0 中心直接通过 HTTPS 提供脚本、节点程序和 SHA-256 校验清单。节点安装时只需能访问中心，无需访问 GitHub。关闭弹窗、复制丢失或命令过期后，进入 **全部节点 → 对应节点 → 安装**，即可签发有效期两小时的新命令。只有该节点之前的安装命令失效，不影响已上线的另一端。已安装节点和手动接入节点不提供首次安装命令。

若中心机器也无法访问 GitHub，可用另一台机器从 [v1.2.0 Release](https://github.com/Toby1GO/stest-relay/releases/tag/v1.2.0) 下载与中心架构匹配的 `stest-center-kit-amd64.tar.gz` 或 `stest-center-kit-arm64.tar.gz`，传到中心并解压。在解压目录以 root 运行 `STEST_PACKAGE_DIR="$PWD" bash ./center.sh 你的公网IPv4`。两种中心包都能安装任一架构的节点。

### 3. 开放端口并验证

| 方向 | 允许的流量 |
|---|---|
| 管理员、A、B → C | TCP 8443 |
| A → B | TCP 8001 |
| 客户端 → A | 规则的 TCP 入口；使用 SOCKS5 UDP 时还需 UDP 20000–20127（默认范围） |
| B → 目标 | TCP 目标端口；使用 UDP 时还需节点协商的 UDP 中继端口 |

如需显示中心探测延迟，允许 C 访问 A 的入口及 B 的 8001。在 **全部节点** 确认 A、B 在线，进入 **转发规则** 选择 A、添加并发布映射，再用客户端连接 A 的 IP 和入口端口。

服务名：C 为 `stest-center`，A 为 `stest-agent`，B 为 `stest-exit`。遇到启动问题可执行 `journalctl -u 服务名 -n 40 --no-pager`。安装脚本面向新服务器，不覆盖现有部署。

基于 [j-jiang/socks5](https://gitee.com/j-jiang/socks5) 的 Go 移植，见 [LICENSE](LICENSE)。
