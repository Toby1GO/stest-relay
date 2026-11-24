发布者在仓库外安全保存一把专用 RSA 签名私钥，跨版本使用同一把密钥；
首次可在受控发布环境使用 `openssl genrsa -aes256 -out /secure/stest-signing.pem 3072` 创建，
并离线备份。私钥和口令不进入源码、Release、中心或节点。

更新 `install/VERSION` 和中心首次安装脚本中的 release 标签，然后运行
`python install/build_center.py --signing-key /secure/stest-signing.pem`。
构建器将公钥写入更新工具，为节点生成签名清单后再编译中心。中心包和节点包的清单分别签名。
将 `dist/bundled` 中本次生成的两种中心程序、两个 kit、`stest`、`manifest.json`、
`manifest.sig` 和 `SHA256SUMS` 一起上传到同版本 GitHub 正式 Release，再设为 latest。
请勿将临时测试密钥用于发布。旧客户端不信任其他签名密钥。
