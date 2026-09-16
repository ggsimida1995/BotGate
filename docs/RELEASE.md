# 发布与升级

Bot Gate 的发布包由 GitHub Actions 在推送 `v*` 标签时自动生成，包含：

- 对应平台的 `bot-gate` 可执行文件；
- `frontend/dist` 管理台和验证页静态资源；
- 可复制修改的 `config.toml`；
- `LICENSE` 与 `README.md`。

## 发布

```bash
git tag v0.1.0
git push origin v0.1.0
```

工作流会生成 Linux x64、macOS arm64、Windows x64 三个压缩包并附加到 GitHub Release。
版本号来自仓库的 `backend/Cargo.toml`，例如 `Cargo.toml` 为 `0.2.0` 时使用 `v0.2.0`。

## Windows 启动

解压后不要只复制 `bot-gate.exe`。保持下面的目录结构，并直接双击 `bot-gate.exe`：

```text
BotGate-<version>-windows-x64/
  bot-gate.exe
  config.toml
  frontend/dist/admin.html
  frontend/dist/challenge.html
```

程序会按可执行文件所在目录查找 `config.toml` 和 `frontend/dist`，因此不依赖当前命令行目录。Windows 版本不会弹出控制台窗口，而是在系统托盘驻留；右键托盘图标可以打开 `http://127.0.0.1:9090` 管理台或退出程序。配置错误、端口占用等启动失败会弹出错误对话框。

首次运行会在包目录附近创建 `data/secret.key` 和 SQLite 数据库。升级时保留 `config.toml` 与 `data/`，只替换可执行文件和 `frontend/` 目录。

## 管理台检查更新

在 `backend/config.toml` 中配置：

```toml
[update]
enabled = true
release_url = "https://api.github.com/repos/<owner>/<repo>/releases/latest"
```

管理台的“检查更新”会读取 GitHub Release JSON，比较 `tag_name`，发现新版本后打开 Release 下载页。当前设计不会自动覆盖正在运行的二进制，避免 Windows 文件占用、权限和回滚问题；下载新包后停止旧进程、替换目录，再启动即可。

发布包启动后默认只运行本机管理端口，网关反向代理由管理台手动启动。启用许可证时，网关启动接口会先验证本地许可证文件和签名有效期；许可证无效时只保留管理台，公网网关不会监听。

## 许可证

许可证采用 Ed25519 签名令牌，客户端只保存令牌并使用公钥验签。配置：

```toml
[license]
enabled = true
public_key = "<base64 Ed25519 public key>"
file = "data/license.key"
```

令牌格式为 `BG1.<base64url payload>.<base64url signature>`，payload 至少包含 `license_id`、`issued_at`、`expires_at`，且有效期不能超过 366 天。管理台调用 `POST /api/license/activate` 激活；私钥只应保留在签发端，绝不能放进发布包。启用许可证后，未激活或已过期的公网请求会在反向代理之前收到 `402`；管理台仍保持本机可访问，用于完成激活。
