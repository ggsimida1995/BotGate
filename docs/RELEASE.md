# 发布与升级

Bot Gate 的发布包由 GitHub Actions 在推送 `v*` 标签时自动生成，包含：

- Linux 包包含 `bot-gate`、`frontend/dist` 和可复制修改的 `config.toml`；
- macOS `.dmg` 包含完整 `.app`，内含后端、前端资源和默认配置；
- Windows 安装程序包含后端、前端资源和默认配置；
- `LICENSE` 与 `README.md`。

## 发布

```bash
git tag v0.1.0
git push origin v0.1.0
```

工作流会生成 Linux x64 压缩包、macOS arm64 安装磁盘映像（`.dmg`）和 Windows x64 安装程序（`.exe`），并附加到 GitHub Release。
版本号来自仓库的 `backend/Cargo.toml`，例如 `Cargo.toml` 为 `0.2.8` 时使用 `v0.2.8`。

macOS 安装包内含完整的 `.app`，其中包含 Rust 后端、`frontend/dist` 和默认 `config.toml`。将应用拖到“应用程序”后即可启动。首次启动会把配置复制到 `~/Library/Application Support/BotGate/`，数据库和签名密钥也会写入该用户目录，不需要修改应用包权限。

Windows 安装程序会把后端、React 页面、默认配置和应用图标安装到当前用户的 Bot Gate 目录，并创建开始菜单快捷方式；安装完成后可直接启动程序。macOS 版以菜单栏应用运行，点击菜单栏图标可打开管理后台或退出 Bot Gate。

应用图标源文件位于 `packaging/assets/`：SVG 源稿、压缩 PNG、Windows `.ico` 和 macOS `.icns`。发布包不包含带水印的原始设计图。

## Windows 启动

直接运行安装程序即可。安装器会把后端、配置、前端资源和 `bot-gate.ico` 放入同一安装目录，并创建带图标的快捷方式。Windows 版本不会弹出控制台窗口，而是在系统托盘驻留；右键托盘图标会打开实际管理地址，默认是 `http://127.0.0.1:9090`，若端口被占用则自动使用空闲端口。配置错误等启动失败会弹出错误对话框。

首次运行会在包目录附近创建 `data/secret.key` 和 SQLite 数据库。升级时保留 `config.toml` 与 `data/`，只替换可执行文件和 `frontend/` 目录。

## 管理台检查更新

在 `backend/config.toml` 中配置：

```toml
[update]
enabled = true
release_url = "https://api.github.com/repos/<owner>/<repo>/releases/latest"
```

管理台的“检查更新”会读取 GitHub Release JSON，比较 `tag_name`。发现新版本后，点击“下载并立即更新”会下载当前平台安装包与对应 `.sha256` 文件；只有校验通过后才启动独立更新器。Windows 以静默安装器升级，macOS 用临时脚本替换 `.app`，Linux 解压并替换程序和前端资源；三者都会保留现有 `config.toml`、许可证和 `data/`，然后自动重启。更新地址及所有 Release 资产地址必须是 HTTPS。

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
