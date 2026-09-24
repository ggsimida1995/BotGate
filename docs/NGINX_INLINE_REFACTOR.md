# Bot Gate Nginx 内联防护重构计划

## 问题与目标

现有“前置代理站点”模式只是在 Bot Gate 内保存 `Host -> upstream`。如果公网 80/443 仍由 Nginx/Caddy 直接处理，流量不会进入 Bot Gate，站点配置不会产生防护效果。

目标是新增 **Nginx 内联模式**：Nginx 保持原有静态文件、PHP、反向代理和 WebSocket 配置；Bot Gate 只在请求进入原站前给出“放行 / 验证 / 拦截”决策。添加、暂停、删除站点由 App 自动更新 Nginx 受控 include 并执行 `nginx -t` 与平滑重载，不再要求用户为每个站点手动改端口或源站路径。

## 约束

- 保留现有 `proxy` 模式，供 Docker、开发环境或独立网关部署使用。
- 新的 `nginx` 模式不需要 `target`，因为原始 Nginx vhost 继续服务业务。
- Nginx 仅通过回环地址访问 Bot Gate；Bot Gate 只信任来自回环地址的内联防护请求。
- 所有 Nginx 文件变更先备份；`nginx -t` 失败时恢复原文件，不执行 reload。

## 分阶段实施

### Phase 1 — 站点模型与持久化（本次）

- 为站点增加 `mode = proxy | nginx`。
- SQLite 迁移保留旧站点为 `proxy`，`nginx` 站点允许没有 upstream。
- 管理端显示实际模式和接管状态，避免把“配置已保存”误称为“已接管”。

### Phase 2 — Nginx 内联协议（本次）

- 增加 `/_bot_gate/check` 内部决策端点：仅返回 Nginx `auth_request` 需要的 2xx/401/403。
- 增加稳定的 `/_bot_gate/...` 验证路径，使 Nginx 能把验证页、验证提交和静态资源定向到 Bot Gate。
- 让内联模式在验证通过后由 Nginx 继续处理原请求，不再通过 Bot Gate 反代原站。

### Phase 3 — 自动 Nginx 适配（本次）

- 新增 `[nginx]` 配置：Nginx 可执行文件、可选的主配置文件、可选 vhost 目录和受控 include 目录。
- 不把 ServBay、宝塔或其他面板路径写进发布包：`binary = "nginx"` 会检查 PATH、常见安装目录以及 Windows 正在运行的 `nginx.exe`，`config_file = ""` 使用 Nginx 默认配置，`vhost_dir = ""` 时通过 `nginx -T` 发现实际加载的配置文件。
- 保存/启用 Nginx 模式站点时，按 `server_name` 找到对应 vhost，写入带 Bot Gate 标记的 include。
- 生成站点专属 include；校验并平滑重载；失败自动还原。
- 暂停/删除 Nginx 模式站点时自动移除 include 并校验、重载。

### Phase 4 — 管理台与验证（本次）

- 管理台可选择“独立前置代理”或“Nginx 内联防护”；后者不显示源站地址。
- 通过单元测试覆盖模式校验、SQLite 迁移、Nginx snippet 和 vhost 标记插入/移除。
- 通过 `cargo test`、`cargo check`、前端构建验证；在具备 Nginx 的环境中再做真实 vhost 写入与 reload 回归。

## 非目标

- 本次不实现 Nginx C 动态模块，也不改动宝塔系统防火墙。
- Caddy/ServBay 动态适配独立于本次 Nginx 重构，后续按相同“控制器 + 适配器”模型实现。

## 实施记录（2026-09-22）

已完成 Phase 1–4 的代码实现：`mode` 数据迁移、Nginx `auth_request` 桥接、验证页面稳定 `/_bot_gate/` 路径、受控 include 的插入/移除与 `nginx -t`/reload 回滚、管理台模式选择。

已完成自动验证：28 个 Rust 测试、前端生产构建、Nginx 配置路径发现测试，以及本机使用 `nginx -T` 的回环管理接口回归。真实 Nginx `-t`/平滑重载仍需在目标环境以一个测试域名完成最终验收；应用不会假设目标环境使用 ServBay 或宝塔。
