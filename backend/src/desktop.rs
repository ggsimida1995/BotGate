use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use eframe::egui;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::tray::{TrayCommand, TrayHandle};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Sites,
    Requests,
    Interceptions,
}

pub(crate) fn run(
    admin_url: String,
    tray: Option<TrayHandle>,
    tray_events: UnboundedReceiver<TrayCommand>,
    tray_enabled: bool,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut tray = tray;
    #[cfg(target_os = "macos")]
    if let Some(handle) = tray.as_mut() {
        handle.display();
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("无法创建桌面管理客户端")?;
    #[cfg(not(target_os = "macos"))]
    let tray = tray;
    let app = DesktopApp::new(admin_url, client, tray, tray_events, tray_enabled);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(egui::vec2(1280.0, 800.0))
            .with_min_inner_size(egui::vec2(960.0, 620.0))
            .with_title("网站卫士"),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "网站卫士",
        options,
        Box::new(move |_context| Ok(Box::new(app))),
    )
    .map_err(|error| anyhow::anyhow!("桌面管理窗口启动失败: {error}"))
}

struct DesktopApp {
    admin_url: String,
    client: Client,
    tray: Option<TrayHandle>,
    tray_events: UnboundedReceiver<TrayCommand>,
    tray_enabled: bool,
    page: Page,
    dashboard: Value,
    system: Value,
    sites: Vec<Value>,
    logs: Vec<Value>,
    log_total: u64,
    nginx: Value,
    nginx_path: String,
    nginx_binary: String,
    new_host: String,
    new_target: String,
    update_message: String,
    error: String,
    last_refresh: Instant,
    refreshing: bool,
}

impl DesktopApp {
    fn new(
        admin_url: String,
        client: Client,
        tray: Option<TrayHandle>,
        tray_events: UnboundedReceiver<TrayCommand>,
        tray_enabled: bool,
    ) -> Self {
        let mut app = Self {
            admin_url,
            client,
            tray,
            tray_events,
            tray_enabled,
            page: Page::Overview,
            dashboard: Value::Null,
            system: Value::Null,
            sites: Vec::new(),
            logs: Vec::new(),
            log_total: 0,
            nginx: Value::Null,
            nginx_path: String::new(),
            nginx_binary: String::new(),
            new_host: String::new(),
            new_target: String::new(),
            update_message: String::new(),
            error: String::new(),
            last_refresh: Instant::now() - Duration::from_secs(10),
            refreshing: false,
        };
        app.refresh();
        app
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.admin_url, path)
    }

    fn get(&self, path: &str) -> Result<Value> {
        Ok(self
            .client
            .get(self.endpoint(path))
            .send()
            .with_context(|| format!("请求管理接口失败: {path}"))?
            .error_for_status()
            .with_context(|| format!("管理接口返回错误: {path}"))?
            .json()?)
    }

    fn post(&self, path: &str, body: Value) -> Result<Value> {
        Ok(self
            .client
            .post(self.endpoint(path))
            .json(&body)
            .send()
            .with_context(|| format!("请求管理接口失败: {path}"))?
            .error_for_status()
            .with_context(|| format!("管理接口返回错误: {path}"))?
            .json()?)
    }

    fn refresh(&mut self) {
        if self.refreshing {
            return;
        }
        self.refreshing = true;
        let result = (|| -> Result<()> {
            self.dashboard = self.get("/api/dashboard")?;
            self.system = self.get("/api/system")?;
            let sites = self.get("/api/sites")?;
            self.nginx = sites.get("nginx").cloned().unwrap_or(Value::Null);
            self.sites = sites
                .get("sites")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if self.nginx_path.is_empty() {
                self.nginx_path = text(&self.nginx, "config_dir");
                self.nginx_binary = text(&self.nginx, "binary");
            }
            Ok(())
        })();
        self.error = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
        self.last_refresh = Instant::now();
        self.refreshing = false;
    }

    fn load_logs(&mut self) {
        let endpoint = match self.page {
            Page::Requests => "/api/requests?page_size=50",
            Page::Interceptions => "/api/interceptions?page_size=50",
            _ => return,
        };
        match self.get(endpoint) {
            Ok(result) => {
                self.logs = result
                    .get("items")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                self.log_total = result.get("total").and_then(Value::as_u64).unwrap_or(0);
                self.error.clear();
            }
            Err(error) => self.error = error.to_string(),
        }
    }

    fn action(&mut self, result: Result<Value>) {
        match result {
            Ok(_) => {
                self.error.clear();
                self.refresh();
            }
            Err(error) => self.error = error.to_string(),
        }
    }

    fn ui_header(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("header").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("网站卫士");
                ui.separator();
                ui.label(format!("v{}", text(&self.system, "version")));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("刷新").clicked() {
                        self.refresh();
                        if matches!(self.page, Page::Requests | Page::Interceptions) {
                            self.load_logs();
                        }
                    }
                    if self.refreshing {
                        ui.spinner();
                    }
                });
            });
        });
    }

    fn ui_navigation(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("navigation")
            .resizable(false)
            .default_size(170.0)
            .show(ui, |ui| {
                ui.add_space(12.0);
                for (page, label) in [
                    (Page::Overview, "概览"),
                    (Page::Sites, "站点路由"),
                    (Page::Requests, "请求记录"),
                    (Page::Interceptions, "拦截记录"),
                ] {
                    if ui.selectable_label(self.page == page, label).clicked() {
                        self.page = page;
                        if matches!(page, Page::Requests | Page::Interceptions) {
                            self.load_logs();
                        }
                    }
                }
                ui.separator();
                ui.label(if self.tray_enabled {
                    "托盘菜单已启用"
                } else {
                    "托盘菜单不可用"
                });
            });
    }

    fn ui_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("运行概览");
        ui.add_space(8.0);
        let gateway = self.system.get("gateway").cloned().unwrap_or(Value::Null);
        let running = gateway
            .get("running")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        ui.horizontal_wrapped(|ui| {
            card(ui, "今日请求", number(&self.dashboard, "today_requests"));
            card(ui, "已验证", number(&self.dashboard, "today_verified"));
            card(ui, "已拦截", number(&self.dashboard, "today_blocked"));
            card(ui, "活动挑战", number(&self.dashboard, "active_challenges"));
        });
        ui.add_space(18.0);
        ui.group(|ui| {
            ui.heading("网关状态");
            ui.horizontal(|ui| {
                let color = if running {
                    egui::Color32::from_rgb(30, 150, 90)
                } else {
                    egui::Color32::from_rgb(190, 70, 70)
                };
                ui.colored_label(color, if running { "运行中" } else { "未启动" });
                if running {
                    if ui.button("停止网关").clicked() {
                        let result = self.post("/api/gateway/stop", json!({}));
                        self.action(result);
                    }
                } else if ui.button("启动网关").clicked() {
                    let result = self.post("/api/gateway/start", json!({}));
                    self.action(result);
                }
                ui.label(format!("监听地址: {}", text(&gateway, "http_listen")));
            });
        });
        ui.add_space(12.0);
        ui.label(format!(
            "许可证: {}",
            text(self.system.get("license").unwrap_or(&Value::Null), "status")
        ));
        if !self.update_message.is_empty() {
            ui.label(&self.update_message);
        }
        if ui.button("检查更新").clicked() {
            match self.get("/api/update/check") {
                Ok(result) => {
                    let update = result.get("update").unwrap_or(&Value::Null);
                    self.update_message = if update
                        .get("update_available")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        format!("发现新版本 v{}", text(update, "latest_version"))
                    } else {
                        format!("当前已是最新版本 v{}", text(update, "current_version"))
                    };
                }
                Err(error) => self.update_message = error.to_string(),
            }
        }
    }

    fn ui_sites(&mut self, ui: &mut egui::Ui) {
        ui.heading("站点路由");
        ui.horizontal(|ui| {
            ui.label("Host");
            ui.add(egui::TextEdit::singleline(&mut self.new_host).desired_width(170.0));
            ui.label("Upstream");
            ui.add(egui::TextEdit::singleline(&mut self.new_target).desired_width(230.0));
            if ui.button("添加站点").clicked() {
                let body = json!({"host": self.new_host.trim(), "target": self.new_target.trim(), "enabled": true, "policy": "normal"});
                self.action(self.post("/api/sites", body));
                self.new_host.clear();
                self.new_target.clear();
            }
        });
        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for site in self.sites.clone() {
                let host = text(&site, "host");
                let enabled = site
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.strong(&host);
                        ui.label(text(&site, "target"));
                        ui.label(if enabled { "保护中" } else { "已暂停" });
                        if ui.button(if enabled { "暂停" } else { "保护" }).clicked() {
                            let result = self.post(
                                "/api/sites/toggle",
                                json!({"host": host, "enabled": !enabled}),
                            );
                            self.action(result);
                        }
                        if ui.button("删除").clicked() {
                            let result = self.post("/api/sites/delete", json!({"host": host}));
                            self.action(result);
                        }
                    });
                });
            }
        });
        ui.separator();
        ui.heading("Nginx 扫描");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.nginx_path).hint_text("Nginx 安装目录或 conf 目录").desired_width(330.0));
            if ui.button("选择目录").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("选择 Nginx 安装或配置目录")
                    .pick_folder()
                {
                    self.nginx_path = path.display().to_string();
                }
            }
            ui.add(egui::TextEdit::singleline(&mut self.nginx_binary).hint_text("nginx.exe 路径（可选）").desired_width(260.0));
            if ui.button("扫描站点").clicked() {
                let result = self.post(
                    "/api/nginx/scan",
                    json!({"config_dir": self.nginx_path.trim(), "binary": self.nginx_binary.trim()}),
                );
                self.action(result);
            }
        });
        if let Some(error) = self.nginx.get("error").and_then(Value::as_str) {
            ui.colored_label(egui::Color32::YELLOW, error);
        }
    }

    fn ui_logs(&mut self, ui: &mut egui::Ui, interceptions: bool) {
        ui.horizontal(|ui| {
            ui.heading(if interceptions {
                "拦截记录"
            } else {
                "请求记录"
            });
            ui.label(format!("共 {} 条", self.log_total));
            if ui.button("清空").clicked() {
                let endpoint = if interceptions {
                    "/api/interceptions/clear"
                } else {
                    "/api/requests/clear"
                };
                let result = self.post(endpoint, json!({}));
                self.action(result);
                self.load_logs();
            }
        });
        egui::ScrollArea::vertical().show(ui, |ui| {
            for item in &self.logs {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(text(item, "host"));
                        ui.label(text(item, "path"));
                        ui.label(if interceptions {
                            text(item, "event_type")
                        } else {
                            format!("{} {}", text(item, "method"), text(item, "status"))
                        });
                        if interceptions {
                            ui.label(text(item, "action"));
                        } else {
                            ui.label(format!("{}ms", text(item, "latency_ms")));
                        }
                    });
                });
            }
        });
    }
}

impl eframe::App for DesktopApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        while let Ok(command) = self.tray_events.try_recv() {
            match command {
                TrayCommand::Exit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                TrayCommand::OpenAdmin => ctx.send_viewport_cmd(egui::ViewportCommand::Focus),
            }
        }
        if self.last_refresh.elapsed() >= Duration::from_secs(5) {
            self.refresh();
            if matches!(self.page, Page::Requests | Page::Interceptions) {
                self.load_logs();
            }
        }
        self.ui_header(ui);
        self.ui_navigation(ui);
        egui::CentralPanel::default().show(ui, |ui| match self.page {
            Page::Overview => self.ui_overview(ui),
            Page::Sites => self.ui_sites(ui),
            Page::Requests => self.ui_logs(ui, false),
            Page::Interceptions => self.ui_logs(ui, true),
        });
        if !self.error.is_empty() {
            egui::Panel::bottom("error").show(ui, |ui| {
                ui.colored_label(egui::Color32::RED, &self.error);
            });
        }
        let _ = &self.tray;
        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .map(|value| match value {
            Value::String(value) => value.clone(),
            Value::Null => "-".to_string(),
            value => value.to_string(),
        })
        .unwrap_or_else(|| "-".to_string())
}

fn number(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .to_string()
}

fn card(ui: &mut egui::Ui, title: &str, value: String) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(180.0);
        ui.label(title);
        ui.heading(value);
    });
}
