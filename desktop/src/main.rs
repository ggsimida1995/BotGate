#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager, WebviewUrl, WebviewWindowBuilder,
};

const BACKEND_NAME: &str = if cfg!(target_os = "windows") {
    "bot-gate-backend.exe"
} else {
    "bot-gate-backend"
};

struct BackendProcess(Mutex<Option<Child>>);

struct RuntimePaths {
    backend: PathBuf,
    config: PathBuf,
    frontend: PathBuf,
    logs: PathBuf,
}

fn log_path(logs: &Path, name: &str) -> PathBuf {
    logs.join(name)
}

fn writable_log_directory(app: &tauri::AppHandle) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let install_logs = std::env::current_exe()?
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("logs");
    if can_write_directory(&install_logs).is_ok() {
        return Ok(install_logs);
    }

    let fallback = app.path().app_data_dir()?.join("logs");
    can_write_directory(&fallback)?;
    Ok(fallback)
}

fn can_write_directory(directory: &Path) -> std::io::Result<()> {
    fs::create_dir_all(directory)?;
    let probe = directory.join(".write-test");
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&probe)?;
    fs::remove_file(probe)
}

fn append_log(path: &Path, message: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{message}")
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let paths = runtime_paths(app.handle())?;
            let port = available_port()?;
            let admin_url = format!("http://127.0.0.1:{port}");
            let desktop_log = log_path(&paths.logs, "desktop.log");
            append_log(
                &desktop_log,
                &format!(
                    "starting desktop; backend={} config={} frontend={} admin={}",
                    paths.backend.display(),
                    paths.config.display(),
                    paths.frontend.display(),
                    admin_url
                ),
            )?;
            let mut backend = match start_backend(&paths, port) {
                Ok(backend) => backend,
                Err(error) => {
                    let _ = append_log(&desktop_log, &format!("backend spawn failed: {error}"));
                    return Err(error);
                }
            };
            if let Err(error) = wait_for_admin(port, &mut backend, &desktop_log) {
                let _ = backend.kill();
                return Err(error);
            }
            app.manage(BackendProcess(Mutex::new(Some(backend))));
            create_window(app, &admin_url)?;
            create_tray(app)?;
            watch_backend(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("Bot Gate desktop client initialization failed")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                stop_backend(app);
            }
        })
}

fn runtime_paths(app: &tauri::AppHandle) -> Result<RuntimePaths, Box<dyn std::error::Error>> {
    let resource_dir = app.path().resource_dir()?.join("resources");
    let bundled_backend = resource_dir.join(BACKEND_NAME);
    let bundled_frontend = resource_dir.join("frontend/dist");
    let bundled_config = resource_dir.join("config.toml");
    if bundled_backend.exists() && bundled_frontend.join("admin.html").exists() {
        let config = persistent_config(app, &bundled_config)?;
        return Ok(RuntimePaths {
            backend: bundled_backend,
            config,
            frontend: bundled_frontend,
            logs: writable_log_directory(app)?,
        });
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("desktop directory has a repository parent");
    let backend_name = if cfg!(target_os = "windows") {
        "bot-gate.exe"
    } else {
        "bot-gate"
    };
    let backend = root.join("backend/target/release").join(backend_name);
    let config = root.join("backend/config.toml");
    let config = if config.exists() {
        config
    } else {
        root.join("backend/config.example.toml")
    };
    let logs = writable_log_directory(app)?;
    Ok(RuntimePaths {
        backend,
        config,
        frontend: root.join("frontend/dist"),
        logs,
    })
}

fn persistent_config(
    app: &tauri::AppHandle,
    bundled_config: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let config_dir = app.path().app_data_dir()?;
    fs::create_dir_all(&config_dir)?;
    let config = config_dir.join("config.toml");
    if !config.exists() {
        fs::copy(bundled_config, &config)?;
    } else {
        migrate_legacy_default_listener(&config)?;
    }
    Ok(config)
}

fn migrate_legacy_default_listener(config: &Path) -> std::io::Result<()> {
    let content = fs::read_to_string(config)?;
    let mut in_server = false;
    let mut changed = false;
    let mut migrated = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_server = trimmed == "[server]";
        }
        if in_server
            && matches!(
                trimmed,
                r#"listen = "127.0.0.1:8080""# | r#"listen = "127.0.0.1:18081""#
            )
        {
            migrated.push_str(
                &line.replace(
                    trimmed
                        .trim_start_matches("listen = \"")
                        .trim_end_matches('"'),
                    "127.0.0.1:0",
                ),
            );
            changed = true;
        } else {
            migrated.push_str(line);
        }
        migrated.push('\n');
    }
    if changed {
        fs::write(config, migrated)?;
    }
    Ok(())
}

fn available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn start_backend(paths: &RuntimePaths, port: u16) -> Result<Child, Box<dyn std::error::Error>> {
    if !paths.backend.exists() {
        return Err(format!("未找到后端程序：{}", paths.backend.display()).into());
    }
    if !paths.frontend.join("admin.html").exists() {
        return Err(format!("未找到管理界面资源：{}", paths.frontend.display()).into());
    }
    let backend_log = log_path(&paths.logs, "desktop-backend.log");
    if let Some(parent) = backend_log.parent() {
        fs::create_dir_all(parent)?;
    }
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&backend_log)?;
    let stderr = stdout.try_clone()?;
    append_log(
        &backend_log,
        &format!(
            "spawning backend={} config={} frontend={} admin=127.0.0.1:{}",
            paths.backend.display(),
            paths.config.display(),
            paths.frontend.display(),
            port
        ),
    )?;
    let desktop_executable = std::env::current_exe()?;
    let mut command = Command::new(&paths.backend);
    command
        .arg("--headless")
        .arg(&paths.config)
        .env("BOT_GATE_ADMIN_LISTEN", format!("127.0.0.1:{port}"))
        .env("BOT_GATE_FRONTEND_DIST", &paths.frontend)
        .env("BOT_GATE_LOG_DIR", &paths.logs)
        .env("BOT_GATE_DESKTOP_EXECUTABLE", desktop_executable)
        .env("BOT_GATE_DESKTOP_PID", std::process::id().to_string());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        command.creation_flags(0x08000000);
    }
    Ok(command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?)
}

fn wait_for_admin(
    port: u16,
    backend: &mut Child,
    desktop_log: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        if let Some(status) = backend.try_wait()? {
            let message = format!(
                "backend exited before management API was ready: {status}; see {} and the backend log next to it",
                desktop_log.display()
            );
            let _ = append_log(desktop_log, &message);
            return Err(message.into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    let message = format!("management API startup timed out on 127.0.0.1:{port}");
    let _ = append_log(desktop_log, &message);
    Err(format!("管理服务启动超时；详见 {}", desktop_log.display()).into())
}

fn create_window(app: &mut tauri::App, admin_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = url::Url::parse(admin_url)?;
    WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
        .title("Bot Gate")
        .inner_size(1280.0, 800.0)
        .min_inner_size(960.0, 620.0)
        .center()
        .build()?;
    Ok(())
}

fn create_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let open = MenuItem::with_id(app, "open", "Open Dashboard", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Bot Gate", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    TrayIconBuilder::new()
        .icon(tauri::image::Image::from_bytes(include_bytes!(
            "../../packaging/assets/bot-gate-icon.png"
        ))?)
        .menu(&menu)
        .tooltip("Bot Gate")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_window(app),
            "quit" => {
                stop_backend(app);
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn show_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn watch_backend(app: tauri::AppHandle) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(250));
        let exited = app
            .try_state::<BackendProcess>()
            .and_then(|process| process.0.lock().ok()?.as_mut()?.try_wait().ok())
            .flatten()
            .is_some();
        if exited {
            app.exit(0);
            break;
        }
    });
}

fn stop_backend(app: &tauri::AppHandle) {
    if let Some(process) = app.try_state::<BackendProcess>() {
        if let Ok(mut child) = process.0.lock() {
            if let Some(child) = child.as_mut() {
                let _ = child.kill();
            }
        }
    }
}
