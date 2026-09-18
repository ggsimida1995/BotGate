#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs,
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
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let paths = runtime_paths(app.handle())?;
            let port = available_port()?;
            let admin_url = format!("http://127.0.0.1:{port}");
            let mut backend = start_backend(&paths, port)?;
            if let Err(error) = wait_for_admin(port) {
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
        .expect("网站卫士桌面客户端初始化失败")
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
    Ok(RuntimePaths {
        backend,
        config,
        frontend: root.join("frontend/dist"),
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
    }
    Ok(config)
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
    let desktop_executable = std::env::current_exe()?;
    Ok(Command::new(&paths.backend)
        .arg("--headless")
        .arg(&paths.config)
        .env("BOT_GATE_ADMIN_LISTEN", format!("127.0.0.1:{port}"))
        .env("BOT_GATE_FRONTEND_DIST", &paths.frontend)
        .env("BOT_GATE_DESKTOP_EXECUTABLE", desktop_executable)
        .env("BOT_GATE_DESKTOP_PID", std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn wait_for_admin(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("管理服务启动超时".into())
}

fn create_window(app: &mut tauri::App, admin_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = url::Url::parse(admin_url)?;
    WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
        .title("网站卫士")
        .inner_size(1280.0, 800.0)
        .min_inner_size(960.0, 620.0)
        .center()
        .build()?;
    Ok(())
}

fn create_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let open = MenuItem::with_id(app, "open", "打开管理台", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出网站卫士", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    TrayIconBuilder::new()
        .icon(tauri::image::Image::from_bytes(include_bytes!(
            "../../packaging/assets/bot-gate-icon.png"
        ))?)
        .menu(&menu)
        .tooltip("网站卫士")
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
