#[cfg(unix)]
use std::process::Command;

use anyhow::{Context, Result};
use tokio::sync::mpsc::{self, UnboundedReceiver};

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum TrayCommand {
    OpenAdmin,
    Exit,
}

pub(crate) struct TrayHandle {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    tray: tray_item::TrayItem,
    #[cfg(target_os = "macos")]
    _keepalive: mpsc::UnboundedSender<TrayCommand>,
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    _keepalive: mpsc::UnboundedSender<TrayCommand>,
}

#[allow(unused_variables)]
pub(crate) fn start(admin_url: String) -> Result<(TrayHandle, UnboundedReceiver<TrayCommand>)> {
    let (sender, receiver) = mpsc::unbounded_channel();

    #[cfg(target_os = "windows")]
    {
        use std::{env, os::windows::ffi::OsStrExt, path::PathBuf};
        use tray_item::{IconSource, TrayItem};
        use windows_sys::Win32::{
            Foundation::HINSTANCE,
            UI::WindowsAndMessaging::{LoadIconW, LoadImageW, IMAGE_ICON, LR_LOADFROMFILE},
        };

        let icon_path = env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(PathBuf::from))
            .map(|path| path.join("bot-gate.ico"));
        let icon = icon_path
            .as_ref()
            .filter(|path| path.exists())
            .and_then(|path| {
                let wide: Vec<u16> = path
                    .as_os_str()
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let handle = unsafe {
                    LoadImageW(
                        0 as HINSTANCE,
                        wide.as_ptr(),
                        IMAGE_ICON,
                        0,
                        0,
                        LR_LOADFROMFILE,
                    )
                };
                (handle != 0).then(|| IconSource::RawIcon(handle))
            })
            .unwrap_or_else(|| unsafe {
                IconSource::RawIcon(LoadIconW(
                    0 as HINSTANCE,
                    windows_sys::Win32::UI::WindowsAndMessaging::IDI_APPLICATION,
                ))
            });
        let mut tray =
            TrayItem::new("Bot Gate", icon).context("failed to create Windows tray icon")?;
        let open_sender = sender.clone();
        tray.add_menu_item("打开管理台", move || {
            let _ = open_sender.send(TrayCommand::OpenAdmin);
        })
        .context("failed to create tray management menu")?;
        let exit_sender = sender.clone();
        tray.add_menu_item("退出 Bot Gate", move || {
            let _ = exit_sender.send(TrayCommand::Exit);
        })
        .context("failed to create tray exit menu")?;

        let _ = admin_url;
        return Ok((TrayHandle { tray }, receiver));
    }

    #[cfg(target_os = "macos")]
    {
        use tray_item::{IconSource, TrayItem};

        let mut tray = TrayItem::new(
            "网站卫士",
            IconSource::Data {
                width: 1024,
                height: 1024,
                data: include_bytes!("../../packaging/assets/bot-gate-icon.png").to_vec(),
            },
        )
        .context("failed to create macOS menu bar icon")?;
        let open_url = admin_url.clone();
        tray.add_menu_item("打开管理后台", move || {
            let _ = open_admin(&open_url);
        })
        .context("failed to create macOS management menu")?;
        tray.inner_mut().add_quit_item("退出网站卫士");
        Ok((
            TrayHandle {
                tray,
                _keepalive: sender,
            },
            receiver,
        ))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = admin_url;
        Ok((TrayHandle { _keepalive: sender }, receiver))
    }
}

#[cfg(target_os = "macos")]
impl TrayHandle {
    pub(crate) fn display(&mut self) {
        self.tray.inner_mut().display();
    }
}

pub(crate) fn open_admin(url: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

        let operation: Vec<u16> = std::ffi::OsStr::new("open")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let target: Vec<u16> = std::ffi::OsStr::new(url)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let result = unsafe {
            ShellExecuteW(
                0,
                operation.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if result <= 32 {
            anyhow::bail!("Windows failed to open management dashboard (code {result})");
        }
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url)
            .spawn()
            .context("failed to open management dashboard")?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(url)
            .spawn()
            .context("failed to open management dashboard")?;
    }
    Ok(())
}
