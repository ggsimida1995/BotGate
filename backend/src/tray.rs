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
    #[cfg(target_os = "windows")]
    tray: tray_item::TrayItem,
    #[cfg(not(target_os = "windows"))]
    _keepalive: mpsc::UnboundedSender<TrayCommand>,
}

#[allow(unused_variables)]
pub(crate) fn start(admin_url: String) -> Result<(TrayHandle, UnboundedReceiver<TrayCommand>)> {
    let (sender, receiver) = mpsc::unbounded_channel();

    #[cfg(target_os = "windows")]
    {
        use tray_item::{IconSource, TrayItem};
        use windows_sys::Win32::{
            Foundation::HINSTANCE,
            UI::WindowsAndMessaging::{LoadIconW, IDI_APPLICATION},
        };

        let icon = unsafe { IconSource::RawIcon(LoadIconW(0 as HINSTANCE, IDI_APPLICATION)) };
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

    #[cfg(not(target_os = "windows"))]
    {
        let _ = admin_url;
        Ok((TrayHandle { _keepalive: sender }, receiver))
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
