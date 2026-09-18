use anyhow::Result;
use tokio::sync::mpsc::{self, UnboundedReceiver};

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum TrayCommand {
    OpenAdmin,
    Exit,
}

pub(crate) struct TrayHandle {
    _keepalive: mpsc::UnboundedSender<TrayCommand>,
}

/// Desktop tray ownership lives in the Tauri shell. The backend keeps this
/// no-op adapter so Linux can continue using the same lifecycle wiring.
pub(crate) fn start(_admin_url: String) -> Result<(TrayHandle, UnboundedReceiver<TrayCommand>)> {
    let (sender, receiver) = mpsc::unbounded_channel();
    Ok((TrayHandle { _keepalive: sender }, receiver))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub(crate) fn open_admin(url: &str) -> Result<()> {
    use std::process::Command;

    Command::new("xdg-open")
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(Into::into)
}
