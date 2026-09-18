use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::UpdateConfig;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UpdateAsset {
    pub(crate) name: String,
    pub(crate) size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UpdateCheck {
    pub(crate) current_version: String,
    pub(crate) latest_version: String,
    pub(crate) update_available: bool,
    pub(crate) release_page: String,
    pub(crate) release_notes: String,
    pub(crate) asset: Option<UpdateAsset>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UpdateApply {
    pub(crate) latest_version: String,
    pub(crate) asset: UpdateAsset,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

struct ReleaseSelection {
    latest_version: String,
    release_page: String,
    release_notes: String,
    asset: GithubAsset,
    checksum: GithubAsset,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UpdateProgress {
    pub(crate) status: String,
    pub(crate) percent: u8,
    pub(crate) message: String,
    pub(crate) latest_version: Option<String>,
    pub(crate) release_notes: Option<String>,
}

impl Default for UpdateProgress {
    fn default() -> Self {
        Self {
            status: "idle".to_string(),
            percent: 0,
            message: String::new(),
            latest_version: None,
            release_notes: None,
        }
    }
}

pub(crate) type UpdateProgressState = Arc<Mutex<UpdateProgress>>;

pub(crate) async fn check(config: &UpdateConfig, current_version: &str) -> Result<UpdateCheck> {
    if !config.enabled {
        bail!("在线更新已禁用");
    }
    let selection = load_selection(&config.release_url).await?;
    Ok(UpdateCheck {
        current_version: current_version.to_string(),
        update_available: is_newer_version(&selection.latest_version, current_version),
        latest_version: selection.latest_version,
        release_page: selection.release_page,
        release_notes: selection.release_notes,
        asset: Some(UpdateAsset {
            name: selection.asset.name,
            size: selection.asset.size,
        }),
    })
}

pub(crate) async fn apply(
    config: &UpdateConfig,
    current_version: &str,
    progress: UpdateProgressState,
) -> Result<UpdateApply> {
    set_progress(&progress, "checking", 0, "正在检查最新版本", None, None);
    let result = apply_inner(config, current_version, &progress).await;
    if let Err(error) = &result {
        mark_failed(&progress, &error.to_string());
    }
    result
}

async fn apply_inner(
    config: &UpdateConfig,
    current_version: &str,
    progress: &UpdateProgressState,
) -> Result<UpdateApply> {
    if !config.enabled {
        bail!("在线更新已禁用");
    }
    let selection = load_selection(&config.release_url).await?;
    let latest_version = selection.latest_version.clone();
    if !is_newer_version(&latest_version, current_version) {
        bail!("当前已是最新版本 v{current_version}");
    }
    set_progress(
        progress,
        "downloading",
        5,
        "已找到新版本，准备下载",
        Some(latest_version.clone()),
        Some(selection.release_notes.clone()),
    );

    let client = client()?;
    let temp_dir = update_temp_dir()?;
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .with_context(|| format!("failed to create update directory {}", temp_dir.display()))?;
    let package_path = temp_dir.join(&selection.asset.name);
    let checksum_path = temp_dir.join(&selection.checksum.name);
    let package = download(
        &client,
        &selection.asset.browser_download_url,
        &package_path,
        progress,
        10,
        75,
        "正在下载更新包",
    )
    .await?;
    let checksum = download(
        &client,
        &selection.checksum.browser_download_url,
        &checksum_path,
        progress,
        75,
        90,
        "正在校验更新包",
    )
    .await?;
    verify_sha256(&package, &checksum)?;
    set_progress(
        progress,
        "restarting",
        95,
        "更新包校验完成，正在重启应用",
        Some(latest_version.clone()),
        Some(selection.release_notes.clone()),
    );
    schedule_platform_update(&temp_dir, &selection.asset.name).await?;

    Ok(UpdateApply {
        latest_version,
        asset: UpdateAsset {
            name: selection.asset.name,
            size: selection.asset.size,
        },
        message: "更新包已下载，应用将自动重启完成更新",
    })
}

async fn load_selection(release_url: &str) -> Result<ReleaseSelection> {
    let client = client()?;
    let release_url = https_url(release_url, "Release 地址")?;
    let (owner, repository) = github_repository(&release_url)
        .context("Release 地址必须指向 GitHub 仓库的 latest release")?;
    let api_url = Url::parse(&format!(
        "https://api.github.com/repos/{owner}/{repository}/releases/latest"
    ))?;
    let response = client
        .get(api_url)
        .send()
        .await
        .context("连接 GitHub Release 失败")?;
    let status = response.status();
    let response = response
        .error_for_status()
        .with_context(|| format!("GitHub Release 返回错误 ({status})"))?;
    let release: GithubRelease = response
        .json()
        .await
        .context("无法读取 GitHub Release 信息")?;
    let GithubRelease {
        tag_name: tag,
        html_url,
        body,
        assets,
    } = release;
    let latest_version = tag.trim_start_matches('v').to_string();
    let suffix = platform_package_suffix();
    let asset_name = format!("BotGate-{latest_version}{suffix}");
    let download_base = format!("https://github.com/{owner}/{repository}/releases/download/{tag}");
    let asset = assets
        .into_iter()
        .find(|asset| asset.name == asset_name)
        .map(|asset| GithubAsset {
            browser_download_url: asset.browser_download_url,
            name: asset.name,
            size: asset.size,
        })
        .unwrap_or_else(|| GithubAsset {
            browser_download_url: format!("{download_base}/{asset_name}"),
            name: asset_name,
            size: 0,
        });
    let checksum_name = format!("{}.sha256", asset.name);
    let checksum = GithubAsset {
        browser_download_url: format!("{download_base}/{checksum_name}"),
        name: checksum_name,
        size: 0,
    };
    https_url(&asset.browser_download_url, "更新包地址")?;
    https_url(&checksum.browser_download_url, "校验文件地址")?;
    Ok(ReleaseSelection {
        latest_version,
        release_page: html_url,
        release_notes: body.unwrap_or_default(),
        asset,
        checksum,
    })
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    body: Option<String>,
    #[serde(default)]
    assets: Vec<GithubReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

fn github_repository(url: &Url) -> Option<(String, String)> {
    let segments = url.path_segments()?.collect::<Vec<_>>();
    match url.host_str()? {
        "api.github.com" if segments.len() >= 3 && segments[0] == "repos" => {
            Some((segments[1].to_string(), segments[2].to_string()))
        }
        "github.com" if segments.len() >= 2 => {
            Some((segments[0].to_string(), segments[1].to_string()))
        }
        _ => None,
    }
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("BotGate/{0}", crate::APP_VERSION))
        .build()
        .context("创建更新客户端失败")
}

fn https_url(value: &str, label: &str) -> Result<Url> {
    let url = Url::parse(value).with_context(|| format!("{label}无效"))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        bail!("{label}必须使用 HTTPS");
    }
    Ok(url)
}

async fn download(
    client: &reqwest::Client,
    url: &str,
    path: &Path,
    progress: &UpdateProgressState,
    start: u8,
    end: u8,
    message: &str,
) -> Result<Vec<u8>> {
    let mut response = client
        .get(https_url(url, "下载地址")?)
        .send()
        .await
        .context("下载更新文件失败")?
        .error_for_status()
        .context("下载更新文件返回错误")?;
    let total = response.content_length().unwrap_or(0);
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("读取更新文件失败")? {
        body.extend_from_slice(&chunk);
        let percent = if total == 0 {
            start
        } else {
            start.saturating_add(
                (((body.len() as u64).saturating_mul((end - start) as u64)) / total) as u8,
            )
        };
        set_progress(
            progress,
            "downloading",
            percent.min(end),
            message,
            None,
            None,
        );
    }
    tokio::fs::write(path, &body)
        .await
        .with_context(|| format!("保存更新文件失败: {}", path.display()))?;
    Ok(body.to_vec())
}

fn set_progress(
    progress: &UpdateProgressState,
    status: &str,
    percent: u8,
    message: &str,
    latest_version: Option<String>,
    release_notes: Option<String>,
) {
    if let Ok(mut current) = progress.lock() {
        current.status = status.to_string();
        current.percent = percent;
        current.message = message.to_string();
        if latest_version.is_some() {
            current.latest_version = latest_version;
        }
        if release_notes.is_some() {
            current.release_notes = release_notes;
        }
    }
}

fn mark_failed(progress: &UpdateProgressState, message: &str) {
    if let Ok(mut current) = progress.lock() {
        current.status = "failed".to_string();
        current.message = message.to_string();
    }
}

fn verify_sha256(package: &[u8], checksum: &[u8]) -> Result<()> {
    let expected = std::str::from_utf8(checksum)
        .context("SHA256 校验文件不是 UTF-8")?
        .split_whitespace()
        .next()
        .unwrap_or_default();
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("SHA256 校验文件格式无效");
    }
    let actual = format!("{:x}", Sha256::digest(package));
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("更新包 SHA256 校验失败");
    }
    Ok(())
}

fn update_temp_dir() -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    Ok(env::temp_dir().join(format!(
        "bot-gate-update-{}-{timestamp}",
        std::process::id()
    )))
}

fn is_newer_version(remote: &str, current: &str) -> bool {
    let remote = version_parts(remote);
    let current = version_parts(current);
    for index in 0..3 {
        if remote[index] != current[index] {
            return remote[index] > current[index];
        }
    }
    false
}

fn version_parts(value: &str) -> [u64; 3] {
    let mut parts = [0; 3];
    for (index, part) in value.trim_start_matches('v').split('.').take(3).enumerate() {
        parts[index] = part.parse().unwrap_or(0);
    }
    parts
}

fn platform_package_suffix() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "-windows-x64-setup.exe"
    }
    #[cfg(target_os = "macos")]
    {
        "-macos-arm64.dmg"
    }
    #[cfg(target_os = "linux")]
    {
        "-linux-x64.tar.gz"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        "-unsupported"
    }
}

async fn schedule_platform_update(temp_dir: &Path, package_name: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        schedule_windows_update(temp_dir, package_name).await
    }
    #[cfg(target_os = "macos")]
    {
        schedule_macos_update(temp_dir, package_name).await
    }
    #[cfg(target_os = "linux")]
    {
        schedule_linux_update(temp_dir, package_name).await
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (temp_dir, package_name);
        bail!("当前操作系统不支持一键更新");
    }
}

#[cfg(target_os = "windows")]
async fn schedule_windows_update(temp_dir: &Path, package_name: &str) -> Result<()> {
    use std::os::windows::process::CommandExt;

    let executable = env::current_exe().context("无法定位当前程序")?;
    let installer = temp_dir.join(package_name);
    let script = temp_dir.join("update.ps1");
    let script_body = format!(
        "$ErrorActionPreference = 'Stop'\n$parentPid = {pid}\n$log = Join-Path $env:TEMP 'bot-gate-update.log'\n\"Bot Gate update started $(Get-Date -Format o)\" | Set-Content -LiteralPath $log\ntry {{\n  $deadline = (Get-Date).AddMinutes(5)\n  while ((Get-Process -Id $parentPid -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {{ Start-Sleep -Milliseconds 500 }}\n  if (Get-Process -Id $parentPid -ErrorAction SilentlyContinue) {{ throw '旧进程在 5 分钟内没有退出' }}\n  $installerProcess = Start-Process -FilePath {installer} -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/CLOSEAPPLICATIONS','/RESTARTAPPLICATIONS') -WorkingDirectory {working_directory} -PassThru -Wait\n  if ($installerProcess.ExitCode -ne 0) {{ throw \"安装器退出码: $($installerProcess.ExitCode)\" }}\n  if (Test-Path -LiteralPath {executable}) {{ Start-Process -FilePath {executable} -WorkingDirectory {working_directory} }}\n  \"Bot Gate update completed $(Get-Date -Format o)\" | Add-Content -LiteralPath $log\n}} catch {{\n  \"Bot Gate update failed: $($_.Exception.Message)\" | Add-Content -LiteralPath $log\n  exit 1\n}} finally {{\n  Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue\n}}\n",
        pid = std::process::id(),
        installer = powershell_quote(&installer),
        executable = powershell_quote(&executable),
        working_directory = powershell_quote(executable.parent().unwrap_or_else(|| Path::new("."))),
    );
    tokio::fs::write(&script, script_body)
        .await
        .with_context(|| format!("无法写入更新脚本: {}", script.display()))?;
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-File",
        ])
        .arg(&script)
        .creation_flags(0x08000000)
        .spawn()
        .context("无法启动 Windows 更新器")?;
    schedule_process_exit();
    Ok(())
}

#[cfg(target_os = "windows")]
fn powershell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
}

#[cfg(target_os = "macos")]
async fn schedule_macos_update(temp_dir: &Path, package_name: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let executable = env::current_exe().context("无法定位当前程序")?;
    let app = executable
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .context("无法定位 macOS 应用目录")?
        .to_path_buf();
    let dmg = temp_dir.join(package_name);
    let script = temp_dir.join("update.sh");
    let script_body = format!(
        "#!/bin/sh\nset -eu\nparent_pid={pid}\nwhile kill -0 \"$parent_pid\" 2>/dev/null; do sleep 1; done\nmount_dir=$(mktemp -d)\ncleanup() {{ hdiutil detach \"$mount_dir\" >/dev/null 2>&1 || true; rm -rf \"$mount_dir\"; }}\ntrap cleanup EXIT\nhdiutil attach {dmg} -nobrowse -readonly -mountpoint \"$mount_dir\" >/dev/null\nnew_app=$(find \"$mount_dir\" -maxdepth 1 -type d -name '*.app' -print -quit)\napp_path={app}\ntmp_app=\"${{app_path}}.update\"\nbackup_app=\"${{app_path}}.backup\"\nrm -rf \"$tmp_app\" \"$backup_app\"\nditto \"$new_app\" \"$tmp_app\"\nmv \"$app_path\" \"$backup_app\"\nif mv \"$tmp_app\" \"$app_path\"; then\n  open \"$app_path\"\n  rm -rf \"$backup_app\"\nelse\n  mv \"$backup_app\" \"$app_path\"\n  exit 1\nfi\nrm -f \"$0\"\n",
        pid = std::process::id(),
        dmg = shell_quote(&dmg),
        app = shell_quote(&app),
    );
    tokio::fs::write(&script, script_body)
        .await
        .with_context(|| format!("无法写入 macOS 更新脚本: {}", script.display()))?;
    let mut permissions = tokio::fs::metadata(&script).await?.permissions();
    permissions.set_mode(0o700);
    tokio::fs::set_permissions(&script, permissions).await?;
    Command::new("/bin/sh")
        .arg(&script)
        .spawn()
        .context("无法启动 macOS 更新器")?;
    schedule_process_exit();
    Ok(())
}

#[cfg(target_os = "linux")]
async fn schedule_linux_update(temp_dir: &Path, package_name: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let executable = env::current_exe().context("无法定位当前程序")?;
    let install_dir = executable.parent().context("无法定位安装目录")?;
    let archive = temp_dir.join(package_name);
    let script = temp_dir.join("update.sh");
    let script_body = format!(
        "#!/bin/sh\nset -eu\nparent_pid={pid}\nwhile kill -0 \"$parent_pid\" 2>/dev/null; do sleep 1; done\nextract_dir=$(mktemp -d)\ntar -xzf {archive} -C \"$extract_dir\"\nrelease_dir=$(find \"$extract_dir\" -mindepth 1 -maxdepth 1 -type d -print -quit)\ninstall -m 0755 \"$release_dir/bot-gate\" {executable}\nrm -rf {frontend}\ncp -R \"$release_dir/frontend\" {frontend}\nnohup {executable} >/dev/null 2>&1 &\nrm -rf \"$extract_dir\"\nrm -f \"$0\"\n",
        pid = std::process::id(),
        archive = shell_quote(&archive),
        executable = shell_quote(&executable),
        frontend = shell_quote(&install_dir.join("frontend")),
    );
    tokio::fs::write(&script, script_body).await?;
    let mut permissions = tokio::fs::metadata(&script).await?.permissions();
    permissions.set_mode(0o700);
    tokio::fs::set_permissions(&script, permissions).await?;
    Command::new("/bin/sh")
        .arg(&script)
        .spawn()
        .context("无法启动 Linux 更新器")?;
    schedule_process_exit();
    Ok(())
}

#[cfg(unix)]
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn schedule_process_exit() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        std::process::exit(0);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_accepts_strictly_newer_semantic_versions() {
        assert!(is_newer_version("0.2.8", "0.2.7"));
        assert!(is_newer_version("1.0.0", "0.99.99"));
        assert!(!is_newer_version("0.2.7", "0.2.7"));
        assert!(!is_newer_version("0.2.6", "0.2.7"));
        assert!(!is_newer_version("0.3.0", "1.0.0"));
    }

    #[test]
    fn rejects_invalid_or_mismatched_checksums() {
        let package = b"bot-gate package";
        let checksum = format!("{:x}  BotGate-test\n", Sha256::digest(package));
        assert!(verify_sha256(package, checksum.as_bytes()).is_ok());
        assert!(verify_sha256(package, b"not-a-checksum").is_err());
        assert!(verify_sha256(
            package,
            b"0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
    }

    #[test]
    fn recognizes_github_release_urls_without_using_the_api() {
        let api =
            Url::parse("https://api.github.com/repos/example/project/releases/latest").unwrap();
        let page = Url::parse("https://github.com/example/project/releases/latest").unwrap();
        assert_eq!(
            github_repository(&api),
            Some(("example".to_string(), "project".to_string()))
        );
        assert_eq!(
            github_repository(&page),
            Some(("example".to_string(), "project".to_string()))
        );
    }
}
