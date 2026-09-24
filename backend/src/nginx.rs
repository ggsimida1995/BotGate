use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::{ManagedSite, NginxConfig};

const MARKER_PREFIX: &str = "# bot-gate:inline:";

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NginxDetection {
    pub(crate) available: bool,
    pub(crate) config_valid: bool,
    pub(crate) binary: Option<String>,
    pub(crate) config_file: Option<String>,
    pub(crate) message: String,
}

pub(crate) fn resolve_config(config: &NginxConfig) -> Result<NginxConfig> {
    let mut resolved = config.clone();
    resolved.binary = resolve_binary(&config.binary)?;
    Ok(resolved)
}

pub(crate) fn detect(config: &NginxConfig) -> NginxDetection {
    let resolved = match resolve_config(config) {
        Ok(config) => config,
        Err(error) => {
            return NginxDetection {
                available: false,
                config_valid: false,
                binary: None,
                config_file: None,
                message: error.to_string(),
            }
        }
    };

    let mut command = Command::new(&resolved.binary);
    add_config_arg(&mut command, &resolved.config_file);
    match command.arg("-t").output() {
        Ok(output) if output.status.success() => NginxDetection {
            available: true,
            config_valid: true,
            binary: Some(resolved.binary),
            config_file: (!resolved.config_file.is_empty()).then_some(resolved.config_file),
            message: "已找到 Nginx，配置校验通过".to_string(),
        },
        Ok(output) => NginxDetection {
            available: true,
            config_valid: false,
            binary: Some(resolved.binary),
            config_file: (!resolved.config_file.is_empty()).then_some(resolved.config_file),
            message: format!("已找到 Nginx，但配置校验失败：{}", diagnostic_tail(&output)),
        },
        Err(error) => NginxDetection {
            available: true,
            config_valid: false,
            binary: Some(resolved.binary),
            config_file: (!resolved.config_file.is_empty()).then_some(resolved.config_file),
            message: format!("已找到 Nginx，但无法执行配置校验：{error}"),
        },
    }
}

pub(crate) fn sync_site(config: &NginxConfig, gate_listen: &str, site: &ManagedSite) -> Result<()> {
    if !config.enabled {
        bail!("Nginx 内联适配未启用；请先在 [nginx] 中启用它，并确认 binary/include_dir 可用");
    }
    let config = resolve_config(config)?;
    let vhost = find_vhost(&config, &site.host)?;
    let original = fs::read_to_string(&vhost)
        .with_context(|| format!("无法读取 Nginx 站点配置 {}", vhost.display()))?;
    let include = include_path(&config, &site.host)?;
    let previous_include = fs::read_to_string(&include).ok();
    let (updated, desired_include) = if site.enabled {
        (
            insert_marker(&original, &site.host, &include)?,
            Some(render_include(gate_listen)),
        )
    } else {
        (remove_marker(&original, &site.host), None)
    };
    let vhost_changed = updated != original;
    let include_changed = match (&previous_include, &desired_include) {
        (Some(previous), Some(desired)) => previous != desired,
        (None, Some(_)) | (Some(_), None) => true,
        (None, None) => false,
    };
    if !vhost_changed && !include_changed {
        return Ok(());
    }

    if let Some(content) = desired_include.as_deref() {
        fs::create_dir_all(&config.include_dir)
            .with_context(|| format!("无法创建 Nginx include 目录 {}", config.include_dir))?;
        fs::write(&include, content)
            .with_context(|| format!("无法写入 Nginx 防护 include {}", include.display()))?;
    } else if include.exists() {
        fs::remove_file(&include)
            .with_context(|| format!("无法移除 Nginx 防护 include {}", include.display()))?;
    }
    if vhost_changed {
        fs::write(&vhost, &updated)
            .with_context(|| format!("无法更新 Nginx 站点配置 {}", vhost.display()))?;
    }

    if let Err(error) = test_and_reload(&config) {
        if vhost_changed {
            let _ = fs::write(&vhost, original);
        }
        match previous_include {
            Some(content) => {
                let _ = fs::create_dir_all(&config.include_dir);
                let _ = fs::write(&include, content);
            }
            None => {
                let _ = fs::remove_file(&include);
            }
        }
        return Err(error);
    }
    Ok(())
}

pub(crate) fn remove_site(
    config: &NginxConfig,
    gate_listen: &str,
    site: &ManagedSite,
) -> Result<()> {
    let mut disabled = site.clone();
    disabled.enabled = false;
    sync_site(config, gate_listen, &disabled)
}

#[allow(dead_code)]
pub(crate) fn is_site_protected(config: &NginxConfig, host: &str) -> Result<bool> {
    let config = resolve_config(config)?;
    let vhost = find_vhost(&config, host)?;
    let include = include_path(&config, host)?;
    let body = fs::read_to_string(&vhost)
        .with_context(|| format!("无法读取 Nginx 站点配置 {}", vhost.display()))?;
    Ok(include.exists() && body.contains(&format!("{MARKER_PREFIX}{host}:begin")))
}

fn resolve_binary(binary: &str) -> Result<String> {
    let requested = binary.trim();
    if !requested.is_empty() && !is_default_binary(requested) {
        if can_execute(requested) {
            return Ok(requested.to_string());
        }
        bail!("无法执行配置中的 Nginx：{requested}");
    }

    if can_execute("nginx") {
        return Ok("nginx".to_string());
    }
    let candidates = nginx_binary_candidates();
    let existing = first_existing_binary(candidates.clone())
        .filter(|path| can_execute(&path.to_string_lossy()));
    if let Some(path) = existing {
        return Ok(path.to_string_lossy().into_owned());
    }
    bail!(
        "未找到 Nginx。已自动检查 PATH 和常见安装目录；请确认 Nginx 正在本机安装并可执行。已检查：{}",
        candidates
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn is_default_binary(binary: &str) -> bool {
    binary.eq_ignore_ascii_case("nginx") || binary.eq_ignore_ascii_case("nginx.exe")
}

fn can_execute(binary: &str) -> bool {
    Command::new(binary).arg("-v").output().is_ok()
}

fn nginx_binary_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(current_dir) = env::current_dir() {
        candidates.push(current_dir.join(if cfg!(target_os = "windows") {
            "nginx.exe"
        } else {
            "nginx"
        }));
    }

    candidates.extend(running_nginx_binary_candidates());
    if let Ok(executable) = env::current_exe() {
        if let Some(directory) = executable.parent() {
            candidates.push(directory.join(if cfg!(target_os = "windows") {
                "nginx.exe"
            } else {
                "nginx"
            }));
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut roots = vec![PathBuf::from(r"C:\nginx")];
        roots.extend(
            [
                "ProgramFiles",
                "ProgramFiles(x86)",
                "ProgramW6432",
                "LOCALAPPDATA",
                "USERPROFILE",
            ]
            .into_iter()
            .filter_map(env::var_os)
            .map(PathBuf::from),
        );
        for root in roots {
            candidates.push(root.join("nginx.exe"));
            candidates.push(root.join("nginx").join("nginx.exe"));
            candidates.push(root.join("nginx").join("sbin").join("nginx.exe"));
        }
    }

    #[cfg(not(target_os = "windows"))]
    candidates.extend([
        PathBuf::from("/opt/homebrew/bin/nginx"),
        PathBuf::from("/usr/local/bin/nginx"),
        PathBuf::from("/usr/local/nginx/sbin/nginx"),
        PathBuf::from("/usr/sbin/nginx"),
        PathBuf::from("/opt/nginx/sbin/nginx"),
    ]);

    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

#[cfg(target_os = "windows")]
fn running_nginx_binary_candidates() -> Vec<PathBuf> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance Win32_Process -Filter \"Name = 'nginx.exe'\" | Select-Object -First 1 -ExpandProperty ExecutablePath)",
        ])
        .output();
    output
        .ok()
        .into_iter()
        .flat_map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        })
        .filter(|path| !path.as_os_str().is_empty())
        .collect()
}

#[cfg(not(target_os = "windows"))]
fn running_nginx_binary_candidates() -> Vec<PathBuf> {
    Vec::new()
}

fn first_existing_binary<I>(candidates: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = PathBuf>,
{
    candidates.into_iter().find(|path| path.is_file())
}

fn diagnostic_tail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stderr
        .lines()
        .last()
        .or_else(|| stdout.lines().last())
        .unwrap_or("unknown nginx error")
        .trim()
        .to_string()
}

fn test_and_reload(config: &NginxConfig) -> Result<()> {
    let mut test = Command::new(&config.binary);
    add_config_arg(&mut test, &config.config_file);
    let test = test
        .arg("-t")
        .output()
        .with_context(|| format!("无法执行 {} -t", config.binary))?;
    if !test.status.success() {
        bail!(
            "Nginx 配置校验失败: {}",
            String::from_utf8_lossy(&test.stderr).trim()
        );
    }

    let mut reload = Command::new(&config.binary);
    add_config_arg(&mut reload, &config.config_file);
    let reload = reload
        .args(["-s", "reload"])
        .output()
        .with_context(|| format!("无法执行 {} -s reload", config.binary))?;
    if !reload.status.success() {
        bail!(
            "Nginx 平滑重载失败: {}",
            String::from_utf8_lossy(&reload.stderr).trim()
        );
    }
    Ok(())
}

fn add_config_arg(command: &mut Command, config_file: &str) {
    if !config_file.trim().is_empty() {
        command.args(["-c", config_file]);
    }
}

fn include_path(config: &NginxConfig, host: &str) -> Result<PathBuf> {
    if host.is_empty() || host.contains(['/', '\\', '\r', '\n']) {
        bail!("invalid host for Nginx include");
    }
    Ok(Path::new(&config.include_dir).join(format!("{host}.conf")))
}

fn find_vhost(config: &NginxConfig, host: &str) -> Result<PathBuf> {
    let files = if config.vhost_dir.trim().is_empty() {
        discover_loaded_config_files(config)?
    } else {
        read_vhost_directory(&config.vhost_dir)?
    };
    let matches = files
        .into_iter()
        .filter_map(|(path, body)| {
            matching_server_closes(&body, host)
                .ok()
                .filter(|blocks| !blocks.is_empty())
                .map(|_| path)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => bail!("未找到 server_name 包含 {host} 的 Nginx vhost；请确认该站点已加载且 nginx -T 可读取配置"),
        _ => bail!("找到多个包含 {host} 的 Nginx vhost，拒绝自动修改"),
    }
}

fn read_vhost_directory(directory: &str) -> Result<Vec<(PathBuf, String)>> {
    let directory = Path::new(directory);
    let entries = fs::read_dir(directory)
        .with_context(|| format!("无法读取 Nginx vhost 目录 {}", directory.display()))?;
    Ok(entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "conf")
        })
        .filter_map(|path| fs::read_to_string(&path).ok().map(|body| (path, body)))
        .collect())
}

fn discover_loaded_config_files(config: &NginxConfig) -> Result<Vec<(PathBuf, String)>> {
    let mut command = Command::new(&config.binary);
    add_config_arg(&mut command, &config.config_file);
    let output = command.arg("-T").output().with_context(|| {
        format!(
            "无法执行 {} -T；请在 [nginx].binary 中填写 Nginx 可执行文件",
            config.binary
        )
    })?;
    let mut diagnostic = String::from_utf8_lossy(&output.stdout).into_owned();
    diagnostic.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        bail!(
            "无法读取 Nginx 生效配置（{} -T）：{}",
            config.binary,
            diagnostic
                .lines()
                .last()
                .unwrap_or("unknown nginx error")
                .trim()
        );
    }

    let paths = extract_config_paths(&diagnostic);
    let mut seen = HashSet::new();
    let files = paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .filter_map(|path| fs::read_to_string(&path).ok().map(|body| (path, body)))
        .collect::<Vec<_>>();
    if files.is_empty() {
        bail!("nginx -T 未返回可读取的配置文件；请填写 [nginx].vhost_dir，或检查 Nginx 进程权限");
    }
    Ok(files)
}

fn extract_config_paths(output: &str) -> Vec<PathBuf> {
    const PREFIX: &str = "# configuration file ";
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let path = line.strip_prefix(PREFIX)?.strip_suffix(':')?.trim();
            (!path.is_empty()).then(|| PathBuf::from(path))
        })
        .collect()
}

fn render_include(gate_listen: &str) -> String {
    let gate_listen = gate_listen.strip_prefix("http://").unwrap_or(gate_listen);
    let gate_listen = gate_listen.strip_prefix("https://").unwrap_or(gate_listen);
    format!(
        r#"# Generated by Bot Gate. Include this file inside the protected server {{ }} block.
auth_request /_bot_gate/check;
error_page 401 = @bot_gate_challenge;
error_page 403 = @bot_gate_deny;

location = /_bot_gate/check {{
    internal;
    auth_request off;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Bot-Gate-Original-URI $request_uri;
    proxy_set_header X-Bot-Gate-Original-Method $request_method;
    proxy_pass http://{gate_listen}/_bot_gate/check;
}}

location ^~ /_bot_gate/ {{
    auth_request off;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_pass http://{gate_listen};
}}

location @bot_gate_challenge {{
    internal;
    auth_request off;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Bot-Gate-Original-URI $request_uri;
    proxy_set_header X-Bot-Gate-Original-Method $request_method;
    rewrite ^ /_bot_gate/challenge break;
    proxy_pass http://{gate_listen};
}}

location @bot_gate_deny {{
    internal;
    auth_request off;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Bot-Gate-Original-URI $request_uri;
    proxy_set_header X-Bot-Gate-Original-Method $request_method;
    rewrite ^ /_bot_gate/deny break;
    proxy_pass http://{gate_listen};
}}
"#
    )
}

fn marker(host: &str, include: &Path) -> String {
    format!(
        "{MARKER_PREFIX}{host}:begin\ninclude \"{}\";\n{MARKER_PREFIX}{host}:end\n",
        nginx_path_literal(include)
    )
}

fn nginx_path_literal(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .replace('$', "\\$")
        .replace('\"', "\\\"")
}

fn remove_marker(body: &str, host: &str) -> String {
    let start = format!("{MARKER_PREFIX}{host}:begin");
    let end = format!("{MARKER_PREFIX}{host}:end");
    let mut result = String::with_capacity(body.len());
    let mut cursor = body;
    while let Some(index) = cursor.find(&start) {
        result.push_str(&cursor[..index]);
        let rest = &cursor[index..];
        let Some(end_index) = rest.find(&end) else {
            result.push_str(rest);
            return result;
        };
        cursor = &rest[end_index + end.len()..];
        if let Some(stripped) = cursor.strip_prefix('\n') {
            cursor = stripped;
        }
    }
    result.push_str(cursor);
    result
}

fn insert_marker(body: &str, host: &str, include: &Path) -> Result<String> {
    let body = remove_marker(body, host);
    let closes = matching_server_closes(&body, host)?;
    if closes.is_empty() {
        bail!("未找到 server_name 包含 {host} 的 server 块");
    }
    let marker = marker(host, include);
    let mut result = body;
    for close in closes.into_iter().rev() {
        let indented = marker.replace('\n', "\n    ");
        result.insert_str(close, &format!("\n    {indented}"));
    }
    Ok(result)
}

fn matching_server_closes(body: &str, host: &str) -> Result<Vec<usize>> {
    let mut blocks = Vec::new();
    let mut offset = 0;
    let mut start = None;
    let mut depth = 0i32;
    let mut names_match = false;
    for line in body.split_inclusive('\n') {
        let code = line.split('#').next().unwrap_or_default();
        let trimmed = code.trim();
        if start.is_none() && trimmed.starts_with("server") && trimmed.contains('{') {
            start = Some(offset);
            depth = 0;
            names_match = false;
        }
        if start.is_some() && trimmed.starts_with("server_name") {
            let mut names = trimmed
                .trim_start_matches("server_name")
                .trim()
                .trim_end_matches(';')
                .split_whitespace();
            names_match |= names.any(|name| name.eq_ignore_ascii_case(host));
        }
        if start.is_some() {
            depth += code.matches('{').count() as i32;
            depth -= code.matches('}').count() as i32;
            if depth == 0 {
                if names_match {
                    let close = offset + code.rfind('}').context("server block missing close")?;
                    blocks.push(close);
                }
                start = None;
            }
        }
        offset += line.len();
    }
    if start.is_some() {
        bail!("Nginx server block braces are unbalanced");
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_and_removes_a_site_marker_in_each_matching_server() {
        let source = "server {\n server_name dada.com;\n}\nserver {\n server_name dada.com www.dada.com;\n}\n";
        let include = Path::new("/tmp/bot-gate/dada.com.conf");
        let inserted = insert_marker(source, "dada.com", include).unwrap();
        assert_eq!(
            inserted.matches("bot-gate:inline:dada.com:begin").count(),
            2
        );
        assert!(!remove_marker(&inserted, "dada.com").contains("bot-gate:inline:dada.com"));
    }

    #[test]
    fn extracts_loaded_config_paths_without_assuming_an_install_layout() {
        let output = "# configuration file /opt/nginx/nginx.conf:\n# configuration file /srv/sites/example.conf:\n";
        assert_eq!(
            extract_config_paths(output),
            vec![
                PathBuf::from("/opt/nginx/nginx.conf"),
                PathBuf::from("/srv/sites/example.conf"),
            ]
        );
    }

    #[test]
    fn quotes_include_paths_with_spaces() {
        let source = "server {\n server_name dada.com;\n}\n";
        let include =
            Path::new("/Users/fyx/Library/Application Support/BotGate/data/nginx/dada.com.conf");
        let inserted = insert_marker(source, "dada.com", include).unwrap();
        assert!(inserted.contains(
            r#"include "/Users/fyx/Library/Application Support/BotGate/data/nginx/dada.com.conf";"#
        ));
    }

    #[test]
    fn renders_an_internal_auth_request_bridge() {
        let snippet = render_include("127.0.0.1:8080");
        assert!(snippet.contains("auth_request /_bot_gate/check"));
        assert!(snippet.contains("rewrite ^ /_bot_gate/challenge break;"));
    }

    #[test]
    fn renders_a_valid_upstream_without_url_scheme() {
        let snippet = render_include("http://127.0.0.1:8080");
        assert!(snippet.contains("proxy_pass http://127.0.0.1:8080/_bot_gate/check;"));
        assert!(!snippet.contains("http://http://"));
    }

    #[test]
    fn selects_an_installed_binary_when_nginx_is_not_on_path() {
        let root = std::env::temp_dir().join(format!("bot-gate-nginx-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let installed = root.join(if cfg!(target_os = "windows") {
            "nginx.exe"
        } else {
            "nginx"
        });
        fs::write(&installed, b"test").unwrap();

        assert_eq!(
            first_existing_binary([root.join("missing"), installed.clone()]),
            Some(installed)
        );

        let _ = fs::remove_dir_all(root);
    }
}
