use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fs,
    hash::{Hash, Hasher},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use url::Url;

const MAX_CONFIG_FILES: usize = 512;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NginxSite {
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) target: String,
    pub(crate) config_file: String,
    pub(crate) supported: bool,
    pub(crate) protected: bool,
}

#[derive(Debug, Clone)]
struct SiteRef {
    id: String,
    host: String,
    target: String,
    original_target: String,
    config_file: PathBuf,
    block_start: usize,
    block_end: usize,
    proxy_line: usize,
    listen_line: Option<usize>,
    front_mode: bool,
    protected: bool,
    supported: bool,
}

#[derive(Debug, Default)]
pub(crate) struct NginxManager {
    config_dir: Option<PathBuf>,
    selected_config: Option<PathBuf>,
    binary: Option<PathBuf>,
    sites: HashMap<String, SiteRef>,
    ignored_hosts: HashSet<String>,
    last_scan_file_count: usize,
}

impl NginxManager {
    pub(crate) fn new(config_dir: Option<String>, binary: Option<String>) -> Self {
        let configured_path = config_dir
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        let (config_dir, selected_config) = match configured_path {
            Some(path) if path.is_file() => (path.parent().map(Path::to_path_buf), Some(path)),
            path => (path, None),
        };
        Self {
            config_dir,
            selected_config,
            binary: binary
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from),
            sites: HashMap::new(),
            ignored_hosts: HashSet::new(),
            last_scan_file_count: 0,
        }
    }

    pub(crate) fn set_ignored_hosts(&mut self, hosts: HashSet<String>) {
        self.ignored_hosts = hosts;
    }

    pub(crate) fn clear_ignored_hosts(&mut self) {
        self.ignored_hosts.clear();
    }

    pub(crate) fn ignored_hosts(&self) -> Vec<String> {
        self.ignored_hosts.iter().cloned().collect()
    }

    pub(crate) fn last_scan_file_count(&self) -> usize {
        self.last_scan_file_count
    }

    pub(crate) fn config_dir(&self) -> Option<&Path> {
        self.config_dir.as_deref()
    }

    pub(crate) fn binary(&self) -> Option<&Path> {
        self.binary.as_deref()
    }

    pub(crate) fn config_file(&self) -> Option<&Path> {
        self.selected_config.as_deref()
    }

    pub(crate) fn configure(&mut self, config_dir: String, binary: Option<String>) -> Result<()> {
        let selected_config = PathBuf::from(config_dir.trim());
        if !selected_config.is_dir() && !selected_config.is_file() {
            bail!(
                "Web 服务目录或配置文件不存在: {}",
                selected_config.display()
            );
        }
        let (config_dir, selected_config) = if selected_config.is_file() {
            let service_dir = selected_config
                .parent()
                .context("配置文件没有有效的 Web 服务目录")?
                .to_path_buf();
            (service_dir, Some(selected_config))
        } else {
            (selected_config, None)
        };
        if self.config_dir.as_ref() != Some(&config_dir) {
            self.ignored_hosts.clear();
        }
        self.config_dir = Some(config_dir);
        self.selected_config = selected_config;
        self.binary = binary
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        Ok(())
    }

    pub(crate) fn set_config_file(&mut self, config_file: String) -> Result<()> {
        let root = self
            .config_dir
            .as_deref()
            .context("请先设置 Web 服务目录")?;
        self.selected_config = Some(validate_config_file(root, Path::new(config_file.trim()))?);
        Ok(())
    }

    pub(crate) fn scan(&mut self) -> Result<Vec<NginxSite>> {
        let config_dir = self
            .config_dir
            .as_deref()
            .context("请先设置 Web 服务目录")?;
        if !config_dir.is_dir() {
            bail!("Web 服务目录不存在: {}", config_dir.display());
        }
        let selected_config = self.selected_config.clone();
        let (prefix_dir, main_config) = if let Some(config_file) = selected_config.as_deref() {
            let prefix = nginx_config_context(config_dir)
                .map(|(prefix, _)| prefix)
                .unwrap_or_else(|| config_dir.to_path_buf());
            (prefix, Some(config_file.to_path_buf()))
        } else if let Some((prefix, main)) = nginx_config_context(config_dir) {
            (prefix, Some(main))
        } else {
            self.sites.clear();
            self.last_scan_file_count = 0;
            return Ok(Vec::new());
        };
        let has_selected_config = selected_config.is_some();
        let mut files = if let Some(config_file) = selected_config {
            vec![config_file]
        } else {
            let mut files = Vec::new();
            collect_config_files(config_dir, &mut files)?;
            if let Some(main_config) = main_config.as_ref() {
                if !files.contains(main_config) {
                    files.push(main_config.clone());
                }
            }
            files
        };
        if files.is_empty() {
            bail!("目录中没有找到 nginx.conf 或 *.conf 文件");
        }
        collect_included_files(&prefix_dir, &mut files)?;
        if !has_selected_config {
            if let Some(main_config) = main_config.as_deref() {
                for file in self.effective_config_files(&prefix_dir, main_config) {
                    if file.is_file() && !files.contains(&file) {
                        files.push(file);
                    }
                }
            }
        }
        files.sort();
        files.dedup();
        if files.is_empty() {
            bail!("目录中没有找到 nginx.conf 或 *.conf 文件");
        }
        self.last_scan_file_count = files.len();

        let mut refs = HashMap::new();
        for file in files {
            let source = fs::read_to_string(&file)
                .with_context(|| format!("无法读取 Nginx 配置: {}", file.display()))?;
            let backup = backup_path(&file);
            let backup_sites = if backup.is_file() {
                fs::read_to_string(&backup)
                    .ok()
                    .map(|value| parse_file(&backup, &value))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            for parsed in parse_file(&file, &source) {
                if self.ignored_hosts.contains(&parsed.host) {
                    continue;
                }
                let backup_target = backup_sites
                    .iter()
                    .find(|candidate| candidate.host == parsed.host)
                    .map(|candidate| candidate.target.clone());
                let original_target = if parsed.front_target.is_some() {
                    String::new()
                } else if parsed.protected {
                    backup_target.unwrap_or_else(|| parsed.target.clone())
                } else {
                    parsed.target.clone()
                };
                refs.insert(
                    parsed.id.clone(),
                    SiteRef {
                        id: parsed.id,
                        host: parsed.host,
                        target: parsed.front_target.clone().unwrap_or_else(|| {
                            if parsed.protected {
                                original_target.clone()
                            } else {
                                parsed.target
                            }
                        }),
                        original_target,
                        config_file: file.clone(),
                        block_start: parsed.block_start,
                        block_end: parsed.block_end,
                        proxy_line: parsed.proxy_line,
                        listen_line: parsed.listen_line,
                        front_mode: parsed.front_mode,
                        protected: parsed.protected,
                        supported: parsed.supported,
                    },
                );
            }
        }
        self.sites = refs;
        Ok(self
            .sites
            .values()
            .map(|site| NginxSite {
                id: site.id.clone(),
                host: site.host.clone(),
                target: site.target.clone(),
                config_file: site.config_file.display().to_string(),
                supported: site.supported,
                protected: site.protected,
            })
            .collect())
    }

    pub(crate) fn set_protected(
        &mut self,
        id: &str,
        protected: bool,
        gateway_address: &str,
    ) -> Result<NginxSite> {
        let site = self
            .sites
            .get(id)
            .cloned()
            .context("Nginx 站点不存在，请先重新扫描")?;
        if !site.supported {
            bail!("该站点不是标准 proxy_pass 反代配置，无法自动接管");
        }
        if site.protected == protected {
            return Ok(site.into_public());
        }
        let source = fs::read_to_string(&site.config_file)
            .with_context(|| format!("无法读取 Nginx 配置: {}", site.config_file.display()))?;
        if site.front_mode {
            let candidate = if protected {
                let mut lines = source.lines().map(str::to_string).collect::<Vec<_>>();
                let listen_line = site
                    .listen_line
                    .context("Nginx server 块缺少 listen 配置")?;
                let original_listen = lines
                    .get(listen_line)
                    .and_then(|line| listen_spec(line))
                    .context("Nginx listen 配置无效")?;
                let internal_port = allocate_front_proxy_port()?;
                let internal_target = format!("http://127.0.0.1:{internal_port}");
                let line = lines
                    .get_mut(listen_line)
                    .context("Nginx 配置行已变化，请重新扫描")?;
                replace_listen_target(line, &format!("127.0.0.1:{internal_port}"))?;
                if !line.contains("bot-gate: front-proxy") {
                    line.push_str(&format!(
                        " # bot-gate: managed front-proxy upstream={internal_target}"
                    ));
                }
                if !backup_path(&site.config_file).exists() {
                    fs::copy(&site.config_file, backup_path(&site.config_file)).with_context(
                        || format!("无法创建 Nginx 配置备份: {}", site.config_file.display()),
                    )?;
                }
                let host = &site.host;
                let front = format!(
                    "\n\n# bot-gate: front-gateway\nserver {{\n    listen {original_listen};\n    server_name {host};\n    location / {{\n        proxy_pass http://{gateway_address};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        proxy_http_version 1.1;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection \"upgrade\";\n    }}\n}}\n"
                );
                let mut candidate = join_lines(&lines, source.ends_with('\n'));
                candidate.push_str(&front);
                candidate
            } else {
                fs::read_to_string(backup_path(&site.config_file)).with_context(|| {
                    format!(
                        "无法读取 Nginx 配置备份: {}",
                        backup_path(&site.config_file).display()
                    )
                })?
            };
            fs::write(&site.config_file, candidate.as_bytes())
                .with_context(|| format!("无法写入 Nginx 配置: {}", site.config_file.display()))?;
            if let Err(error) = self.test_and_reload() {
                let _ = fs::write(&site.config_file, source);
                return Err(error);
            }
            return self
                .scan()?
                .into_iter()
                .find(|value| value.host == site.host)
                .context("Nginx 配置刷新后未找到站点");
        }
        let mut lines = source.lines().map(str::to_string).collect::<Vec<_>>();
        let had_trailing_newline = source.ends_with('\n');
        let replacement = if protected {
            format!("http://{gateway_address}")
        } else if site.original_target.is_empty() {
            bail!("找不到站点原始 upstream，请从备份恢复后重新扫描");
        } else {
            site.original_target.clone()
        };
        let indent = {
            let line = lines
                .get_mut(site.proxy_line)
                .context("Nginx 配置行已变化，请重新扫描")?;
            replace_proxy_target(line, &replacement)?;
            line.chars()
                .take_while(|ch| ch.is_whitespace())
                .collect::<String>()
        };
        if protected {
            let line = lines
                .get_mut(site.proxy_line)
                .context("Nginx 配置行已变化，请重新扫描")?;
            if !line.contains("bot-gate: managed") {
                line.push_str(" # bot-gate: managed");
            }
            if !has_host_header(&lines, site.block_start, site.block_end) {
                lines.insert(
                    site.proxy_line + 1,
                    format!("{indent}proxy_set_header Host $host; # bot-gate: managed"),
                );
            }
            if !backup_path(&site.config_file).exists() {
                fs::copy(&site.config_file, backup_path(&site.config_file)).with_context(|| {
                    format!("无法创建 Nginx 配置备份: {}", site.config_file.display())
                })?;
            }
        } else {
            {
                let line = lines
                    .get_mut(site.proxy_line)
                    .context("Nginx 配置行已变化，请重新扫描")?;
                *line = line.replace(" # bot-gate: managed", "");
            }
            remove_managed_host_headers(&mut lines, site.block_start, site.block_end);
        }
        let candidate = join_lines(&lines, had_trailing_newline);
        fs::write(&site.config_file, candidate.as_bytes())
            .with_context(|| format!("无法写入 Nginx 配置: {}", site.config_file.display()))?;
        if let Err(error) = self.test_and_reload() {
            let _ = fs::write(&site.config_file, source);
            return Err(error);
        }
        let sites = self.scan()?;
        sites
            .into_iter()
            .find(|value| value.id == site.id)
            .context("Nginx 配置刷新后未找到站点")
    }

    pub(crate) fn remove_site(&mut self, id: &str, gateway_address: &str) -> Result<String> {
        let site = self
            .sites
            .get(id)
            .cloned()
            .context("Nginx 站点不存在，请先重新扫描")?;
        if site.protected {
            self.set_protected(id, false, gateway_address)?;
        }
        self.ignored_hosts.insert(site.host.clone());
        self.sites.remove(id);
        Ok(site.host)
    }

    fn test_and_reload(&self) -> Result<()> {
        let config_dir = self
            .config_dir
            .as_deref()
            .context("请先设置 Web 服务目录")?;
        let binary = self.binary_path();
        let context = nginx_config_context(config_dir);
        let test = if let Some((prefix_dir, config)) = context.as_ref() {
            let relative_config = config.strip_prefix(prefix_dir).unwrap_or(config);
            nginx_command(&binary)
                .args(["-p"])
                .arg(prefix_dir)
                .args(["-t", "-c"])
                .arg(relative_config)
                .output()
                .with_context(|| format!("无法执行 Nginx: {}", binary.display()))?
        } else {
            nginx_command(&binary)
                .args(["-t"])
                .output()
                .with_context(|| format!("无法执行 Nginx: {}", binary.display()))?
        };
        if !test.status.success() {
            bail!(
                "Nginx 配置检查失败: {}",
                command_output(&test.stdout, &test.stderr)
            );
        }
        let reload = if let Some((prefix_dir, config)) = context.as_ref() {
            let relative_config = config.strip_prefix(prefix_dir).unwrap_or(config);
            nginx_command(&binary)
                .args(["-p"])
                .arg(prefix_dir)
                .args(["-s", "reload", "-c"])
                .arg(relative_config)
                .output()
                .with_context(|| format!("无法执行 Nginx: {}", binary.display()))?
        } else {
            nginx_command(&binary)
                .args(["-s", "reload"])
                .output()
                .with_context(|| format!("无法执行 Nginx: {}", binary.display()))?
        };
        if !reload.status.success() {
            bail!(
                "Nginx reload 失败: {}",
                command_output(&reload.stdout, &reload.stderr)
            );
        }
        Ok(())
    }

    fn binary_path(&self) -> PathBuf {
        if let Some(binary) = &self.binary {
            if binary.is_file() {
                return binary.clone();
            }
            if binary.is_dir() {
                if let Some(path) = nginx_binary_candidates(binary)
                    .into_iter()
                    .find(|path| path.is_file())
                {
                    return path;
                }
            }
        }
        if let Some(config_dir) = self.config_dir.as_deref() {
            let root = if config_dir.is_file() {
                config_dir.parent().unwrap_or(config_dir)
            } else {
                config_dir
            };
            let mut roots = vec![root.to_path_buf()];
            if let Some(parent) = root.parent() {
                roots.push(parent.to_path_buf());
            }
            if let Some((prefix, _)) = nginx_config_context(config_dir) {
                roots.push(prefix);
            }
            for root in roots {
                if let Some(binary) = nginx_binary_candidates(&root)
                    .into_iter()
                    .find(|path| path.is_file())
                {
                    return binary;
                }
            }
        }
        PathBuf::from(if cfg!(target_os = "windows") {
            "nginx.exe"
        } else {
            "nginx"
        })
    }

    fn effective_config_files(&self, prefix_dir: &Path, config: &Path) -> Vec<PathBuf> {
        let relative_config = config.strip_prefix(prefix_dir).unwrap_or(config);
        let output = match nginx_command(&self.binary_path())
            .args(["-p"])
            .arg(prefix_dir)
            .args(["-T", "-c"])
            .arg(relative_config)
            .output()
        {
            // `nginx -T` writes parsed files before some configuration errors.
            // Those paths are still useful when the selected directory relies on
            // includes outside the directory itself.
            Ok(output) => output,
            _ => return Vec::new(),
        };
        let dump = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        dumped_config_files(&dump)
    }
}

pub(crate) fn pick_directory() -> Result<Option<String>> {
    #[cfg(target_os = "windows")]
    {
        return windows_pick_directory();
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("osascript")
            .args([
                "-e",
                "POSIX path of (choose folder with prompt \"选择 Web 服务目录\")",
            ])
            .output()
            .context("无法打开 macOS 文件夹选择器")?;
        if !output.status.success() {
            return Ok(None);
        }
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let output = Command::new("zenity")
            .args([
                "--file-selection",
                "--directory",
                "--title",
                "选择 Web 服务目录",
            ])
            .output()
            .context("无法打开目录选择器，请手动输入 Web 服务目录")?;
        if !output.status.success() {
            return Ok(None);
        }
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ));
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
    Ok(None)
}

pub(crate) fn validate_config_file(root: &Path, config_file: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(root)
        .with_context(|| format!("Web 服务目录不存在: {}", root.display()))?;
    let config_file = fs::canonicalize(config_file)
        .with_context(|| format!("Nginx 配置文件不存在: {}", config_file.display()))?;
    if !config_file.is_file() {
        bail!("Nginx 配置文件不存在: {}", config_file.display());
    }
    if !config_file.starts_with(&root) {
        bail!("只能导入 Web 服务目录内的配置文件");
    }
    Ok(config_file)
}

pub(crate) fn pick_config_file() -> Result<Option<String>> {
    #[cfg(target_os = "windows")]
    {
        return windows_pick_config_file();
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("osascript")
            .args([
                "-e",
                "POSIX path of (choose file with prompt \"选择 Nginx 配置文件\")",
            ])
            .output()
            .context("无法打开 macOS 配置文件选择器")?;
        if !output.status.success() {
            return Ok(None);
        }
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let output = Command::new("zenity")
            .args([
                "--file-selection",
                "--title",
                "选择 Nginx 配置文件",
                "--file-filter",
                "Nginx 配置 (*.conf) | *.conf",
            ])
            .output()
            .context("无法打开配置文件选择器，请手动输入 Nginx 配置文件")?;
        if !output.status.success() {
            return Ok(None);
        }
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ));
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
    Ok(None)
}

#[cfg(target_os = "windows")]
fn windows_pick_directory() -> Result<Option<String>> {
    std::thread::spawn(windows_pick_directory_sta)
        .join()
        .map_err(|_| anyhow::anyhow!("Windows 文件夹选择器线程异常退出"))?
}

#[cfg(target_os = "windows")]
fn windows_pick_directory_sta() -> Result<Option<String>> {
    use std::{ffi::c_void, ptr};

    #[repr(C)]
    struct ItemIdList {
        _private: [u8; 0],
    }

    type BrowseCallback = Option<unsafe extern "system" fn(isize, u32, isize, isize) -> i32>;

    #[repr(C)]
    struct BrowseInfoW {
        hwnd_owner: isize,
        pidl_root: *mut ItemIdList,
        display_name: *mut u16,
        title: *const u16,
        flags: u32,
        callback: BrowseCallback,
        callback_data: isize,
        image: i32,
    }

    #[link(name = "shell32")]
    extern "system" {
        fn SHBrowseForFolderW(info: *const BrowseInfoW) -> *mut ItemIdList;
        fn SHGetPathFromIDListW(item: *const ItemIdList, path: *mut u16) -> i32;
    }

    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(reserved: *const c_void, flags: u32) -> i32;
        fn CoTaskMemFree(value: *const c_void);
        fn CoUninitialize();
    }

    const COINIT_APARTMENTTHREADED: u32 = 0x2;
    const BIF_RETURNONLYFSDIRS: u32 = 0x0001;
    const BIF_NEWDIALOGSTYLE: u32 = 0x0040;
    let com_result = unsafe { CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED) };
    if com_result < 0 {
        bail!("无法初始化 Windows 文件夹选择器 ({com_result:#x})");
    }
    let title: Vec<u16> = "选择 Web 服务目录"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut display_name = vec![0u16; 260];
    let info = BrowseInfoW {
        hwnd_owner: 0,
        pidl_root: ptr::null_mut(),
        display_name: display_name.as_mut_ptr(),
        title: title.as_ptr(),
        flags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
        callback: None,
        callback_data: 0,
        image: 0,
    };
    let item = unsafe { SHBrowseForFolderW(&info) };
    if item.is_null() {
        unsafe { CoUninitialize() };
        return Ok(None);
    }
    let mut path = vec![0u16; 32_768];
    let selected = unsafe { SHGetPathFromIDListW(item, path.as_mut_ptr()) != 0 };
    unsafe { CoTaskMemFree(item.cast()) };
    unsafe { CoUninitialize() };
    if !selected {
        return Ok(None);
    }
    let length = path
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(path.len());
    let path = String::from_utf16(&path[..length]).context("Windows 路径编码无效")?;
    Ok((!path.is_empty()).then_some(path))
}

#[cfg(target_os = "windows")]
fn windows_pick_config_file() -> Result<Option<String>> {
    std::thread::spawn(windows_pick_config_file_sta)
        .join()
        .map_err(|_| anyhow::anyhow!("Windows 配置文件选择器线程异常退出"))?
}

#[cfg(target_os = "windows")]
fn windows_pick_config_file_sta() -> Result<Option<String>> {
    use std::{ffi::c_void, ptr};

    #[repr(C)]
    struct OpenFileNameW {
        l_struct_size: u32,
        hwnd_owner: isize,
        h_instance: isize,
        filter: *const u16,
        custom_filter: *mut u16,
        max_custom_filter: u32,
        filter_index: u32,
        file: *mut u16,
        max_file: u32,
        file_title: *mut u16,
        max_file_title: u32,
        initial_dir: *const u16,
        title: *const u16,
        flags: u32,
        file_offset: u16,
        file_extension: u16,
        def_ext: *const u16,
        data: isize,
        hook: *const c_void,
        template_name: *const u16,
        reserved: *mut c_void,
        reserved2: u32,
        flags_ex: u32,
    }

    #[link(name = "comdlg32")]
    extern "system" {
        fn GetOpenFileNameW(file_name: *mut OpenFileNameW) -> i32;
    }

    const OFN_FILEMUSTEXIST: u32 = 0x0000_1000;
    const OFN_PATHMUSTEXIST: u32 = 0x0000_0800;
    let filter: Vec<u16> = "Nginx 配置文件 (*.conf)\0*.conf\0所有文件\0*.*\0\0"
        .encode_utf16()
        .collect();
    let title: Vec<u16> = "选择 Nginx 配置文件"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut file = vec![0u16; 32_768];
    let mut info = OpenFileNameW {
        l_struct_size: std::mem::size_of::<OpenFileNameW>() as u32,
        hwnd_owner: 0,
        h_instance: 0,
        filter: filter.as_ptr(),
        custom_filter: ptr::null_mut(),
        max_custom_filter: 0,
        filter_index: 1,
        file: file.as_mut_ptr(),
        max_file: file.len() as u32,
        file_title: ptr::null_mut(),
        max_file_title: 0,
        initial_dir: ptr::null(),
        title: title.as_ptr(),
        flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST,
        file_offset: 0,
        file_extension: 0,
        def_ext: ptr::null(),
        data: 0,
        hook: ptr::null(),
        template_name: ptr::null(),
        reserved: ptr::null_mut(),
        reserved2: 0,
        flags_ex: 0,
    };
    if unsafe { GetOpenFileNameW(&mut info) } == 0 {
        return Ok(None);
    }
    let length = file
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(file.len());
    Ok(Some(
        String::from_utf16(&file[..length]).context("Windows 路径编码无效")?,
    ))
}

impl SiteRef {
    fn into_public(self) -> NginxSite {
        NginxSite {
            id: self.id,
            host: self.host,
            target: self.target,
            config_file: self.config_file.display().to_string(),
            supported: self.supported,
            protected: self.protected,
        }
    }
}

#[derive(Debug)]
struct ParsedSite {
    id: String,
    host: String,
    target: String,
    block_start: usize,
    block_end: usize,
    proxy_line: usize,
    listen_line: Option<usize>,
    front_target: Option<String>,
    front_mode: bool,
    protected: bool,
    supported: bool,
}

fn collect_config_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if files.len() >= MAX_CONFIG_FILES {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("无法读取目录: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_config_files(&path, files)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("nginx.conf")
            || path.extension().and_then(|ext| ext.to_str()) == Some("conf")
        {
            files.push(path);
        }
        if files.len() >= MAX_CONFIG_FILES {
            break;
        }
    }
    Ok(())
}

fn collect_included_files(prefix: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut index = 0;
    while index < files.len() && files.len() < MAX_CONFIG_FILES {
        let file = files[index].clone();
        index += 1;
        let source = match fs::read_to_string(&file) {
            Ok(source) => source,
            Err(_) => continue,
        };
        for pattern in include_patterns(&source) {
            let path = Path::new(&pattern);
            let bases = if path.is_absolute() {
                vec![PathBuf::new()]
            } else {
                vec![
                    prefix.to_path_buf(),
                    file.parent().unwrap_or(prefix).to_path_buf(),
                ]
            };
            for base in bases {
                let candidate = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    base.join(path)
                };
                for included in expand_path_pattern(&candidate) {
                    if included.is_file() && !files.contains(&included) {
                        files.push(included);
                        if files.len() >= MAX_CONFIG_FILES {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn nginx_binary_candidates(root: &Path) -> Vec<PathBuf> {
    let executable = if cfg!(target_os = "windows") {
        "nginx.exe"
    } else {
        "nginx"
    };
    vec![
        root.join(executable),
        root.join("sbin").join(executable),
        root.join("bin").join(executable),
    ]
}

fn dumped_config_files(output: &str) -> Vec<PathBuf> {
    output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("# configuration file "))
        .filter_map(|path| path.strip_suffix(':'))
        .map(PathBuf::from)
        .collect()
}

fn include_patterns(source: &str) -> Vec<String> {
    let source = source
        .lines()
        .map(without_comment)
        .collect::<Vec<_>>()
        .join("\n");
    source
        .split(';')
        .filter_map(|line| {
            let line = without_comment(line).trim();
            let marker = line.find("include")?;
            if marker > 0
                && !line[..marker]
                    .chars()
                    .last()
                    .is_some_and(|ch| ch.is_whitespace() || matches!(ch, '{' | '}'))
            {
                return None;
            }
            let value = line[marker + "include".len()..].trim();
            (!value.is_empty()).then(|| value.trim_matches('"').trim_matches('\'').to_string())
        })
        .collect()
}

fn expand_path_pattern(path: &Path) -> Vec<PathBuf> {
    let parts = path
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect::<Vec<_>>();
    expand_path_parts(PathBuf::new(), &parts)
}

fn expand_path_parts(current: PathBuf, parts: &[std::ffi::OsString]) -> Vec<PathBuf> {
    let Some((part, rest)) = parts.split_first() else {
        return vec![current];
    };
    let part = part.to_string_lossy();
    if part.contains(['*', '?']) {
        let mut matches = Vec::new();
        if let Ok(entries) = fs::read_dir(&current) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if wildcard_match(&part, &name.to_string_lossy()) {
                    matches.extend(expand_path_parts(entry.path(), rest));
                }
            }
        }
        matches
    } else {
        let mut next = current;
        next.push(part.as_ref());
        expand_path_parts(next, rest)
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    fn matches(pattern: &[u8], value: &[u8]) -> bool {
        match pattern.split_first() {
            None => value.is_empty(),
            Some((b'*', rest)) => {
                matches(rest, value) || value.first().is_some_and(|_| matches(pattern, &value[1..]))
            }
            Some((b'?', rest)) => value.first().is_some_and(|_| matches(rest, &value[1..])),
            Some((expected, rest)) => value
                .first()
                .is_some_and(|actual| expected == actual && matches(rest, &value[1..])),
        }
    }
    matches(pattern.as_bytes(), value.as_bytes())
}

fn parse_file(path: &Path, source: &str) -> Vec<ParsedSite> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut sites = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let clean = without_comment(lines[index]);
        if is_server_start(clean) {
            let start = index;
            let mut depth = brace_delta(clean);
            index += 1;
            if depth == 0
                && lines
                    .get(index)
                    .is_some_and(|line| without_comment(line).trim() == "{")
            {
                depth = 1;
                index += 1;
            }
            while index < lines.len() && depth > 0 {
                depth += brace_delta(without_comment(lines[index]));
                index += 1;
            }
            let end = index.min(lines.len());
            let block = &lines[start..end];
            if block
                .iter()
                .any(|line| line.contains("bot-gate: front-gateway"))
            {
                index = end;
                continue;
            }
            let hosts = server_names(block);
            let listen_line = block.iter().enumerate().find_map(|(offset, line)| {
                directive_value(without_comment(line), "listen").map(|_| start + offset)
            });
            let front_target = block.iter().find_map(|line| {
                line.split_once("bot-gate: managed front-proxy upstream=")
                    .and_then(|(_, value)| value.split_whitespace().next())
                    .map(str::to_string)
            });
            let proxies = block
                .iter()
                .enumerate()
                .filter_map(|(offset, line)| {
                    parse_proxy_pass(without_comment(line)).map(|target| (offset, target))
                })
                .collect::<Vec<_>>();
            if let Some((offset, target)) = proxies.first().cloned() {
                for host in hosts.iter().cloned() {
                    let managed = block.iter().any(|line| line.contains("bot-gate: managed"));
                    let standard = proxies.len() == 1
                        && !target.contains('$')
                        && Url::parse(&target).is_ok_and(|url| {
                            url.scheme() == "http" && (url.path().is_empty() || url.path() == "/")
                        });
                    let front_mode = !standard || front_target.is_some();
                    let supported = host != "_" && (standard || listen_line.is_some());
                    sites.push(ParsedSite {
                        id: site_id(path, &host, start),
                        host,
                        target: target.clone(),
                        block_start: start,
                        block_end: end,
                        proxy_line: start + offset,
                        listen_line,
                        front_target: front_target.clone(),
                        front_mode,
                        protected: managed,
                        supported,
                    });
                }
            } else {
                let root = block.iter().find_map(|line| {
                    without_comment(line)
                        .trim()
                        .strip_prefix("root ")
                        .map(|value| value.trim().trim_end_matches(';').to_string())
                });
                if let Some(root) = root {
                    for host in hosts.iter().cloned() {
                        let host_supported = host != "_" && listen_line.is_some();
                        sites.push(ParsedSite {
                            id: site_id(path, &host, start),
                            host,
                            target: format!("root {root}"),
                            block_start: start,
                            block_end: end,
                            proxy_line: start,
                            listen_line,
                            front_target: front_target.clone(),
                            front_mode: true,
                            protected: false,
                            supported: host_supported,
                        });
                    }
                }
            }
        } else {
            index += 1;
        }
    }
    sites
}

fn server_names(block: &[&str]) -> Vec<String> {
    block
        .iter()
        .filter_map(|line| directive_value(without_comment(line), "server_name"))
        .flat_map(|value| value.split_whitespace())
        .filter(|host| !host.starts_with('$') && !host.contains('*'))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn nginx_command(binary: &Path) -> Command {
    #[cfg(target_os = "windows")]
    let mut command = Command::new(binary);
    #[cfg(not(target_os = "windows"))]
    let command = Command::new(binary);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command
}

fn parse_proxy_pass(line: &str) -> Option<String> {
    let target = directive_value(line, "proxy_pass")?
        .split_whitespace()
        .next()?;
    Some(target.to_string())
}

fn listen_spec(line: &str) -> Option<String> {
    directive_value(without_comment(line), "listen")?
        .split_whitespace()
        .next()
        .map(str::to_string)
}

fn replace_listen_target(line: &mut String, replacement: &str) -> Result<()> {
    let keyword = line.find("listen").context("Nginx listen 行无效")?;
    let value_start = keyword + "listen".len();
    let whitespace = line[value_start..]
        .find(|ch: char| !ch.is_whitespace())
        .map(|offset| value_start + offset)
        .context("Nginx listen 缺少端口")?;
    let value_end = line[whitespace..]
        .find(char::is_whitespace)
        .map(|offset| whitespace + offset)
        .unwrap_or(line.len());
    line.replace_range(whitespace..value_end, replacement);
    Ok(())
}

fn allocate_front_proxy_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("无法分配 Nginx 内部监听端口")?;
    Ok(listener.local_addr()?.port())
}

fn directive_value<'a>(line: &'a str, directive: &str) -> Option<&'a str> {
    let offset = line.find(directive)?;
    if offset > 0
        && !line[..offset]
            .chars()
            .last()
            .is_some_and(|ch| ch.is_whitespace() || matches!(ch, '{' | '}' | ';'))
    {
        return None;
    }
    let value = &line[offset + directive.len()..];
    if !value.starts_with(char::is_whitespace) {
        return None;
    }
    let value = value.trim_start();
    Some(value.split(';').next().unwrap_or(value).trim())
}

fn is_server_start(line: &str) -> bool {
    let line = line.trim();
    if line == "server" {
        return true;
    }
    line.starts_with("server")
        && line[6..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_whitespace() || ch == '{')
        && line.contains('{')
}

fn without_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or(line)
}

fn brace_delta(line: &str) -> i32 {
    line.chars().fold(0, |depth, ch| match ch {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

fn site_id(path: &Path, host: &str, block_start: usize) -> String {
    let mut hasher = DefaultHasher::new();
    path.to_string_lossy().hash(&mut hasher);
    host.hash(&mut hasher);
    block_start.hash(&mut hasher);
    format!("nginx-{:x}", hasher.finish())
}

fn backup_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.botgate.bak", path.display()))
}

fn nginx_config_context(config_dir: &Path) -> Option<(PathBuf, PathBuf)> {
    if config_dir.is_file() {
        let parent = config_dir.parent()?;
        let prefix = if parent.file_name().and_then(|name| name.to_str()) == Some("conf") {
            parent.parent().unwrap_or(parent)
        } else {
            parent
        };
        return Some((prefix.to_path_buf(), config_dir.to_path_buf()));
    }
    let mut roots = vec![config_dir.to_path_buf()];
    let mut current = config_dir;
    for _ in 0..3 {
        let Some(parent) = current.parent() else {
            break;
        };
        roots.push(parent.to_path_buf());
        current = parent;
    }
    for root in roots {
        let candidates = [
            root.join("nginx.conf"),
            root.join("conf/nginx.conf"),
            root.join("etc/nginx/nginx.conf"),
        ];
        if let Some(config) = candidates.into_iter().find(|path| path.is_file()) {
            let parent = config.parent().unwrap_or(&root);
            let prefix = if parent.file_name().and_then(|name| name.to_str()) == Some("conf") {
                parent.parent().unwrap_or(parent)
            } else {
                parent
            };
            return Some((prefix.to_path_buf(), config));
        }
    }
    None
}

fn replace_proxy_target(line: &mut String, replacement: &str) -> Result<()> {
    let keyword = line.find("proxy_pass").context("Nginx proxy_pass 行无效")?;
    let value_start = keyword + "proxy_pass".len();
    let whitespace = line[value_start..]
        .find(|ch: char| !ch.is_whitespace())
        .map(|offset| value_start + offset)
        .context("Nginx proxy_pass 缺少 upstream")?;
    let value_end = line[whitespace..]
        .find(|ch: char| ch.is_whitespace() || ch == ';')
        .map(|offset| whitespace + offset)
        .unwrap_or(line.len());
    line.replace_range(whitespace..value_end, replacement);
    Ok(())
}

fn has_host_header(lines: &[String], block_start: usize, block_end: usize) -> bool {
    lines
        .get(block_start..block_end.min(lines.len()))
        .unwrap_or_default()
        .iter()
        .any(|line| {
            let clean = without_comment(line).trim();
            clean.starts_with("proxy_set_header Host ")
        })
}

fn remove_managed_host_headers(lines: &mut Vec<String>, block_start: usize, block_end: usize) {
    let end = block_end.min(lines.len());
    let mut index = block_start.min(end);
    while index < end && index < lines.len() {
        if lines[index].contains("proxy_set_header Host $host")
            && lines[index].contains("bot-gate: managed")
        {
            lines.remove(index);
        } else {
            index += 1;
        }
    }
}

fn join_lines(lines: &[String], trailing_newline: bool) -> String {
    let mut result = lines.join("\n");
    if trailing_newline {
        result.push('\n');
    }
    result
}

fn command_output(stdout: &[u8], stderr: &[u8]) -> String {
    let output = if stderr.is_empty() { stdout } else { stderr };
    String::from_utf8_lossy(output).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_server_proxy_block() {
        let source = "server {\n    server_name cool.com www.cool.com;\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n    }\n}\n";
        let sites = parse_file(Path::new("nginx.conf"), source);
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].target, "http://127.0.0.1:3000");
        assert!(sites[0].supported);
        assert!(!sites[0].protected);
    }

    #[test]
    fn keeps_catch_all_server_as_unsupported_instead_of_hiding_it() {
        let source = "server {\n    listen 18081;\n    server_name _;\n    location /api/ {\n        proxy_pass http://127.0.0.1:8001/;\n    }\n    location /socket {\n        proxy_pass http://127.0.0.1:8001/socket;\n    }\n}\n";
        let sites = parse_file(Path::new("nginx-test.conf"), source);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].host, "_");
        assert!(!sites[0].supported);
    }

    #[test]
    fn supports_a_multi_location_server_with_front_gateway_mode() {
        let source = "server {\n    listen 18081;\n    server_name 172.22.31.39;\n    root d:/ps_dev/dist;\n    location /api/ { proxy_pass http://127.0.0.1:8001/; }\n    location /socket { proxy_pass http://127.0.0.1:8001/socket; }\n}\n";
        let sites = parse_file(Path::new("nginx-test.conf"), source);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].host, "172.22.31.39");
        assert!(sites[0].supported);
        assert!(sites[0].front_mode);
        assert_eq!(sites[0].listen_line, Some(1));
    }

    #[test]
    fn ignores_static_and_variable_upstreams() {
        let source = "server {\n    server_name static.test;\n    root html;\n}\nserver {\n    server_name variable.test;\n    proxy_pass http://$backend;\n}\n";
        let sites = parse_file(Path::new("nginx.conf"), source);
        assert_eq!(sites.len(), 2);
        assert!(sites.iter().all(|site| !site.supported));
        assert!(sites.iter().any(|site| site.host == "variable.test"));
        assert!(sites.iter().any(|site| site.host == "static.test"));
    }

    #[test]
    fn parses_include_patterns_and_wildcards() {
        assert_eq!(
            include_patterns("include conf.d/*.conf; # sites\ninclude\textra.conf;"),
            vec!["conf.d/*.conf", "extra.conf"]
        );
        assert!(wildcard_match("*.conf", "site.conf"));
        assert!(wildcard_match("conf?.d", "conf1.d"));
        assert!(!wildcard_match("*.conf", "site.conf.bak"));
    }

    #[test]
    fn parses_nginx_effective_config_markers_and_inline_directives() {
        let files = dumped_config_files(
            "nginx: configuration file /etc/nginx/nginx.conf test is successful\n\
             # configuration file /etc/nginx/nginx.conf:\n\
             # configuration file /etc/nginx/sites-enabled/cool.conf:\n",
        );
        assert_eq!(
            files,
            vec![
                PathBuf::from("/etc/nginx/nginx.conf"),
                PathBuf::from("/etc/nginx/sites-enabled/cool.conf"),
            ]
        );

        let sites = parse_file(
            Path::new("cool.conf"),
            "server { server_name cool.test; location / { proxy_pass http://127.0.0.1:3000; } }",
        );
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].host, "cool.test");
        assert_eq!(sites[0].target, "http://127.0.0.1:3000");
    }

    #[test]
    fn removing_one_nginx_site_does_not_remove_other_sites() {
        let mut manager = NginxManager::default();
        manager.sites.insert(
            "one".to_string(),
            SiteRef {
                id: "one".to_string(),
                host: "one.test".to_string(),
                target: "http://127.0.0.1:3001".to_string(),
                original_target: "http://127.0.0.1:3001".to_string(),
                config_file: PathBuf::from("nginx.conf"),
                block_start: 0,
                block_end: 1,
                proxy_line: 0,
                listen_line: None,
                front_mode: false,
                protected: false,
                supported: true,
            },
        );
        manager.sites.insert(
            "two".to_string(),
            SiteRef {
                id: "two".to_string(),
                host: "two.test".to_string(),
                target: "http://127.0.0.1:3002".to_string(),
                original_target: "http://127.0.0.1:3002".to_string(),
                config_file: PathBuf::from("nginx.conf"),
                block_start: 2,
                block_end: 3,
                proxy_line: 2,
                listen_line: None,
                front_mode: false,
                protected: false,
                supported: true,
            },
        );

        assert_eq!(
            manager.remove_site("one", "127.0.0.1:9090").unwrap(),
            "one.test"
        );
        assert!(!manager.sites.contains_key("one"));
        assert!(manager.sites.contains_key("two"));
    }

    #[test]
    fn scans_servers_from_included_files_outside_selected_conf_directory() {
        let root = std::env::temp_dir().join(format!(
            "bot-gate-nginx-test-{}-{}",
            std::process::id(),
            unix_test_suffix()
        ));
        let conf = root.join("conf");
        let sites = root.join("sites-enabled");
        fs::create_dir_all(&sites).unwrap();
        fs::create_dir_all(&conf).unwrap();
        fs::write(
            conf.join("nginx.conf"),
            "http { include sites-enabled/*.conf; }\n",
        )
        .unwrap();
        fs::write(
            sites.join("cool.conf"),
            "server {\n server_name cool.test;\n location / {\n  proxy_pass http://127.0.0.1:3000;\n }\n}\n",
        )
        .unwrap();

        let mut manager = NginxManager::default();
        manager.configure(conf.display().to_string(), None).unwrap();
        let discovered = manager.scan().unwrap();
        assert_eq!(
            discovered
                .iter()
                .map(|site| site.host.as_str())
                .collect::<Vec<_>>(),
            ["cool.test"]
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scans_from_nginx_install_directory_with_multiline_server_block() {
        let root = std::env::temp_dir().join(format!(
            "bot-gate-nginx-install-test-{}-{}",
            std::process::id(),
            unix_test_suffix()
        ));
        let conf = root.join("conf");
        let sites = conf.join("conf.d");
        fs::create_dir_all(&sites).unwrap();
        fs::write(
            conf.join("nginx.conf"),
            "http {\n    include conf.d/*.conf;\n}\n",
        )
        .unwrap();
        fs::write(
            sites.join("cool.conf"),
            "server\n{\n    server_name cool.test;\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n    }\n}\n",
        )
        .unwrap();

        let context = nginx_config_context(&root).unwrap();
        assert_eq!(context.0, root);
        assert_eq!(context.1, conf.join("nginx.conf"));

        let mut manager = NginxManager::default();
        manager.configure(root.display().to_string(), None).unwrap();
        let discovered = manager.scan().unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].host, "cool.test");
        assert_eq!(discovered[0].target, "http://127.0.0.1:3000");
        assert!(discovered[0].supported);
        assert!(manager.last_scan_file_count() >= 2);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scans_a_selected_config_file_and_its_includes_only() {
        let root = std::env::temp_dir().join(format!(
            "bot-gate-nginx-file-test-{}-{}",
            std::process::id(),
            unix_test_suffix()
        ));
        let sites = root.join("sites");
        fs::create_dir_all(&sites).unwrap();
        let config = root.join("custom-nginx.conf");
        fs::write(&config, "http { include sites/*.conf; }\n").unwrap();
        fs::write(
            sites.join("cool.conf"),
            "server { server_name cool.test; proxy_pass http://127.0.0.1:3000; }\n",
        )
        .unwrap();
        fs::write(
            root.join("unrelated.conf"),
            "server { server_name unrelated.test; proxy_pass http://127.0.0.1:3001; }\n",
        )
        .unwrap();

        let mut manager = NginxManager::default();
        manager
            .configure(config.display().to_string(), None)
            .unwrap();
        let discovered = manager.scan().unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].host, "cool.test");
        assert_eq!(manager.last_scan_file_count(), 2);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scans_a_web_service_directory_with_a_standalone_server_config() {
        let root = std::env::temp_dir().join(format!(
            "bot-gate-web-service-test-{}-{}",
            std::process::id(),
            unix_test_suffix()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("cool.conf"),
            "server {\n    server_name cool.test;\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n    }\n}\n",
        )
        .unwrap();

        let mut manager = NginxManager::default();
        manager.configure(root.display().to_string(), None).unwrap();
        assert!(manager.scan().unwrap().is_empty());
        manager
            .set_config_file(root.join("cool.conf").display().to_string())
            .unwrap();
        let discovered = manager.scan().unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].host, "cool.test");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_a_config_file_outside_the_web_service_directory() {
        let root = std::env::temp_dir().join(format!(
            "bot-gate-web-service-boundary-test-{}-{}",
            std::process::id(),
            unix_test_suffix()
        ));
        let outside = root.with_extension("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let config = outside.join("outside.conf");
        fs::write(&config, "server { server_name outside.test; }\n").unwrap();

        let error = validate_config_file(&root, &config)
            .unwrap_err()
            .to_string();
        assert!(error.contains("只能导入 Web 服务目录内的配置文件"));

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    fn unix_test_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
