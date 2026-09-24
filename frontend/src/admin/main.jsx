import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Alert,
  App,
  Button,
  Card,
  Col,
  ConfigProvider,
  Form,
  Input,
  InputNumber,
  Layout,
  Modal,
  Popconfirm,
  Progress,
  Row,
  Select,
  Space,
  Switch,
  Statistic,
  Table,
  Tag,
  Tabs,
  Tooltip,
  Typography,
} from "antd";
import {
  ApiOutlined,
  CheckCircleFilled,
  CloudOutlined,
  CloudDownloadOutlined,
  DeleteOutlined,
  GlobalOutlined,
  KeyOutlined,
  LockOutlined,
  PauseCircleOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  SyncOutlined,
  UnlockOutlined,
} from "@ant-design/icons";
import "antd/dist/reset.css";
import "./style.css";
import LogsPanel from "./logs.jsx";

const { Header, Content } = Layout;
const { Text, Title } = Typography;

const metricCards = [
  {
    key: "today_requests",
    label: "今日请求",
    icon: <ApiOutlined />,
    tone: "blue",
    mode: "requests",
  },
  {
    key: "today_verified",
    label: "已验证请求",
    icon: <CheckCircleFilled />,
    tone: "green",
    mode: "requests",
  },
  {
    key: "today_blocked",
    label: "已拦截请求",
    icon: <LockOutlined />,
    tone: "orange",
    mode: "requests",
  },
  {
    key: "today_challenge_failures",
    label: "验证失败",
    icon: <SafetyCertificateOutlined />,
    tone: "purple",
    mode: "interceptions",
  },
  {
    key: "active_bans",
    label: "活跃封禁",
    icon: <DeleteOutlined />,
    tone: "red",
    mode: "bans",
  },
  {
    key: "active_challenges",
    label: "进行中验证",
    icon: <GlobalOutlined />,
    tone: "cyan",
    mode: "challenges",
  },
];

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "content-type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok)
    throw new Error(body.message || `请求失败 (${response.status})`);
  return body;
}

function AdminConsole() {
  const { message } = App.useApp();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [dashboard, setDashboard] = useState({});
  const [sites, setSites] = useState([]);
  const [bans, setBans] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [systemInfo, setSystemInfo] = useState({
    version: "0.1.0",
    update_enabled: false,
    gateway: { running: false },
  });
  const [gatewayStatus, setGatewayStatus] = useState({ running: false });
  const [logModal, setLogModal] = useState(null);
  const [addModal, setAddModal] = useState(null);
  const [nginxPathModal, setNginxPathModal] = useState(false);
  const [licenseModal, setLicenseModal] = useState(false);
  const [updateModal, setUpdateModal] = useState(false);
  const [updateInfo, setUpdateInfo] = useState(null);
  const [updateError, setUpdateError] = useState("");
  const [updateLoading, setUpdateLoading] = useState(false);
  const [updateProgress, setUpdateProgress] = useState({
    status: "idle",
    percent: 0,
    message: "",
  });
  const [autoUpdateChecked, setAutoUpdateChecked] = useState(false);
  const [banForm] = Form.useForm();
  const [whitelistForm] = Form.useForm();
  const [siteForm] = Form.useForm();
  const [licenseForm] = Form.useForm();
  const [nginxForm] = Form.useForm();
  const [nginxPathForm] = Form.useForm();
  const siteMode = Form.useWatch("mode", siteForm) || "nginx";
  const licenseStatus = systemInfo.license?.status || "disabled";
  const licenseLabel =
    licenseStatus === "active"
      ? "有效"
      : licenseStatus === "disabled"
        ? "未启用"
        : "未激活";

  useEffect(() => {
    if (systemInfo.nginx) {
      nginxForm.setFieldsValue(systemInfo.nginx);
      nginxPathForm.setFieldsValue({ binary: systemInfo.nginx.binary });
    }
  }, [nginxForm, nginxPathForm, systemInfo.nginx]);

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const [stats, siteData, banData, whitelistData, systemData] =
        await Promise.all([
          api("/api/dashboard"),
          api("/api/sites"),
          api("/api/bans"),
          api("/api/whitelist"),
          api("/api/system"),
        ]);
      setDashboard(stats);
      setSites(siteData.sites || []);
      setBans(banData.bans || []);
      setWhitelist(whitelistData.whitelist || []);
      setSystemInfo(systemData);
      setGatewayStatus(systemData.gateway || { running: false });
      setLastUpdated(new Date());
    } catch (cause) {
      setError(cause.message);
    } finally {
      setLoading(false);
    }
  }

  async function checkForUpdates(silent = false) {
    setUpdateError("");
    if (!systemInfo.update_enabled || !systemInfo.release_url) {
      setUpdateInfo({
        update_available: false,
        current_version: systemInfo.version,
        latest_version: systemInfo.version,
      });
      setUpdateError("尚未配置 GitHub Release 更新地址");
      if (!silent) setUpdateModal(true);
      if (!silent) message.info("尚未配置 GitHub Release 更新地址");
      return;
    }
    setUpdateLoading(true);
    try {
      const result = await api("/api/update/check");
      const update = result.update;
      setUpdateInfo(update);
      if (update.update_available) {
        setUpdateModal(true);
      } else {
        if (!silent) setUpdateModal(true);
        if (!silent)
          message.success(`当前已是最新版本 v${update.current_version}`);
      }
    } catch (cause) {
      setUpdateError(cause.message);
      if (!silent) setUpdateModal(true);
      if (!silent) message.error(cause.message);
    } finally {
      setUpdateLoading(false);
    }
  }

  async function applyUpdate() {
    if (
      ["checking", "downloading", "restarting"].includes(updateProgress.status)
    )
      return;
    setUpdateLoading(true);
    try {
      await api("/api/update/apply", {
        method: "POST",
        headers: { "x-bot-gate-action": "update" },
      });
      message.success("更新已开始下载");
    } catch (cause) {
      message.error(cause.message);
    } finally {
      setUpdateLoading(false);
    }
  }

  async function activateLicense(values) {
    try {
      const result = await api("/api/license/activate", {
        method: "POST",
        body: JSON.stringify({ key: values.key }),
      });
      setSystemInfo((current) => ({ ...current, license: result.license }));
      licenseForm.resetFields();
      setLicenseModal(false);
      message.success("许可证激活成功");
    } catch (cause) {
      message.error(cause.message);
    }
  }

  async function toggleGateway() {
    const action = gatewayStatus.running ? "stop" : "start";
    try {
      const result = await api(`/api/gateway/${action}`, { method: "POST" });
      setGatewayStatus(result.gateway);
      message.success(action === "start" ? "网关已启动" : "网关已停止");
    } catch (cause) {
      message.error(cause.message);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    if (
      !autoUpdateChecked &&
      systemInfo.version !== "0.1.0" &&
      systemInfo.update_enabled
    ) {
      setAutoUpdateChecked(true);
      checkForUpdates(true);
    }
  }, [autoUpdateChecked, systemInfo.version, systemInfo.update_enabled]);

  useEffect(() => {
    if (!updateModal) return undefined;
    let active = true;
    const loadProgress = async () => {
      try {
        const result = await api("/api/update/progress");
        if (active && result.progress) setUpdateProgress(result.progress);
      } catch (_) {
        // The management endpoint can briefly disappear while the app restarts.
      }
    };
    loadProgress();
    const timer = window.setInterval(loadProgress, 700);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [updateModal]);

  function openAddModal(type) {
    if (type === "ban") banForm.resetFields();
    if (type === "whitelist") whitelistForm.resetFields();
    if (type === "site") siteForm.resetFields();
    setAddModal(type);
  }

  function openMetric(card) {
    const filters = {};
    if (card.key === "today_verified") filters.verified = true;
    if (card.key === "today_blocked") filters.blocked = true;
    if (card.key === "today_challenge_failures")
      filters.event_type = "challenge_failure";
    setLogModal({ mode: card.mode, filters });
  }

  async function reloadConfig() {
    try {
      await api("/api/reload", { method: "POST" });
      message.success("配置已重新加载，SQLite 中的站点和白名单已保留");
      await refresh();
    } catch (cause) {
      message.error(cause.message);
    }
  }

  async function saveBan(values) {
    try {
      await api("/api/bans", { method: "POST", body: JSON.stringify(values) });
      banForm.resetFields(["ip", "reason"]);
      message.success("封禁已保存");
      await refresh();
      return true;
    } catch (cause) {
      message.error(cause.message);
      return false;
    }
  }

  async function saveWhitelist(values) {
    try {
      await api("/api/whitelist", {
        method: "POST",
        body: JSON.stringify({
          ...values,
          skip_challenge: false,
          skip_rate_limit: false,
        }),
      });
      whitelistForm.resetFields();
      message.success("白名单已保存");
      await refresh();
      return true;
    } catch (cause) {
      message.error(cause.message);
      return false;
    }
  }

  async function saveNginxConfig(values) {
    try {
      const result = await api("/api/nginx/config", {
        method: "POST",
        body: JSON.stringify(values),
      });
      setSystemInfo((current) => ({ ...current, nginx: result.nginx }));
      message.success(
        result.existing_sites_require_resync
          ? "Nginx 设置已保存到 SQLite；已有站点如修改了路径，请重新保存一次"
          : "Nginx 设置已保存到 SQLite",
      );
      await refresh();
      return true;
    } catch (cause) {
      message.error(cause.message);
      return false;
    }
  }

  async function detectNginx() {
    try {
      const result = await api("/api/nginx/detect");
      setSystemInfo((current) => ({
        ...current,
        nginx_detection: result.nginx_detection,
      }));
      if (result.nginx_detection.binary) {
        nginxPathForm.setFieldsValue({ binary: result.nginx_detection.binary });
      }
      message[result.nginx_detection.config_valid ? "success" : "warning"](
        result.nginx_detection.message,
      );
    } catch (cause) {
      message.error(cause.message);
    }
  }

  async function saveNginxPath(values) {
    const current = systemInfo.nginx || {};
    const saved = await saveNginxConfig({
      enabled: current.enabled ?? true,
      binary: values.binary,
      config_file: current.config_file || "",
      vhost_dir: current.vhost_dir || "",
      include_dir: current.include_dir || "",
    });
    if (saved) setNginxPathModal(false);
    return saved;
  }

  async function saveSite(values) {
    try {
      await api("/api/sites", {
        method: "POST",
        body: JSON.stringify({ ...values, policy: "normal", enabled: true }),
      });
      message.success(
        values.mode === "nginx"
          ? "Nginx 内联防护站点已保存并同步配置"
          : "前置代理站点已保存",
      );
      await refresh();
      return true;
    } catch (cause) {
      message.error(cause.message);
      return false;
    }
  }

  async function deleteSite(host) {
    try {
      await api("/api/sites/delete", {
        method: "POST",
        body: JSON.stringify({ host }),
      });
      message.success("站点已删除");
      await refresh();
    } catch (cause) {
      message.error(cause.message);
    }
  }

  async function toggleSite(row) {
    try {
      await api("/api/sites/toggle", {
        method: "POST",
        body: JSON.stringify({ host: row.host, enabled: !row.enabled }),
      });
      message.success(
        row.enabled
          ? "已暂停保护；源站仍应保持内网监听"
          : "已恢复保护，域名重新经过 Bot Gate",
      );
      await refresh();
    } catch (cause) {
      message.error(cause.message);
    }
  }

  async function deleteBan(ip) {
    try {
      await api("/api/bans/delete", {
        method: "POST",
        body: JSON.stringify({ ip }),
      });
      message.success("封禁已删除");
      await refresh();
    } catch (cause) {
      message.error(cause.message);
    }
  }

  async function deleteWhitelist(id) {
    try {
      await api("/api/whitelist/delete", {
        method: "POST",
        body: JSON.stringify({ id }),
      });
      message.success("白名单已删除");
      await refresh();
    } catch (cause) {
      message.error(cause.message);
    }
  }

  const siteColumns = [
    { title: "公网 Host", dataIndex: "host", key: "host" },
    {
      title: "接入模式",
      dataIndex: "mode",
      key: "mode",
      render: (value) => (
        <Tag color={value === "nginx" ? "blue" : "default"}>
          {value === "nginx" ? "Nginx 内联" : "前置代理"}
        </Tag>
      ),
    },
    {
      title: "源站服务",
      dataIndex: "target",
      key: "target",
      render: (value, row) =>
        row.mode === "nginx" ? "由原 Nginx vhost 保持服务" : value,
    },
    {
      title: "策略",
      dataIndex: "policy",
      key: "policy",
      render: (value) => <Tag>{value}</Tag>,
    },
    {
      title: "保护状态",
      dataIndex: "enabled",
      key: "enabled",
      render: (value, row) => {
        const active = row.effective_protection;
        return (
          <Tag color={active ? "success" : "default"}>
            {active ? "保护中" : value ? "接入未完成" : "已暂停"}
          </Tag>
        );
      },
    },
    {
      title: "操作",
      key: "action",
      render: (_, row) => (
        <Space size="small">
          <Tooltip title={row.enabled ? "暂停保护" : "恢复保护"}>
            <Button
              type="link"
              aria-label={row.enabled ? "暂停保护" : "恢复保护"}
              icon={row.enabled ? <PauseCircleOutlined /> : <UnlockOutlined />}
              onClick={() => toggleSite(row)}
            />
          </Tooltip>
          <Tooltip title="删除站点">
            <Button
              danger
              type="link"
              aria-label="删除站点"
              icon={<DeleteOutlined />}
              onClick={() => deleteSite(row.host)}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];
  const banColumns = [
    { title: "IP", dataIndex: "ip", key: "ip" },
    { title: "原因", dataIndex: "reason", key: "reason" },
    { title: "来源", dataIndex: "source", key: "source" },
    {
      title: "到期时间",
      dataIndex: "expires_at",
      key: "expires_at",
      render: (value) => new Date(value * 1000).toLocaleString(),
    },
    {
      title: "操作",
      key: "action",
      render: (_, row) => (
        <Tooltip title="解除封禁">
          <Button
            danger
            type="link"
            aria-label="解除封禁"
            icon={<UnlockOutlined />}
            onClick={() => deleteBan(row.ip)}
          />
        </Tooltip>
      ),
    },
  ];
  const whitelistColumns = [
    { title: "类型", dataIndex: "kind", key: "kind" },
    { title: "值", dataIndex: "value", key: "value" },
    {
      title: "备注",
      dataIndex: "note",
      key: "note",
      render: (value) => value || "-",
    },
    {
      title: "操作",
      key: "action",
      render: (_, row) => (
        <Tooltip title="删除白名单">
          <Button
            danger
            type="link"
            aria-label="删除白名单"
            icon={<DeleteOutlined />}
            onClick={() => deleteWhitelist(row.id)}
          />
        </Tooltip>
      ),
    },
  ];
  return (
    <Layout className="admin-layout">
      <Header className="admin-header">
        <div className="brand-block">
          <div className="brand-mark">
            <CloudOutlined />
          </div>
          <div>
            <Title level={3}>Bot Gate</Title>
          </div>
        </div>
        <div className="header-actions">
          <Button
            type={gatewayStatus.running ? "default" : "primary"}
            danger={gatewayStatus.running}
            disabled={
              !gatewayStatus.running &&
              licenseStatus !== "active" &&
              licenseStatus !== "disabled"
            }
            onClick={toggleGateway}
          >
            {gatewayStatus.running ? "停止网关" : "启动网关"}
          </Button>
          <Tooltip title="激活许可证">
            <Button
              aria-label="激活许可证"
              icon={<KeyOutlined />}
              onClick={() => setLicenseModal(true)}
            />
          </Tooltip>
          <Tooltip title="检查更新">
            <Button
              aria-label="检查更新"
              loading={updateLoading}
              icon={<CloudDownloadOutlined />}
              onClick={() => checkForUpdates(false)}
            />
          </Tooltip>
          <Tooltip title="重新加载配置">
            <Button
              aria-label="重新加载配置"
              icon={<ReloadOutlined />}
              onClick={reloadConfig}
            />
          </Tooltip>
          <Tooltip title="刷新数据">
            <Button
              type="primary"
              aria-label="刷新数据"
              icon={<SyncOutlined spin={loading} />}
              onClick={refresh}
            />
          </Tooltip>
        </div>
      </Header>
      <Content className="admin-content">
        <section className="welcome-row">
          <div>
            <Text className="eyebrow">SECURITY OVERVIEW</Text>
            <Title className="page-title">运行概览</Title>
            <Text className="page-subtitle">
              支持 Nginx
              内联防护：原站配置不迁移，验证通过后继续走原有站点逻辑。
            </Text>
          </div>
        </section>
        <Alert
          className="notice-alert"
          type="info"
          showIcon
          message="推荐使用 Nginx 内联模式：Bot Gate 只做验证与拦截，原 Nginx 继续服务静态文件、API 和 WebSocket。管理台仅监听本机回环地址。"
        />
        {error && (
          <Alert
            className="error-alert"
            type="error"
            showIcon
            message={error}
          />
        )}

        <Row gutter={[12, 12]} className="stats-grid">
          {metricCards.map((card) => (
            <Col xs={24} sm={12} lg={8} key={card.key}>
              <Card
                className={`metric-card metric-${card.tone} metric-clickable`}
                onClick={() => openMetric(card)}
                role="button"
                tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ")
                    openMetric(card);
                }}
              >
                <div className="metric-icon">{card.icon}</div>
                <Statistic
                  title={card.label}
                  value={dashboard[card.key] ?? 0}
                />
                <Text className="metric-caption">
                  {card.key.startsWith("today_") ? "今日累计" : "当前状态"}
                </Text>
              </Card>
            </Col>
          ))}
        </Row>

        <Text className="metric-hint">点击上方统计卡片查看对应明细</Text>

        <Tabs
          className="log-tabs management-tabs"
          items={[
            {
              key: "sites",
              label: (
                <span>
                  <GlobalOutlined /> 站点路由
                </span>
              ),
              children: (
                <div className="management-panel">
                  <div className="management-panel-head">
                    <SectionTitle
                      icon={<GlobalOutlined />}
                      title="受保护站点"
                      description={`${sites.length} 个站点；Nginx 内联模式无需迁移源站地址`}
                    />
                    <Space wrap>
                      <Button
                        icon={<SettingOutlined />}
                        onClick={() => {
                          nginxPathForm.setFieldsValue({
                            binary: systemInfo.nginx?.binary || "",
                          });
                          setNginxPathModal(true);
                        }}
                      >
                        设置 Nginx 路径
                      </Button>
                      <Button
                        type="primary"
                        icon={<PlusOutlined />}
                        onClick={() => openAddModal("site")}
                      >
                        添加站点
                      </Button>
                    </Space>
                  </div>
                  <Alert
                    type="info"
                    showIcon
                    message="Nginx 内联模式会自动写入受控 include、执行 nginx -t 并平滑重载。"
                    description="内联模式保留原 Nginx vhost 的 root、/api/、PHP 和 WebSocket 配置；只有独立前置代理模式才需要填写内部源站地址。"
                    style={{ marginBottom: 16 }}
                  />
                  <Table
                    rowKey="host"
                    loading={loading}
                    columns={siteColumns}
                    dataSource={sites}
                    pagination={{ pageSize: 8 }}
                  />
                </div>
              ),
            },
            {
              key: "nginx",
              label: (
                <span>
                  <CloudOutlined /> Nginx 设置
                </span>
              ),
              children: (
                <div className="management-panel">
                  <SectionTitle
                    icon={<CloudOutlined />}
                    title="Nginx 内联适配"
                    description="每台机器只需配置一次，站点添加时直接复用"
                  />
                  <Alert
                    type="info"
                    showIcon
                    message="Bot Gate 会自动寻找本机正在运行的 Nginx"
                    description="默认会自动检测 Nginx；如果安装目录不在 PATH 中，可直接在“站点路由”右侧设置运行目录。Nginx 的站点配置文件仍会通过 nginx -T 自动发现。"
                    style={{ marginBottom: 16 }}
                  />
                  {systemInfo.nginx_detection && (
                    <Alert
                      type={
                        systemInfo.nginx_detection.config_valid
                          ? "success"
                          : "warning"
                      }
                      showIcon
                      message={systemInfo.nginx_detection.message}
                      description={
                        systemInfo.nginx_detection.binary
                          ? `程序：${systemInfo.nginx_detection.binary}${systemInfo.nginx_detection.config_file ? `；配置：${systemInfo.nginx_detection.config_file}` : "；配置：使用 Nginx 默认配置"}`
                          : "请先启动 Nginx，或在站点路由右侧填写 Nginx 运行目录。"
                      }
                      action={
                        <Button size="small" onClick={detectNginx}>
                          重新检测
                        </Button>
                      }
                      style={{ marginBottom: 16 }}
                    />
                  )}
                  <Form
                    form={nginxForm}
                    layout="vertical"
                    onFinish={saveNginxConfig}
                    style={{ maxWidth: 760 }}
                  >
                    <Form.Item
                      name="enabled"
                      label="启用 Nginx 内联适配"
                      valuePropName="checked"
                    >
                      <Switch />
                    </Form.Item>
                    <Button
                      type="primary"
                      htmlType="submit"
                      icon={<SafetyCertificateOutlined />}
                    >
                      保存 Nginx 设置
                    </Button>
                    <details className="nginx-advanced-settings">
                      <summary>高级设置：其他 Nginx 配置</summary>
                      <Text type="secondary">
                        只有 Nginx 未启动、且安装目录不在 PATH 或常见目录时才需要使用。普通用户无需填写。
                      </Text>
                      <Form.Item name="binary" label="Nginx 运行目录或程序路径">
                        <Input placeholder="例如 D:\\nginx 或 nginx.exe 的完整路径" />
                      </Form.Item>
                      <Form.Item name="config_file" label="Nginx 主配置文件">
                        <Input placeholder="可选，例如 conf/nginx.conf" />
                      </Form.Item>
                      <Form.Item name="vhost_dir" label="站点配置目录">
                        <Input placeholder="可选；留空自动发现" />
                      </Form.Item>
                      <Form.Item name="include_dir" label="Bot Gate include 目录">
                        <Input placeholder="可选；默认 data/nginx" />
                      </Form.Item>
                      <Button type="primary" htmlType="submit">
                        保存高级设置
                      </Button>
                    </details>
                  </Form>
                </div>
              ),
            },
            {
              key: "bans",
              label: (
                <span>
                  <LockOutlined /> 临时封禁
                </span>
              ),
              children: (
                <div className="management-panel">
                  <div className="management-panel-head">
                    <SectionTitle
                      icon={<LockOutlined />}
                      title="临时封禁"
                      description="控制异常来源的访问权限"
                    />
                    <Button
                      type="primary"
                      danger
                      icon={<PlusOutlined />}
                      onClick={() => openAddModal("ban")}
                    >
                      添加封禁
                    </Button>
                  </div>
                  <Table
                    rowKey="ip"
                    loading={loading}
                    columns={banColumns}
                    dataSource={bans}
                    pagination={{ pageSize: 8 }}
                  />
                </div>
              ),
            },
            {
              key: "whitelist",
              label: (
                <span>
                  <SafetyCertificateOutlined /> 白名单
                </span>
              ),
              children: (
                <div className="management-panel">
                  <div className="management-panel-head">
                    <SectionTitle
                      icon={<SafetyCertificateOutlined />}
                      title="白名单"
                      description="仅影响策略，不跳过浏览器验证"
                    />
                    <Button
                      type="primary"
                      icon={<PlusOutlined />}
                      onClick={() => openAddModal("whitelist")}
                    >
                      添加白名单
                    </Button>
                  </div>
                  <Table
                    rowKey="id"
                    loading={loading}
                    columns={whitelistColumns}
                    dataSource={whitelist}
                    pagination={{ pageSize: 8 }}
                  />
                </div>
              ),
            },
          ]}
        />
        <Modal
          open={nginxPathModal}
          centered
          title="设置 Nginx 运行目录"
          footer={null}
          destroyOnClose
          onCancel={() => setNginxPathModal(false)}
        >
          <Form
            form={nginxPathForm}
            layout="vertical"
            onFinish={saveNginxPath}
          >
            <Form.Item
              name="binary"
              label="Nginx 运行目录或程序路径"
              rules={[{ required: true, message: "请输入 Nginx 安装目录或 nginx.exe 路径" }]}
            >
              <Input placeholder="例如 D:\\nginx 或 /usr/local/nginx" />
            </Form.Item>
            <Text type="secondary">
              可以填写 Nginx 安装目录，也可以填写 nginx.exe 的完整路径。保存后，添加站点、启动保护、取消保护和配置重载都会使用这里的路径。
            </Text>
            <Space style={{ marginTop: 20 }}>
              <Button onClick={detectNginx} icon={<ReloadOutlined />}>
                自动检测
              </Button>
              <Button type="primary" htmlType="submit" icon={<CheckCircleFilled />}>
                保存并检测
              </Button>
            </Space>
          </Form>
        </Modal>
        <Modal
          open={Boolean(addModal)}
          centered
          title={
            addModal === "site"
              ? "添加受保护站点"
              : addModal === "ban"
                ? "添加临时封禁"
                : "添加白名单"
          }
          footer={null}
          destroyOnClose
          onCancel={() => setAddModal(null)}
        >
          {addModal === "site" && (
            <Form
              form={siteForm}
              layout="vertical"
              onFinish={async (values) => {
                if (await saveSite(values)) setAddModal(null);
              }}
            >
              <Form.Item
                name="mode"
                label="接入模式"
                initialValue="nginx"
                rules={[{ required: true }]}
              >
                <Select
                  options={[
                    { value: "nginx", label: "Nginx 内联防护（推荐）" },
                    { value: "proxy", label: "独立前置代理" },
                  ]}
                />
              </Form.Item>
              <Alert
                type={siteMode === "nginx" ? "info" : "warning"}
                showIcon
                message={
                  siteMode === "nginx"
                    ? "原 Nginx 站点配置保持不变"
                    : "请先将源站服务改为内部监听"
                }
                description={
                  siteMode === "nginx"
                    ? `Bot Gate 会自动定位 Nginx 和 Host 对应的 vhost，写入受控 include 后执行 nginx -t 和平滑重载。当前 Nginx：${systemInfo.nginx_detection?.config_valid ? "已检测并通过配置校验" : "未检测到可用配置"}`
                    : "源站必须只暴露给本机或内网，例如 127.0.0.1:18082；否则用户仍可绕过 Bot Gate 直接访问源站。"
                }
                style={{ marginBottom: 16 }}
              />
              <Form.Item
                name="host"
                label="公网 Host"
                rules={[
                  { required: true, message: "请输入用户访问的域名或 IP" },
                ]}
              >
                <Input placeholder="dada.com 或 example.com" />
              </Form.Item>
              {siteMode === "proxy" && (
                <Form.Item
                  preserve={false}
                  name="target"
                  label="源站服务地址"
                  rules={[
                    {
                      required: true,
                      type: "url",
                      message: "请输入完整 HTTP 地址",
                    },
                  ]}
                >
                  <Input placeholder="http://127.0.0.1:3000" />
                </Form.Item>
              )}
              <Button
                type="primary"
                htmlType="submit"
                block
                icon={<SafetyCertificateOutlined />}
              >
                保存并启用保护
              </Button>
            </Form>
          )}
          {addModal === "ban" && (
            <Form
              form={banForm}
              layout="vertical"
              onFinish={async (values) => {
                if (await saveBan(values)) setAddModal(null);
              }}
            >
              <Form.Item
                name="ip"
                label="IP 地址"
                rules={[{ required: true, message: "请输入 IP 地址" }]}
              >
                <Input placeholder="192.168.1.20" />
              </Form.Item>
              <Form.Item
                name="reason"
                label="原因"
                rules={[{ required: true, message: "请输入封禁原因" }]}
              >
                <Input placeholder="扫描行为" />
              </Form.Item>
              <Form.Item
                name="duration_secs"
                label="持续秒数"
                initialValue={600}
                rules={[{ required: true, message: "请输入持续秒数" }]}
              >
                <InputNumber min={1} className="full-width" placeholder="600" />
              </Form.Item>
              <Button type="primary" danger htmlType="submit" block>
                保存封禁
              </Button>
            </Form>
          )}
          {addModal === "whitelist" && (
            <Form
              form={whitelistForm}
              layout="vertical"
              onFinish={async (values) => {
                if (await saveWhitelist(values)) setAddModal(null);
              }}
            >
              <Form.Item
                name="value"
                label="地址或网段"
                rules={[{ required: true, message: "请输入地址或网段" }]}
              >
                <Input placeholder="127.0.0.1 或 192.168.1.0/24" />
              </Form.Item>
              <Form.Item name="note" label="备注">
                <Input placeholder="备注（可选）" />
              </Form.Item>
              <Button
                type="primary"
                htmlType="submit"
                block
                icon={<SafetyCertificateOutlined />}
              >
                保存白名单
              </Button>
            </Form>
          )}
        </Modal>
        <Modal
          open={licenseModal}
          centered
          title="激活许可证"
          okButtonProps={{ style: { display: "none" } }}
          cancelText="关闭"
          onCancel={() => setLicenseModal(false)}
        >
          <Form form={licenseForm} layout="vertical" onFinish={activateLicense}>
            <Form.Item
              name="key"
              label="许可证密钥"
              rules={[{ required: true, message: "请输入许可证密钥" }]}
            >
              <Input.TextArea rows={5} placeholder="BG1.payload.signature" />
            </Form.Item>
            <Button type="primary" htmlType="submit" block>
              验证并激活
            </Button>
          </Form>
        </Modal>
        <Modal
          open={updateModal}
          centered
          title={
            updateError
              ? "检查更新失败"
              : updateInfo?.update_available
                ? "发现新版本"
                : "检查更新"
          }
          okText={
            updateError || !updateInfo?.update_available
              ? "关闭"
              : updateProgress.status === "failed"
                ? "重新下载"
                : ["checking", "downloading", "restarting"].includes(
                      updateProgress.status,
                    )
                  ? "更新中"
                  : "下载并安装"
          }
          cancelText="暂不更新"
          confirmLoading={updateLoading}
          okButtonProps={{
            type: "primary",
            disabled:
              !updateError &&
              updateInfo?.update_available &&
              ["checking", "downloading", "restarting"].includes(
                updateProgress.status,
              ),
          }}
          onOk={
            updateError || !updateInfo?.update_available
              ? () => setUpdateModal(false)
              : applyUpdate
          }
          onCancel={() => setUpdateModal(false)}
        >
          {updateError ? (
            <Alert type="error" showIcon message={updateError} />
          ) : (
            <>
              <p>当前版本：v{updateInfo?.current_version}</p>
              <p>最新版本：v{updateInfo?.latest_version}</p>
            </>
          )}
          {!updateError && updateInfo?.update_available ? (
            <>
              <Alert
                type="info"
                showIcon
                message="更新内容"
                description={
                  updateInfo?.release_notes ? (
                    <pre
                      style={{
                        whiteSpace: "pre-wrap",
                        maxHeight: 180,
                        overflow: "auto",
                        margin: 0,
                      }}
                    >
                      {updateInfo.release_notes}
                    </pre>
                  ) : (
                    "本次 Release 未填写更新说明。"
                  )
                }
              />
              <Progress
                percent={updateProgress.percent}
                status={
                  updateProgress.status === "failed"
                    ? "exception"
                    : updateProgress.status === "restarting"
                      ? "active"
                      : undefined
                }
                style={{ marginTop: 16 }}
              />
              {updateProgress.message && (
                <Text
                  type={
                    updateProgress.status === "failed" ? "danger" : "secondary"
                  }
                >
                  {updateProgress.message}
                </Text>
              )}
              <p>配置文件、许可证和运行数据会被保留。</p>
            </>
          ) : (
            !updateError && (
              <Alert
                type="success"
                showIcon
                message={`当前已是最新版本 v${updateInfo?.current_version || systemInfo.version}`}
              />
            )
          )}
        </Modal>
      </Content>
      <footer className="admin-footer">
        <span className="footer-powered">
          Powered by <strong>Bot Gate</strong>
        </span>
        <div className="footer-status">
          <Tag icon={<CheckCircleFilled />} color="success">
            本机运行
          </Tag>
          <Tag>管理 · Loopback only</Tag>
          <Tag color={licenseStatus === "active" ? "success" : "default"}>
            许可证 · {licenseLabel}
          </Tag>
          <Tag color={gatewayStatus.running ? "success" : "default"}>
            网关 · {gatewayStatus.running ? "运行中" : "已停止"}
          </Tag>
        </div>
        <span className="footer-version">
          v{systemInfo.version} · 更新于{" "}
          {lastUpdated ? lastUpdated.toLocaleTimeString() : "加载中"}
        </span>
      </footer>
      <LogsPanel
        api={api}
        message={message}
        open={Boolean(logModal)}
        mode={logModal?.mode}
        filters={logModal?.filters}
        onChanged={refresh}
        onClose={() => setLogModal(null)}
      />
    </Layout>
  );
}

function SectionTitle({ icon, title, description }) {
  return (
    <div className="section-title">
      <span className="section-icon">{icon}</span>
      <span>
        <strong>{title}</strong>
        <small>{description}</small>
      </span>
    </div>
  );
}

createRoot(document.getElementById("root")).render(
  <ConfigProvider
    theme={{
      token: {
        colorPrimary: "#149b73",
        colorInfo: "#149b73",
        borderRadius: 12,
        fontFamily:
          'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      },
      components: {
        Card: { headerFontSize: 16 },
        Button: { controlHeight: 38 },
      },
    }}
  >
    <App>
      <AdminConsole />
    </App>
  </ConfigProvider>,
);
