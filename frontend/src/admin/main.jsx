import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
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
  Space,
  Statistic,
  Table,
  Tag,
  Tabs,
  Tooltip,
  Typography,
} from 'antd';
import {
  ApiOutlined,
  CheckCircleFilled,
  CloudOutlined,
  CloudDownloadOutlined,
  DeleteOutlined,
  FileSearchOutlined,
  FolderOpenOutlined,
  GlobalOutlined,
  KeyOutlined,
  LockOutlined,
  PauseCircleOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SyncOutlined,
  UnlockOutlined,
} from '@ant-design/icons';
import 'antd/dist/reset.css';
import './style.css';
import LogsPanel from './logs.jsx';

const { Header, Content } = Layout;
const { Text, Title } = Typography;

const metricCards = [
  { key: 'today_requests', label: '今日请求', icon: <ApiOutlined />, tone: 'blue', mode: 'requests' },
  { key: 'today_verified', label: '已验证请求', icon: <CheckCircleFilled />, tone: 'green', mode: 'requests' },
  { key: 'today_blocked', label: '已拦截请求', icon: <LockOutlined />, tone: 'orange', mode: 'requests' },
  { key: 'today_challenge_failures', label: '验证失败', icon: <SafetyCertificateOutlined />, tone: 'purple', mode: 'interceptions' },
  { key: 'active_bans', label: '活跃封禁', icon: <DeleteOutlined />, tone: 'red', mode: 'bans' },
  { key: 'active_challenges', label: '进行中验证', icon: <GlobalOutlined />, tone: 'cyan', mode: 'challenges' },
];

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.message || `请求失败 (${response.status})`);
  return body;
}

function AdminConsole() {
  const { message } = App.useApp();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [dashboard, setDashboard] = useState({});
  const [sites, setSites] = useState([]);
  const [bans, setBans] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [caddyEnabled, setCaddyEnabled] = useState(false);
  const [nginxInfo, setNginxInfo] = useState({ configured: false });
  const [lastUpdated, setLastUpdated] = useState(null);
  const [systemInfo, setSystemInfo] = useState({ version: '0.1.0', update_enabled: false, gateway: { running: false } });
  const [gatewayStatus, setGatewayStatus] = useState({ running: false });
  const [logModal, setLogModal] = useState(null);
  const [addModal, setAddModal] = useState(null);
  const [nginxModal, setNginxModal] = useState(false);
  const [nginxScanLoading, setNginxScanLoading] = useState(false);
  const [licenseModal, setLicenseModal] = useState(false);
  const [updateModal, setUpdateModal] = useState(false);
  const [updateInfo, setUpdateInfo] = useState(null);
  const [updateError, setUpdateError] = useState('');
  const [updateLoading, setUpdateLoading] = useState(false);
  const [updateProgress, setUpdateProgress] = useState({ status: 'idle', percent: 0, message: '' });
  const [autoUpdateChecked, setAutoUpdateChecked] = useState(false);
  const [siteForm] = Form.useForm();
  const [banForm] = Form.useForm();
  const [whitelistForm] = Form.useForm();
  const [licenseForm] = Form.useForm();
  const [nginxForm] = Form.useForm();
  const licenseStatus = systemInfo.license?.status || 'disabled';
  const licenseLabel = licenseStatus === 'active' ? '有效' : licenseStatus === 'disabled' ? '未启用' : '未激活';

  async function refresh() {
    setLoading(true);
    setError('');
    try {
      const [stats, siteData, banData, whitelistData, systemData] = await Promise.all([
        api('/api/dashboard'),
        api('/api/sites'),
        api('/api/bans'),
        api('/api/whitelist'),
        api('/api/system'),
      ]);
      setDashboard(stats);
      setSites(siteData.sites || []);
      setCaddyEnabled(Boolean(siteData.caddy_enabled));
      setNginxInfo(siteData.nginx || { configured: false });
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
    setUpdateError('');
    if (!systemInfo.update_enabled || !systemInfo.release_url) {
      setUpdateInfo({ update_available: false, current_version: systemInfo.version, latest_version: systemInfo.version });
      setUpdateError('尚未配置 GitHub Release 更新地址');
      if (!silent) setUpdateModal(true);
      if (!silent) message.info('尚未配置 GitHub Release 更新地址');
      return;
    }
    setUpdateLoading(true);
    try {
      const result = await api('/api/update/check');
      const update = result.update;
      setUpdateInfo(update);
      if (update.update_available) {
        setUpdateModal(true);
      } else {
        if (!silent) setUpdateModal(true);
        if (!silent) message.success(`当前已是最新版本 v${update.current_version}`);
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
    if (['checking', 'downloading', 'restarting'].includes(updateProgress.status)) return;
    setUpdateLoading(true);
    try {
      await api('/api/update/apply', {
        method: 'POST',
        headers: { 'x-bot-gate-action': 'update' },
      });
      message.success('更新已开始下载');
    } catch (cause) {
      message.error(cause.message);
    } finally {
      setUpdateLoading(false);
    }
  }

  async function activateLicense(values) {
    try {
      const result = await api('/api/license/activate', {
        method: 'POST',
        body: JSON.stringify({ key: values.key }),
      });
      setSystemInfo((current) => ({ ...current, license: result.license }));
      licenseForm.resetFields();
      setLicenseModal(false);
      message.success('许可证激活成功');
    } catch (cause) {
      message.error(cause.message);
    }
  }

  async function toggleGateway() {
    const action = gatewayStatus.running ? 'stop' : 'start';
    try {
      const result = await api(`/api/gateway/${action}`, { method: 'POST' });
      setGatewayStatus(result.gateway);
      message.success(action === 'start' ? '网关已启动' : '网关已停止');
    } catch (cause) {
      message.error(cause.message);
    }
  }

  useEffect(() => { refresh(); }, []);

  useEffect(() => {
    if (!autoUpdateChecked && systemInfo.version !== '0.1.0' && systemInfo.update_enabled) {
      setAutoUpdateChecked(true);
      checkForUpdates(true);
    }
  }, [autoUpdateChecked, systemInfo.version, systemInfo.update_enabled]);

  useEffect(() => {
    if (!updateModal) return undefined;
    let active = true;
    const loadProgress = async () => {
      try {
        const result = await api('/api/update/progress');
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
    if (type === 'site') siteForm.resetFields();
    if (type === 'ban') banForm.resetFields();
    if (type === 'whitelist') whitelistForm.resetFields();
    setAddModal(type);
  }

  function openMetric(card) {
    const filters = {};
    if (card.key === 'today_verified') filters.verified = true;
    if (card.key === 'today_blocked') filters.blocked = true;
    if (card.key === 'today_challenge_failures') filters.event_type = 'challenge_failure';
    setLogModal({ mode: card.mode, filters });
  }

  async function reloadConfig() {
    try {
      await api('/api/reload', { method: 'POST' });
      message.success('配置已重新加载');
      await refresh();
    } catch (cause) {
      message.error(cause.message);
    }
  }

  async function pickNginxDirectory() {
    setNginxScanLoading(true);
    try {
      const result = await api('/api/nginx/pick', { method: 'POST' });
      if (result.path) {
        nginxForm.setFieldValue('config_dir', result.path);
      } else {
        message.info('已取消选择目录');
      }
    } catch (cause) {
      message.error(cause.message);
    } finally {
      setNginxScanLoading(false);
    }
  }

  async function pickNginxConfigFile() {
    setNginxScanLoading(true);
    try {
      const result = await api('/api/nginx/pick-config', { method: 'POST' });
      if (result.path) {
        nginxForm.setFieldValue('config_dir', result.path);
      } else {
        message.info('已取消选择配置文件');
      }
    } catch (cause) {
      message.error(cause.message);
    } finally {
      setNginxScanLoading(false);
    }
  }

  async function scanNginx(values) {
    setNginxScanLoading(true);
    try {
      const result = await api('/api/nginx/scan', { method: 'POST', body: JSON.stringify(values) });
      setNginxModal(false);
      const count = result.sites?.length || 0;
      if (count) {
        message.success(`Nginx 扫描完成：发现 ${count} 个站点，读取 ${result.scanned_files || 0} 个配置文件`);
      } else {
        message.warning(`未发现可管理站点，已读取 ${result.scanned_files || 0} 个配置文件`);
      }
      await refresh();
    } catch (cause) {
      message.error(cause.message);
    } finally {
      setNginxScanLoading(false);
    }
  }

  async function saveSite(values) {
    try {
      const existing = sites.find((site) => site.host === values.host.trim().toLowerCase());
      await api('/api/sites', {
        method: 'POST',
        body: JSON.stringify({ ...values, enabled: existing ? existing.enabled : true }),
      });
      siteForm.resetFields();
      message.success('站点已保存');
      await refresh();
      return true;
    } catch (cause) {
      message.error(cause.message);
      return false;
    }
  }

  async function saveBan(values) {
    try {
      await api('/api/bans', { method: 'POST', body: JSON.stringify(values) });
      banForm.resetFields(['ip', 'reason']);
      message.success('封禁已保存');
      await refresh();
      return true;
    } catch (cause) {
      message.error(cause.message);
      return false;
    }
  }

  async function saveWhitelist(values) {
    try {
      await api('/api/whitelist', {
        method: 'POST',
        body: JSON.stringify({ ...values, skip_challenge: false, skip_rate_limit: false }),
      });
      whitelistForm.resetFields();
      message.success('白名单已保存');
      await refresh();
      return true;
    } catch (cause) {
      message.error(cause.message);
      return false;
    }
  }

  async function deleteSite(host) {
    try {
      await api('/api/sites/delete', { method: 'POST', body: JSON.stringify({ host }) });
      message.success('站点已删除');
      await refresh();
    } catch (cause) { message.error(cause.message); }
  }

  async function toggleSite(row) {
    try {
      await api('/api/sites/toggle', {
        method: 'POST',
        body: JSON.stringify({ host: row.host, enabled: !row.enabled }),
      });
      message.success(row.enabled ? '已暂停保护，域名将直连项目' : '已恢复保护，域名重新经过 Bot Gate');
      await refresh();
    } catch (cause) { message.error(cause.message); }
  }

  async function toggleNginxSite(row) {
    try {
      await api('/api/nginx/toggle', {
        method: 'POST',
        body: JSON.stringify({ id: row.id, protected: !row.protected }),
      });
      message.success(row.protected ? '已取消保护，Nginx 恢复直连项目' : '已启用保护，Nginx 请求将经过 Bot Gate');
      await refresh();
    } catch (cause) { message.error(cause.message); }
  }

  async function deleteNginxSite(row) {
    try {
      await api('/api/nginx/delete', {
        method: 'POST',
        body: JSON.stringify({ id: row.id }),
      });
      message.success('Nginx 站点已从 Bot Gate 列表移除，原配置已恢复直连');
      await refresh();
    } catch (cause) { message.error(cause.message); }
  }

  async function deleteBan(ip) {
    try {
      await api('/api/bans/delete', { method: 'POST', body: JSON.stringify({ ip }) });
      message.success('封禁已删除');
      await refresh();
    } catch (cause) { message.error(cause.message); }
  }

  async function deleteWhitelist(id) {
    try {
      await api('/api/whitelist/delete', { method: 'POST', body: JSON.stringify({ id }) });
      message.success('白名单已删除');
      await refresh();
    } catch (cause) { message.error(cause.message); }
  }

  const siteColumns = [
    { title: 'Host', dataIndex: 'host', key: 'host' },
    { title: 'Upstream', dataIndex: 'target', key: 'target' },
    { title: '来源', dataIndex: 'source', key: 'source', render: (value) => value === 'nginx' ? <Tag color="blue">Nginx</Tag> : <Tag>手动</Tag> },
    { title: '策略', dataIndex: 'policy', key: 'policy', render: (value) => <Tag>{value}</Tag> },
    { title: '保护状态', dataIndex: 'enabled', key: 'enabled', render: (value, row) => <Tag color={value ? 'success' : row.source === 'nginx' && !row.supported ? 'warning' : 'default'}>{value ? '保护中' : row.source === 'nginx' && !row.supported ? '无法自动接管' : row.source === 'nginx' ? '未保护，直连' : '已暂停，直连'}</Tag> },
    { title: '操作', key: 'action', render: (_, row) => <Space size="small">
      {row.source === 'nginx' ? (
        <>
          <Tooltip title={!row.supported ? '不是标准 proxy_pass，无法自动接管' : row.protected ? '取消保护并恢复 Nginx 直连' : '启用保护并接入 Bot Gate'}>
            <Button type="link" disabled={!row.supported} aria-label={row.protected ? '取消保护' : '启用保护'} icon={row.protected ? <PauseCircleOutlined /> : <SafetyCertificateOutlined />} onClick={() => toggleNginxSite(row)} />
          </Tooltip>
          <Popconfirm title="从 Bot Gate 移除此站点？" description="不会删除 Nginx 配置；受保护站点会先恢复为原 upstream。" okText="移除" cancelText="取消" onConfirm={() => deleteNginxSite(row)}>
            <Tooltip title="移除站点"><Button danger type="link" aria-label="移除 Nginx 站点" icon={<DeleteOutlined />} /></Tooltip>
          </Popconfirm>
        </>
      ) : (
        <Tooltip title={caddyEnabled ? (row.enabled ? '暂停保护' : '恢复保护') : '外部代理未启用自动切换'}>
          <Button type="link" disabled={!caddyEnabled} aria-label={row.enabled ? '暂停保护' : '恢复保护'} icon={row.enabled ? <PauseCircleOutlined /> : <UnlockOutlined />} onClick={() => toggleSite(row)} />
        </Tooltip>
      )}
      {row.source !== 'nginx' && <Tooltip title="删除站点"><Button danger type="link" aria-label="删除站点" icon={<DeleteOutlined />} onClick={() => deleteSite(row.host)} /></Tooltip>}
    </Space> },
  ];
  const banColumns = [
    { title: 'IP', dataIndex: 'ip', key: 'ip' },
    { title: '原因', dataIndex: 'reason', key: 'reason' },
    { title: '来源', dataIndex: 'source', key: 'source' },
    { title: '到期时间', dataIndex: 'expires_at', key: 'expires_at', render: (value) => new Date(value * 1000).toLocaleString() },
    { title: '操作', key: 'action', render: (_, row) => <Tooltip title="解除封禁"><Button danger type="link" aria-label="解除封禁" icon={<UnlockOutlined />} onClick={() => deleteBan(row.ip)} /></Tooltip> },
  ];
  const whitelistColumns = [
    { title: '类型', dataIndex: 'kind', key: 'kind' },
    { title: '值', dataIndex: 'value', key: 'value' },
    { title: '备注', dataIndex: 'note', key: 'note', render: (value) => value || '-' },
    { title: '操作', key: 'action', render: (_, row) => <Tooltip title="删除白名单"><Button danger type="link" aria-label="删除白名单" icon={<DeleteOutlined />} onClick={() => deleteWhitelist(row.id)} /></Tooltip> },
  ];
  return (
    <Layout className="admin-layout">
      <Header className="admin-header">
        <div className="brand-block">
          <div className="brand-mark"><CloudOutlined /></div>
          <div>
            <Title level={3}>Bot Gate</Title>
          </div>
        </div>
        <div className="header-actions">
          <Button
            type={gatewayStatus.running ? 'default' : 'primary'}
            danger={gatewayStatus.running}
            disabled={!gatewayStatus.running && licenseStatus !== 'active' && licenseStatus !== 'disabled'}
            onClick={toggleGateway}
          >
            {gatewayStatus.running ? '停止网关' : '启动网关'}
          </Button>
          <Tooltip title="激活许可证"><Button aria-label="激活许可证" icon={<KeyOutlined />} onClick={() => setLicenseModal(true)} /></Tooltip>
          <Tooltip title="检查更新"><Button aria-label="检查更新" loading={updateLoading} icon={<CloudDownloadOutlined />} onClick={() => checkForUpdates(false)} /></Tooltip>
          <Tooltip title="重新加载配置"><Button aria-label="重新加载配置" icon={<ReloadOutlined />} onClick={reloadConfig} /></Tooltip>
          <Tooltip title="刷新数据"><Button type="primary" aria-label="刷新数据" icon={<SyncOutlined spin={loading} />} onClick={refresh} /></Tooltip>
        </div>
      </Header>
      <Content className="admin-content">
        <section className="welcome-row">
          <div>
            <Text className="eyebrow">SECURITY OVERVIEW</Text>
            <Title className="page-title">运行概览</Title>
            <Text className="page-subtitle">保护本机站点，验证通过后才允许请求进入业务后端。</Text>
          </div>
        </section>
        <Alert className="notice-alert" type="info" showIcon message="管理台默认启动且仅监听本机回环地址，无密码登录。许可证有效后，可在此手动启动或停止网关。" />
        {error && <Alert className="error-alert" type="error" showIcon message={error} />}

        <Row gutter={[12, 12]} className="stats-grid">
          {metricCards.map((card) => (
            <Col xs={24} sm={12} lg={8} key={card.key}>
              <Card className={`metric-card metric-${card.tone} metric-clickable`} onClick={() => openMetric(card)} role="button" tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') openMetric(card); }}>
                <div className="metric-icon">{card.icon}</div>
                <Statistic title={card.label} value={dashboard[card.key] ?? 0} />
                <Text className="metric-caption">{card.key.startsWith('today_') ? '今日累计' : '当前状态'}</Text>
              </Card>
            </Col>
          ))}
        </Row>

        <Text className="metric-hint">点击上方统计卡片查看对应明细</Text>

        <Tabs
          className="log-tabs management-tabs"
            items={[
              {
                key: 'sites',
                label: <span><GlobalOutlined /> 站点路由</span>,
                children: (
                  <div className="management-panel">
                    <div className="management-panel-head">
                      <SectionTitle icon={<GlobalOutlined />} title="站点路由" description={`${sites.length} 个站点正在管理 · ${nginxInfo.configured ? 'Nginx 已接入' : '尚未接入 Nginx'}`} />
                      <Space>
                        <Button icon={<FolderOpenOutlined />} onClick={() => { nginxForm.setFieldValue('config_dir', nginxInfo.config_dir || ''); setNginxModal(true); }}>导入 Nginx</Button>
                        <Button type="primary" icon={<PlusOutlined />} onClick={() => openAddModal('site')}>手动添加</Button>
                      </Space>
                    </div>
                    <Table rowKey="host" loading={loading} columns={siteColumns} dataSource={sites} pagination={{ pageSize: 8 }} />
                  </div>
                ),
              },
              {
                key: 'bans',
                label: <span><LockOutlined /> 临时封禁</span>,
                children: (
                  <div className="management-panel">
                    <div className="management-panel-head">
                      <SectionTitle icon={<LockOutlined />} title="临时封禁" description="控制异常来源的访问权限" />
                      <Button type="primary" danger icon={<PlusOutlined />} onClick={() => openAddModal('ban')}>添加封禁</Button>
                    </div>
                    <Table rowKey="ip" loading={loading} columns={banColumns} dataSource={bans} pagination={{ pageSize: 8 }} />
                  </div>
                ),
              },
              {
                key: 'whitelist',
                label: <span><SafetyCertificateOutlined /> 白名单</span>,
                children: (
                  <div className="management-panel">
                    <div className="management-panel-head">
                      <SectionTitle icon={<SafetyCertificateOutlined />} title="白名单" description="仅影响策略，不跳过浏览器验证" />
                      <Button type="primary" icon={<PlusOutlined />} onClick={() => openAddModal('whitelist')}>添加白名单</Button>
                    </div>
                    <Table rowKey="id" loading={loading} columns={whitelistColumns} dataSource={whitelist} pagination={{ pageSize: 8 }} />
                  </div>
                ),
              },
            ]}
        />
        <Modal
          open={Boolean(addModal)}
          centered
          title={addModal === 'site' ? '添加站点' : addModal === 'ban' ? '添加临时封禁' : '添加白名单'}
          footer={null}
          destroyOnClose
          onCancel={() => setAddModal(null)}
        >
          {addModal === 'site' && (
            <Form form={siteForm} layout="vertical" onFinish={async (values) => { if (await saveSite(values)) setAddModal(null); }}>
              <Form.Item name="host" label="Host" rules={[{ required: true, message: '请输入 Host' }]}><Input placeholder="project.local" /></Form.Item>
              <Form.Item name="target" label="Upstream" rules={[{ required: true, message: '请输入 upstream' }]}><Input placeholder="http://127.0.0.1:9001" /></Form.Item>
              <Form.Item name="policy" label="策略" initialValue="normal"><Input placeholder="策略" /></Form.Item>
              <Button type="primary" htmlType="submit" block icon={<GlobalOutlined />}>保存站点</Button>
            </Form>
          )}
          {addModal === 'ban' && (
            <Form form={banForm} layout="vertical" onFinish={async (values) => { if (await saveBan(values)) setAddModal(null); }}>
              <Form.Item name="ip" label="IP 地址" rules={[{ required: true, message: '请输入 IP 地址' }]}><Input placeholder="192.168.1.20" /></Form.Item>
              <Form.Item name="reason" label="原因" rules={[{ required: true, message: '请输入封禁原因' }]}><Input placeholder="扫描行为" /></Form.Item>
              <Form.Item name="duration_secs" label="持续秒数" initialValue={600} rules={[{ required: true, message: '请输入持续秒数' }]}><InputNumber min={1} className="full-width" placeholder="600" /></Form.Item>
              <Button type="primary" danger htmlType="submit" block>保存封禁</Button>
            </Form>
          )}
          {addModal === 'whitelist' && (
            <Form form={whitelistForm} layout="vertical" onFinish={async (values) => { if (await saveWhitelist(values)) setAddModal(null); }}>
              <Form.Item name="value" label="地址或网段" rules={[{ required: true, message: '请输入地址或网段' }]}><Input placeholder="127.0.0.1 或 192.168.1.0/24" /></Form.Item>
              <Form.Item name="note" label="备注"><Input placeholder="备注（可选）" /></Form.Item>
              <Button type="primary" htmlType="submit" block icon={<SafetyCertificateOutlined />}>保存白名单</Button>
            </Form>
          )}
        </Modal>
        <Modal
          open={nginxModal}
          centered
          title="导入 Nginx 站点"
          okText="扫描站点"
          cancelText="取消"
          confirmLoading={nginxScanLoading}
          onCancel={() => setNginxModal(false)}
          onOk={() => nginxForm.submit()}
        >
          <Form form={nginxForm} layout="vertical" onFinish={scanNginx} onFinishFailed={() => message.warning('请选择或输入有效的 Nginx 运行目录或配置文件')}>
            <Form.Item name="config_dir" label="Nginx 运行目录或配置文件" rules={[{ required: true, message: '请选择或输入 Nginx 运行目录或配置文件' }]}>
              <Input placeholder="例如 C:\\nginx、/etc/nginx 或 nginx.conf" />
            </Form.Item>
            <Space>
              <Button icon={<FolderOpenOutlined />} loading={nginxScanLoading} onClick={pickNginxDirectory}>选择运行目录</Button>
              <Button icon={<FileSearchOutlined />} loading={nginxScanLoading} onClick={pickNginxConfigFile}>选择配置文件</Button>
            </Space>
            <Alert type="info" showIcon message="选择安装目录会自动查找 nginx.conf 和 include 配置；也可以直接选择实际配置文件，程序只导入该文件及其 include 的站点。" />
          </Form>
        </Modal>
        <Modal
          open={licenseModal}
          centered
          title="激活许可证"
          okButtonProps={{ style: { display: 'none' } }}
          cancelText="关闭"
          onCancel={() => setLicenseModal(false)}
        >
          <Form form={licenseForm} layout="vertical" onFinish={activateLicense}>
            <Form.Item name="key" label="许可证密钥" rules={[{ required: true, message: '请输入许可证密钥' }]}>
              <Input.TextArea rows={5} placeholder="BG1.payload.signature" />
            </Form.Item>
            <Button type="primary" htmlType="submit" block>验证并激活</Button>
          </Form>
        </Modal>
        <Modal
          open={updateModal}
          centered
          title={updateError ? '检查更新失败' : updateInfo?.update_available ? '发现新版本' : '检查更新'}
          okText={updateError || !updateInfo?.update_available ? '关闭' : (updateProgress.status === 'failed' ? '重新下载' : ['checking', 'downloading', 'restarting'].includes(updateProgress.status) ? '更新中' : '下载并安装')}
          cancelText="暂不更新"
          confirmLoading={updateLoading}
          okButtonProps={{ type: 'primary', disabled: !updateError && updateInfo?.update_available && ['checking', 'downloading', 'restarting'].includes(updateProgress.status) }}
          onOk={updateError || !updateInfo?.update_available ? () => setUpdateModal(false) : applyUpdate}
          onCancel={() => setUpdateModal(false)}
        >
          {updateError ? <Alert type="error" showIcon message={updateError} /> : <>
            <p>当前版本：v{updateInfo?.current_version}</p>
            <p>最新版本：v{updateInfo?.latest_version}</p>
          </>}
          {!updateError && updateInfo?.update_available ? (
            <>
              <Alert
                type="info"
                showIcon
                message="更新内容"
                description={updateInfo?.release_notes ? <pre style={{ whiteSpace: 'pre-wrap', maxHeight: 180, overflow: 'auto', margin: 0 }}>{updateInfo.release_notes}</pre> : '本次 Release 未填写更新说明。'}
              />
              <Progress
                percent={updateProgress.percent}
                status={updateProgress.status === 'failed' ? 'exception' : updateProgress.status === 'restarting' ? 'active' : undefined}
                style={{ marginTop: 16 }}
              />
              {updateProgress.message && <Text type={updateProgress.status === 'failed' ? 'danger' : 'secondary'}>{updateProgress.message}</Text>}
              <p>配置文件、许可证和运行数据会被保留。</p>
            </>
          ) : !updateError && <Alert type="success" showIcon message={`当前已是最新版本 v${updateInfo?.current_version || systemInfo.version}`} />}
        </Modal>
      </Content>
      <footer className="admin-footer">
        <span className="footer-powered">Powered by <strong>Bot Gate</strong></span>
        <div className="footer-status">
          <Tag icon={<CheckCircleFilled />} color="success">本机运行</Tag>
          <Tag>监听 · Loopback only</Tag>
          <Tag color={licenseStatus === 'active' ? 'success' : 'default'}>许可证 · {licenseLabel}</Tag>
          <Tag color={gatewayStatus.running ? 'success' : 'default'}>网关 · {gatewayStatus.running ? '运行中' : '已停止'}</Tag>
        </div>
        <span className="footer-version">v{systemInfo.version} · 更新于 {lastUpdated ? lastUpdated.toLocaleTimeString() : '加载中'}</span>
      </footer>
      <LogsPanel api={api} message={message} open={Boolean(logModal)} mode={logModal?.mode} filters={logModal?.filters} onChanged={refresh} onClose={() => setLogModal(null)} />
    </Layout>
  );
}

function SectionTitle({ icon, title, description }) {
  return <div className="section-title"><span className="section-icon">{icon}</span><span><strong>{title}</strong><small>{description}</small></span></div>;
}

createRoot(document.getElementById('root')).render(
  <ConfigProvider theme={{ token: { colorPrimary: '#149b73', colorInfo: '#149b73', borderRadius: 12, fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' }, components: { Card: { headerFontSize: 16 }, Button: { controlHeight: 38 } } }}>
    <App><AdminConsole /></App>
  </ConfigProvider>,
);
