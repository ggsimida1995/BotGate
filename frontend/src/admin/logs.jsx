import React, { useEffect, useState } from 'react';
import {
  Button,
  Descriptions,
  DatePicker,
  Drawer,
  Empty,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Table,
  Tag,
  Typography,
} from 'antd';
import { FileSearchOutlined, WarningOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';

const { Text } = Typography;
const { RangePicker } = DatePicker;
const defaultLogQuery = { page: 1, page_size: 20 };

function recentHourRange() {
  const to = Math.floor(Date.now() / 1000);
  return { from: to - 60 * 60, to };
}

function localDateTime(timestamp) {
  return timestamp ? dayjs(timestamp * 1000) : undefined;
}

function timestampValue(value) {
  if (!value) return undefined;
  const milliseconds = typeof value?.valueOf === 'function' ? value.valueOf() : new Date(value).getTime();
  const timestamp = Math.floor(milliseconds / 1000);
  return Number.isFinite(timestamp) ? timestamp : undefined;
}

function normalizeLogQuery(values, base = {}) {
  const { time_range: timeRange, ...formValues } = values;
  const query = { ...defaultLogQuery, ...base, ...formValues };
  return {
    ...query,
    from: Array.isArray(timeRange)
      ? timestampValue(timeRange[0])
      : (formValues.from === '' ? undefined : query.from),
    to: Array.isArray(timeRange)
      ? timestampValue(timeRange[1])
      : (formValues.to === '' ? undefined : query.to),
  };
}

function queryString(query) {
  const params = new URLSearchParams();
  Object.entries(query || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') params.set(key, value);
  });
  const value = params.toString();
  return value ? `?${value}` : '';
}

function formatTime(value) {
  return value ? new Date(value * 1000).toLocaleString() : '-';
}

function statusTag(status) {
  const color = status >= 500 ? 'red' : status >= 400 ? 'orange' : status >= 300 ? 'blue' : 'green';
  return <Tag color={color}>{status}</Tag>;
}

export default function LogsPanel({ api, message, open, mode, filters, onChanged, onClose }) {
  const [requestLogs, setRequestLogs] = useState([]);
  const [requestMeta, setRequestMeta] = useState({ total: 0, page: 1, page_size: 20 });
  const [interceptions, setInterceptions] = useState([]);
  const [interceptionMeta, setInterceptionMeta] = useState({ total: 0, page: 1, page_size: 20 });
  const [bans, setBans] = useState([]);
  const [challenges, setChallenges] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [selectedInterception, setSelectedInterception] = useState(null);
  const [requestFilters, setRequestFilters] = useState(defaultLogQuery);
  const [interceptionFilters, setInterceptionFilters] = useState(defaultLogQuery);
  const [requestFilterForm] = Form.useForm();
  const [interceptionFilterForm] = Form.useForm();

  function setTimeFields(form, query) {
    const { from, to, ...rest } = query;
    form.setFieldsValue({
      ...rest,
      time_range: from || to ? [localDateTime(from), localDateTime(to)] : undefined,
    });
  }

  async function loadRequests(query = requestFilters) {
    setLoading(true);
    try {
      const body = await api(`/api/requests${queryString(query)}`);
      setRequestFilters(query);
      setRequestLogs(body.items || []);
      setRequestMeta({ total: body.total || 0, page: body.page || 1, page_size: body.page_size || 20 });
    } catch (cause) {
      message.error(cause.message);
    } finally {
      setLoading(false);
    }
  }

  async function loadInterceptions(query = interceptionFilters) {
    setLoading(true);
    try {
      const body = await api(`/api/interceptions${queryString(query)}`);
      setInterceptionFilters(query);
      setInterceptions(body.items || []);
      setInterceptionMeta({ total: body.total || 0, page: body.page || 1, page_size: body.page_size || 20 });
    } catch (cause) {
      message.error(cause.message);
    } finally {
      setLoading(false);
    }
  }

  function clearLogs(type) {
    const isRequests = type === 'requests';
    const query = isRequests ? requestFilters : interceptionFilters;
    Modal.confirm({
      title: isRequests ? '清空请求记录' : '清空拦截记录',
      content: '将删除当前时间和筛选条件范围内的记录，此操作不可恢复。',
      okText: '确认清空',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        try {
          const body = await api(`/api/${isRequests ? 'requests' : 'interceptions'}/clear`, {
            method: 'POST',
            body: JSON.stringify(query),
          });
          message.success(`已清空 ${body.deleted || 0} 条记录`);
          if (isRequests) await loadRequests(query);
          else await loadInterceptions(query);
          await onChanged?.();
        } catch (cause) {
          message.error(cause.message);
        }
      },
    });
  }

  async function loadSimpleRecords(path, setter) {
    setLoading(true);
    try {
      const body = await api(path);
      setter(body.items || body.bans || []);
    } catch (cause) {
      message.error(cause.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!open) return;
    setSelectedRequest(null);
    setSelectedInterception(null);
    const timeRange = recentHourRange();
    const initialQuery = { ...defaultLogQuery, ...timeRange, ...(filters || {}) };
    if (mode === 'requests') {
      setTimeFields(requestFilterForm, initialQuery);
      loadRequests(initialQuery);
    }
    if (mode === 'interceptions') {
      setTimeFields(interceptionFilterForm, initialQuery);
      loadInterceptions(initialQuery);
    }
    if (mode === 'bans') loadSimpleRecords('/api/bans', setBans);
    if (mode === 'challenges') loadSimpleRecords('/api/challenges', setChallenges);
  }, [open, mode, filters]);

  const requestColumns = [
    { title: '时间', dataIndex: 'timestamp', key: 'timestamp', width: 170, render: formatTime },
    { title: 'IP', dataIndex: 'remote_ip', key: 'remote_ip', width: 130 },
    { title: '站点', dataIndex: 'host', key: 'host', width: 150, ellipsis: true },
    { title: '请求', key: 'request', render: (_, row) => <span><Tag>{row.method}</Tag><Text code>{row.path}</Text></span>, ellipsis: true },
    { title: '状态', dataIndex: 'status', key: 'status', width: 75, render: statusTag },
    { title: '结果', key: 'result', width: 110, render: (_, row) => row.blocked ? <Tag color="error">已拦截</Tag> : <Tag color="success">已放行</Tag> },
    { title: '验证', dataIndex: 'verified', key: 'verified', width: 75, render: (value) => value ? <Tag color="success">通过</Tag> : <Tag>未验证</Tag> },
    { title: '风险', dataIndex: 'risk_score', key: 'risk_score', width: 65 },
    { title: '耗时', dataIndex: 'latency_ms', key: 'latency_ms', width: 70, render: (value) => `${value} ms` },
    { title: '详情', key: 'detail', width: 65, render: (_, row) => <Button type="link" onClick={() => setSelectedRequest(row)}>查看</Button> },
  ];
  const interceptionColumns = [
    { title: '时间', dataIndex: 'timestamp', key: 'timestamp', width: 170, render: formatTime },
    { title: 'IP', dataIndex: 'remote_ip', key: 'remote_ip', width: 130 },
    { title: '站点', dataIndex: 'host', key: 'host', width: 150, ellipsis: true },
    { title: '事件', dataIndex: 'event_type', key: 'event_type', width: 150, render: (value) => <Tag color="orange">{value}</Tag> },
    { title: '路径', dataIndex: 'path', key: 'path', ellipsis: true },
    { title: '动作', dataIndex: 'action', key: 'action', width: 160 },
    { title: '风险', dataIndex: 'risk_score', key: 'risk_score', width: 65 },
    { title: '详情', key: 'detail', width: 65, render: (_, row) => <Button type="link" onClick={() => setSelectedInterception(row)}>查看</Button> },
  ];
  const banColumns = [
    { title: 'IP', dataIndex: 'ip', key: 'ip' },
    { title: '原因', dataIndex: 'reason', key: 'reason' },
    { title: '来源', dataIndex: 'source', key: 'source' },
    { title: '到期时间', dataIndex: 'expires_at', key: 'expires_at', render: formatTime },
  ];
  const challengeColumns = [
    { title: '站点', dataIndex: 'site', key: 'site' },
    { title: 'IP', dataIndex: 'remote_ip', key: 'remote_ip' },
    { title: '开始时间', dataIndex: 'issued_at', key: 'issued_at', render: formatTime },
    { title: '过期时间', dataIndex: 'expires_at', key: 'expires_at', render: formatTime },
    { title: '尝试次数', dataIndex: 'attempts', key: 'attempts' },
  ];

  const requestContent = (
    <>
      <Form form={requestFilterForm} layout="inline" onFinish={(values) => loadRequests(normalizeLogQuery(values, filters || recentHourRange()))} className="inline-form log-filter-form">
        <Form.Item name="search"><Input placeholder="聚合搜索：站点、IP、路径、方法、原因、User-Agent" allowClear /></Form.Item>
        <Form.Item name="status"><InputNumber min={100} max={599} placeholder="状态码" /></Form.Item>
        <Form.Item name="blocked"><Select allowClear placeholder="访问结果" options={[{ value: true, label: '仅拦截' }, { value: false, label: '仅放行' }]} /></Form.Item>
        <Form.Item name="time_range"><RangePicker showTime format="YYYY-MM-DD HH:mm" placeholder={['开始时间', '结束时间']} /></Form.Item>
        <Button htmlType="submit" type="primary">筛选</Button>
        <Button onClick={() => { const query = { ...defaultLogQuery, ...recentHourRange(), ...(filters || {}) }; requestFilterForm.resetFields(); setTimeFields(requestFilterForm, query); loadRequests(query); }}>重置</Button>
        <Button danger onClick={() => clearLogs('requests')}>清空日志</Button>
      </Form>
      <Table rowKey="id" size="small" scroll={{ x: 1100, y: 420 }} loading={loading} columns={requestColumns} dataSource={requestLogs}
        pagination={{ current: requestMeta.page, pageSize: requestMeta.page_size, total: requestMeta.total, showSizeChanger: true, showTotal: (total) => `共 ${total} 条` }}
        onChange={(pagination) => loadRequests({ ...requestFilters, page: pagination.current, page_size: pagination.pageSize })} />
    </>
  );
  const interceptionContent = (
    <>
      <Form form={interceptionFilterForm} layout="inline" onFinish={(values) => loadInterceptions(normalizeLogQuery(values, filters || recentHourRange()))} className="inline-form log-filter-form">
        <Form.Item name="search"><Input placeholder="聚合搜索：站点、IP、路径、事件、动作、详情" allowClear /></Form.Item>
        <Form.Item name="event_type"><Select allowClear placeholder="事件类型" options={[{ value: 'challenge_failure', label: '验证失败' }, { value: 'rate_limit', label: '频率限制' }, { value: 'ban', label: '封禁' }]} /></Form.Item>
        <Form.Item name="time_range"><RangePicker showTime format="YYYY-MM-DD HH:mm" placeholder={['开始时间', '结束时间']} /></Form.Item>
        <Button htmlType="submit" type="primary">筛选</Button>
        <Button onClick={() => { const query = { ...defaultLogQuery, ...recentHourRange(), ...(filters || {}) }; interceptionFilterForm.resetFields(); setTimeFields(interceptionFilterForm, query); loadInterceptions(query); }}>重置</Button>
        <Button danger onClick={() => clearLogs('interceptions')}>清空日志</Button>
      </Form>
      <Table rowKey="id" size="small" scroll={{ x: 1050, y: 420 }} loading={loading} columns={interceptionColumns} dataSource={interceptions}
        pagination={{ current: interceptionMeta.page, pageSize: interceptionMeta.page_size, total: interceptionMeta.total, showSizeChanger: true, showTotal: (total) => `共 ${total} 条` }}
        onChange={(pagination) => loadInterceptions({ ...interceptionFilters, page: pagination.current, page_size: pagination.pageSize })} />
    </>
  );

  const title = mode === 'requests' ? '请求记录' : mode === 'interceptions' ? '拦截记录' : mode === 'bans' ? '活跃封禁' : '进行中验证';
  const icon = mode === 'interceptions' ? <WarningOutlined /> : <FileSearchOutlined />;
  const content = mode === 'requests' ? requestContent
    : mode === 'interceptions' ? interceptionContent
      : mode === 'bans' ? <Table rowKey="ip" size="small" scroll={{ y: 420 }} loading={loading} columns={banColumns} dataSource={bans} pagination={{ pageSize: 10, showTotal: (total) => `共 ${total} 条` }} />
        : challenges.length ? <Table rowKey="id" size="small" scroll={{ y: 420 }} loading={loading} columns={challengeColumns} dataSource={challenges} pagination={false} /> : <Empty description="当前没有进行中的验证" />;

  return (
    <>
      <Modal className="records-modal" title={<span>{icon} {title}</span>} open={open} centered onCancel={onClose} footer={null} width={mode === 'requests' ? 1180 : 1080} destroyOnClose>
        {content}
      </Modal>
      <Drawer title="请求详情" open={Boolean(selectedRequest)} onClose={() => setSelectedRequest(null)} width={480}>
        {selectedRequest && <Descriptions column={1} bordered size="small">
          <Descriptions.Item label="时间">{formatTime(selectedRequest.timestamp)}</Descriptions.Item>
          <Descriptions.Item label="IP">{selectedRequest.remote_ip}</Descriptions.Item>
          <Descriptions.Item label="站点">{selectedRequest.host}</Descriptions.Item>
          <Descriptions.Item label="请求">{selectedRequest.method} {selectedRequest.path}</Descriptions.Item>
          <Descriptions.Item label="状态">{statusTag(selectedRequest.status)}</Descriptions.Item>
          <Descriptions.Item label="结果">{selectedRequest.blocked ? '已拦截' : '已放行'}</Descriptions.Item>
          <Descriptions.Item label="验证 Cookie">{selectedRequest.verified ? '有效' : '无效或不存在'}</Descriptions.Item>
          <Descriptions.Item label="拦截原因">{selectedRequest.reason || '-'}</Descriptions.Item>
          <Descriptions.Item label="风险分">{selectedRequest.risk_score}</Descriptions.Item>
          <Descriptions.Item label="响应耗时">{selectedRequest.latency_ms} ms</Descriptions.Item>
          <Descriptions.Item label="User-Agent">{selectedRequest.user_agent || '-'}</Descriptions.Item>
        </Descriptions>}
      </Drawer>
      <Drawer title="拦截详情" open={Boolean(selectedInterception)} onClose={() => setSelectedInterception(null)} width={480}>
        {selectedInterception && <Descriptions column={1} bordered size="small">
          <Descriptions.Item label="时间">{formatTime(selectedInterception.timestamp)}</Descriptions.Item>
          <Descriptions.Item label="IP">{selectedInterception.remote_ip}</Descriptions.Item>
          <Descriptions.Item label="站点">{selectedInterception.host || '-'}</Descriptions.Item>
          <Descriptions.Item label="路径">{selectedInterception.path || '-'}</Descriptions.Item>
          <Descriptions.Item label="事件类型">{selectedInterception.event_type}</Descriptions.Item>
          <Descriptions.Item label="执行动作">{selectedInterception.action}</Descriptions.Item>
          <Descriptions.Item label="风险分">{selectedInterception.risk_score}</Descriptions.Item>
          <Descriptions.Item label="脱敏详情">{selectedInterception.details_redacted || '-'}</Descriptions.Item>
        </Descriptions>}
      </Drawer>
    </>
  );
}
