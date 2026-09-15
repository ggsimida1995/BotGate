import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Alert, Button, Checkbox, ConfigProvider, Progress, Typography } from 'antd';
import 'antd/dist/reset.css';
import './style.css';

const { Title, Paragraph, Text } = Typography;

function fnv1a32(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) hash = Math.imul(hash ^ value.charCodeAt(index), 16777619) >>> 0;
  return hash;
}

function hasZeroBits(value, bits) {
  return bits === 0 || (value >>> (32 - bits)) === 0;
}

function Challenge() {
  const [challenge, setChallenge] = useState(null);
  const [started, setStarted] = useState(false);
  const [status, setStatus] = useState('请勾选下方复选框开始验证');
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const raw = document.getElementById('bot-gate-challenge')?.textContent;
    try {
      const value = JSON.parse(raw);
      if (!value?.id || !value?.nonce || !value?.signature || !value?.site) throw new Error();
      setChallenge(value);
    } catch {
      setError('Challenge 参数无效，请刷新页面重试。');
    }
  }, []);

  async function run() {
    if (!challenge) return;
    setStarted(true);
    setError('');
    setStatus('正在检查浏览器环境，请稍候…');
    try {
      const startedAt = performance.now();
      for (let counter = 0; ; counter += 1) {
        if (hasZeroBits(fnv1a32(`${challenge.id}:${challenge.nonce}:${counter}`), challenge.difficulty)) {
          const remainingDelay = Math.max(0, 650 - (performance.now() - startedAt));
          if (remainingDelay) await new Promise((resolve) => window.setTimeout(resolve, remainingDelay));
          setProgress(100);
          setStatus('校验完成，正在建立会话…');
          const response = await fetch(`${challenge.verify_path}/submit`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ challenge_id: challenge.id, counter, signature: challenge.signature }),
          });
          const body = await response.json().catch(() => ({}));
          if (!response.ok) throw new Error(body.message || 'Challenge 验证失败');
          window.location.assign(body.redirect || '/');
          return;
        }
        if (counter % 1000 === 0) {
          setProgress(Math.min(95, (counter % 10000) / 100));
          await new Promise(requestAnimationFrame);
        }
      }
    } catch (cause) {
      setError(cause.message);
      setStarted(false);
    }
  }

  return (
    <main className="challenge-shell">
      <section className="challenge-panel">
        <div className="brand-row"><span className="brand-mark">BG</span><span className="brand-name">{challenge?.site || 'Bot Gate'}</span></div>
        <Title level={1}>正在进行安全验证</Title>
        <Paragraph className="lead">本站使用安全服务防护恶意自动程序。在验证您不是自动程序期间，将显示此页面。</Paragraph>
        {error && <Alert type="error" showIcon message={error} />}
        {!error && !started && <Button className="human-check" type="default" onClick={run} disabled={!challenge}><Checkbox checked={false} tabIndex={-1} /><span>请验证您是真人</span><span className="provider"><strong>BOT GATE</strong><small>隐私 · 帮助</small></span></Button>}
        {!error && started && <div className="checking"><Progress percent={progress} showInfo={false} status="active" /><span>{status}</span></div>}
        <Text className="footer-note">验证完成后将自动返回原页面。</Text>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(
  <ConfigProvider theme={{ token: { colorPrimary: '#1769aa', borderRadius: 8 } }}><Challenge /></ConfigProvider>,
);
