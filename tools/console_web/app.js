/* 进程刷新 · 本地控制台 —— 前端逻辑（零外部依赖，可离线） */
'use strict';

const $ = (id) => document.getElementById(id);
const fmt = (n) => (n === null || n === undefined) ? '—' : Math.round(n).toLocaleString('zh-CN');
const mb = (n) => (n === null || n === undefined) ? '—' : (n >= 1024 ? (n / 1024).toFixed(1) + ' GB' : Math.round(n) + ' MB');

let lastStatus = null;
let autoTimer = null;

/* ---------------------------------------------------------------- toast */
function toast(msg, kind) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast ' + (kind || '');
  t.hidden = false;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.hidden = true; }, 2600);
}

/* ---------------------------------------------------------------- fetch */
async function getJSON(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
async function postJSON(url, obj) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(obj || {})
  });
  return r.json();
}

/* ---------------------------------------------------------------- 状态 */
function renderStatus(st) {
  lastStatus = st;
  const m = st.mem;

  $('m-avail').textContent = mb(m.avail_phys_mb);
  $('m-avail-hint').textContent = '共 ' + mb(m.total_phys_mb);
  $('m-load').textContent = m.load_pct + '%';
  $('m-load-hint').textContent = m.load_pct >= 90 ? '内存吃紧' : (m.load_pct >= 75 ? '偏高' : '正常');

  $('m-commit').textContent = mb(m.total_commit_mb - m.avail_commit_mb);
  $('m-commit-hint').textContent = '上限 ' + mb(m.total_commit_mb);

  const n = st.findings.length;
  $('m-anomaly').textContent = n;
  $('m-anomaly-hint').textContent = n ? '需人工判断' : '无异常候选';

  // 本套装占用（WorkBuddy + node + 相关家族）
  const su = st.suite || {};
  $('m-suite').textContent = mb(su.priv_mb);
  $('m-suite-hint').textContent =
    `${su.procs || 0} 个进程 · 占全系统 ${su.pct_of_used || 0}%`;
  const cSuite = $('card-suite');
  cSuite.classList.toggle('alert', (su.pct_of_used || 0) >= 35);
  cSuite.classList.toggle('warn', (su.pct_of_used || 0) >= 20 &&
                                 (su.pct_of_used || 0) < 35);

  $('m-handles').textContent = fmt(st.total_handles);
  $('m-handles-hint').textContent = '全系统合计';

  // 微信族占用（只读观察指标，不给「可回收量」）
  // 🔴 实测杀 WMPF 根进程 15 秒就被微信拉起 → 杀进程无效；
  //    trim 的 ABBA 差分净效应是可用内存 −0.68GB（负收益）→ 都不作为「可省多少」上报。
  const wc = st.wechat || {};
  $('m-wechat').textContent = wc.total_mb ? mb(wc.total_mb) : '未运行';
  $('m-wechat-hint').textContent = wc.total_mb
    ? `${wc.procs || 0} 个进程 · 其中小程序容器 ${wc.wmpf_mb || 0}MB（${wc.wmpf_procs || 0} 进程，占 ${wc.wmpf_pct || 0}%）`
    : '未检测到微信进程';
  const cWechat = $('card-wechat');
  cWechat.classList.toggle('alert', (wc.pct_of_used || 0) >= 10);
  cWechat.classList.toggle('warn', (wc.pct_of_used || 0) >= 5 &&
                                 (wc.pct_of_used || 0) < 10);

  $('m-proc').textContent = fmt(st.proc_count);
  $('m-proc-hint').textContent = st.degraded ? (st.degraded + ' 个权限受限') : '全部可读';

  // 卡片配色
  const cAvail = $('m-avail').closest('.card');
  cAvail.classList.toggle('alert', m.avail_phys_mb < 1024);
  cAvail.classList.toggle('warn', m.avail_phys_mb >= 1024 && m.avail_phys_mb < 2500);

  const cAnom = $('card-anomaly');
  cAnom.classList.toggle('alert', n > 0 && st.findings.some(f => f.kind === 'handle'));
  cAnom.classList.toggle('warn', n > 0 && !st.findings.some(f => f.kind === 'handle'));

  // 健康点
  const dot = $('health-dot');
  dot.className = 'dot ' + (n ? 'warn' : 'ok');

  $('sample-meta').textContent =
    '采样 ' + st.sample_ms + 'ms · ' + st.proc_count + ' 进程 · ' +
    new Date(st.ts * 1000).toLocaleTimeString('zh-CN');

  renderFindings(st);
  renderGroups(st);
  renderWechat(st);
}

function renderFindings(st) {
  const box = $('findings-body');
  $('findings-count').textContent = st.findings.length + ' 项';

  if (!st.findings.length) {
    box.innerHTML = '<p class="empty">没有命中异常判据。句柄与线程都在正常水位。</p>';
    return;
  }
  const cpu = st.cpu_delta || {};
  box.innerHTML = st.findings.map(f => {
    const cpuPct = cpu[String(f.pid)];
    const cpuTxt = cpuPct === undefined ? '' :
      (cpuPct > 1 ? '<span class="pill ok">在干活 ' + cpuPct + '%</span>'
                 : '<span class="pill warn">CPU ' + cpuPct + '%</span>');
    const kindTxt = f.kind === 'handle' ? '句柄异常' : '线程异常';
    return `<div class="find">
      <div class="ico">!</div>
      <div class="body">
        <div class="title">${f.name} <span class="pill info">${kindTxt}</span> ${cpuTxt}</div>
        <div class="desc">${f.reason} · 句柄 ${fmt(f.handles)} · 线程 ${fmt(f.threads)} · Private ${mb(f.priv_mb)} · pid ${f.pid}</div>
      </div>
    </div>`;
  }).join('');
}

function renderWechat(st) {
  const panel = $('panel-wechat');
  const wc = st.wechat || {};
  // 微信没在跑就不占版面
  panel.hidden = !wc.total_mb;
  if (!wc.total_mb) return;

  $('wechat-warn').hidden = (wc.wmpf_pct || 0) < 30;
  const body = wc.wmpf_mb + (wc.total_mb - wc.wmpf_mb);
  $('wechat-body').innerHTML =
    '<table><thead><tr><th>部分</th><th>进程数</th><th>Private</th><th>占微信</th></tr></thead><tbody>' +
    `<tr>
      <td class="name">小程序容器 <code>WeChatAppEx.exe</code></td>
      <td class="num">${wc.wmpf_procs || 0}</td>
      <td class="num">${mb(wc.wmpf_mb)}</td>
      <td class="num">${wc.wmpf_pct || 0}%</td>
    </tr>
    <tr>
      <td class="name">主进程 + 聊天 <code>Weixin.exe</code></td>
      <td class="num">${Math.max((wc.procs || 0) - (wc.wmpf_procs || 0) - (wc.ime_procs || 0), 0)}</td>
      <td class="num">${mb(body - (wc.ime_mb || 0))}</td>
      <td class="num">${wc.total_mb ? Math.round((body - (wc.ime_mb || 0)) / wc.total_mb * 100) : 0}%</td>
    </tr>
    <tr>
      <td class="name">微信输入法 <code>wetype_*</code></td>
      <td class="num">${wc.ime_procs || 0}</td>
      <td class="num">${mb(wc.ime_mb)}</td>
      <td class="num">${wc.total_mb ? Math.round((wc.ime_mb || 0) / wc.total_mb * 100) : 0}%</td>
    </tr>
    <tr>
      <td class="name"><b>合计</b></td>
      <td class="num"><b>${wc.procs || 0}</b></td>
      <td class="num"><b>${mb(wc.total_mb)}</b></td>
      <td class="num">100%</td>
    </tr>
    </tbody></table>`;
}

function renderGroups(st) {
  const box = $('groups-body');
  const gs = st.groups || [];
  $('groups-warn').hidden = gs.length === 0;

  if (!gs.length) {
    box.innerHTML = '<p class="empty">没有会话堆积。</p>';
    return;
  }
  const total = gs.reduce((a, g) => a + g.priv_mb, 0);
  box.innerHTML =
    `<p class="empty" style="padding:0 0 10px;color:var(--text-2)">共 ${gs.length} 组，
      合计占用 <b>${mb(total)}</b>。逐组明细：</p>` +
    '<table><thead><tr><th>入口脚本</th><th>实例数</th><th>Private 合计</th><th>平均</th></tr></thead><tbody>' +
    gs.map(g => `<tr>
      <td class="name">${g.script}</td>
      <td class="num">${g.count}</td>
      <td class="num">${mb(g.priv_mb)}</td>
      <td class="num dim">${mb(g.priv_mb / g.count)}</td>
    </tr>`).join('') +
    '</tbody></table>';
}

/* ---------------------------------------------------------------- 建议 */
async function loadRecipes() {
  const box = $('recipes-body');
  try {
    const d = await getJSON('/api/recipes');
    const rs = d.recipes || [];
    const hits = rs.filter(r => r.hit_now);
    $('recipes-count').textContent = hits.length + ' / ' + rs.length + ' 现在可动';

    box.innerHTML = rs.map(r => {
      const pill = r.hit_now
        ? '<span class="pill warn">现在命中</span>'
        : '<span class="pill">当前无命中</span>';
      const autoPill = r.auto
        ? '<span class="pill ok">已自动化</span>'
        : '<span class="pill danger">需手动确认</span>';
      const riskPill = r.risk === 'high'
        ? '<span class="pill danger">不可逆</span>'
        : '<span class="pill">可恢复</span>';
      return `<div class="recipe ${r.hit_now ? 'hit' : ''}">
        <div class="body">
          <div class="title">${r.name} ${pill} ${autoPill} ${riskPill}</div>
          <div class="cost"><b>代价：</b>${r.cost}</div>
          <div class="cost"><b>症状：</b>${r.symptom}</div>
          <div class="cmd">${r.apply_cmd_str}</div>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    box.innerHTML = '<p class="empty">建议加载失败：' + e.message + '</p>';
  }
}

/* ---------------------------------------------------------------- 任务 */
async function loadTasks() {
  const box = $('tasks-body');
  box.innerHTML = '<p class="empty">读取计划任务中…（首次约 6 秒，Windows 计划任务接口较慢）</p>';
  try {
    const d = await getJSON('/api/tasks');
    const ts = d.tasks || [];
    if (!ts.length) { box.innerHTML = '<p class="empty">没有读到任务。</p>'; return; }

    box.innerHTML = ts.map(t => {
      const trigKinds = (t.Triggers || []).map(x => x.Kind.replace('MSFT_Task', '').replace('Trigger', ''));
      const isDaily = trigKinds.includes('Daily');
      const isWeekly = trigKinds.includes('Weekly');
      const isLogon = trigKinds.includes('Logon');
      const at = (t.Triggers || []).map(x => x.At).filter(a => a && a !== '登录时')[0] || '05:10';

      const trigCtl = `
        <select class="trig-kind" data-task="${t.Name}">
          <option value="logon" ${isLogon && !isDaily && !isWeekly ? 'selected' : ''}>登录时</option>
          <option value="daily" ${isDaily ? 'selected' : ''}>每天</option>
          <option value="weekly" ${isWeekly ? 'selected' : ''}>每周一</option>
        </select>
        <input type="time" class="trig-at" data-task="${t.Name}" value="${at}" ${isLogon && !isDaily && !isWeekly ? 'disabled' : ''}>
        <button class="btn btn-sm trig-save" data-task="${t.Name}">保存触发</button>`;

      const killSwitch = `
        <label class="switch">
          <input type="checkbox" class="kill-sw" data-task="${t.Name}" ${t.has_kill_switch ? 'checked' : ''}>
          自动终止句柄泄漏进程
        </label>`;

      return `<div class="task">
        <div class="t-head">
          <span class="t-name">${t.Name}</span>
          <span class="pill ${t.LastResult === 0 ? 'ok' : 'warn'}">上次结果码 ${t.LastResult}</span>
        </div>
        <div class="t-grid">
          <div>上次运行：<b>${t.LastRun || '—'}</b></div>
          <div>下次运行：<b>${t.NextRun || '—'}</b></div>
          <div>状态：<b>${t.State}</b></div>
          <div>触发：<b>${trigKinds.join(' + ') || '—'}</b></div>
        </div>
        <div class="cmd" style="font-family:var(--mono);font-size:11px;color:var(--text-2);background:var(--surface-2);padding:5px 8px;border-radius:5px;margin-top:9px;word-break:break-all">${t.Arguments || ''}</div>
        <div class="t-actions">
          ${trigCtl}
          ${t.Name === 'StuckProcess-Cleanup' ? killSwitch : ''}
        </div>
        ${t.Name === 'StuckProcess-Cleanup'
          ? `<div class="cost" style="font-size:11px;color:var(--text-3);margin-top:6px">当前：${t.kill_switch_effect}</div>` : ''}
      </div>`;
    }).join('');

    bindTaskEvents();
  } catch (e) {
    box.innerHTML = '<p class="empty">任务加载失败：' + e.message + '</p>';
  }
}

function bindTaskEvents() {
  document.querySelectorAll('.trig-kind').forEach(sel => {
    sel.addEventListener('change', () => {
      const at = document.querySelector('.trig-at[data-task="' + sel.dataset.task + '"]');
      if (at) at.disabled = (sel.value === 'logon');
    });
  });
  document.querySelectorAll('.trig-save').forEach(btn => {
    btn.addEventListener('click', async () => {
      const name = btn.dataset.task;
      const kind = document.querySelector('.trig-kind[data-task="' + name + '"]').value;
      const at = document.querySelector('.trig-at[data-task="' + name + '"]').value;
      btn.disabled = true;
      try {
        const r = await postJSON('/api/task/trigger', { name, kind, at });
        if (r.ok) { toast('已更新 ' + name + ' 的触发器', 'ok'); loadTasks(); }
        else toast('失败：' + (r.error || '未知'), 'err');
      } catch (e) { toast('失败：' + e.message, 'err'); }
      btn.disabled = false;
    });
  });
  document.querySelectorAll('.kill-sw').forEach(cb => {
    cb.addEventListener('change', async () => {
      const name = cb.dataset.task;
      if (cb.checked) {
        const ok = confirm(
          '确认打开「自动终止句柄泄漏进程」？\n\n' +
          '这会让每天的定时任务真的杀掉微信等进程。\n' +
          '代价：丢失登录态、未发送消息、小程序容器（不可逆）。\n\n' +
          '点击「确定」继续。');
        if (!ok) { cb.checked = false; return; }
      }
      const args = cb.checked
        ? '"C:\\agent-hygiene\\tools\\stuck_process_cleanup.py" --apply --sample-sec 3 --kill-handle-leak'
        : '"C:\\agent-hygiene\\tools\\stuck_process_cleanup.py" --apply --sample-sec 3';
      try {
        const r = await postJSON('/api/task/args', {
          name, args, allow_kill_switch: cb.checked
        });
        if (r.ok) { toast(cb.checked ? '已开启（每天会自动终止）' : '已关闭（只报告不杀）', 'ok'); loadTasks(); }
        else { toast('失败：' + (r.error || '未知'), 'err'); cb.checked = !cb.checked; }
      } catch (e) { toast('失败：' + e.message, 'err'); cb.checked = !cb.checked; }
    });
  });
}

/* ------------------------------------------------- 系统定时任务全景 */
let invData = null;
let invFilter = 'attention';
let invQuery = '';
let invTimer = null;

/* 筛选口径：每个 chip 对应一个「集合谓词」 */
const INV_FILTERS = {
  attention: (t) => t.level === 'orphan' || t.level === 'review',
  review:    (t) => t.level === 'review',
  idle:      (t) => t.level === 'idle',
  orphan:    (t) => t.level === 'orphan',
  keep:      (t) => t.level === 'keep',
  disabled:  (t) => t.level === 'disabled',
  system:    (t) => t.level === 'system',
  all:       () => true,
};

const INV_LEVEL_LABEL = {
  system: '系统自带', keep: '在用', review: '待确认',
  idle: '闲置', orphan: '可关闭', disabled: '已禁用'
};

async function loadInventory() {
  const box = $('inv-body');
  const btn = $('btn-inv-refresh');
  if (btn) btn.disabled = true;
  if (!invData) box.innerHTML = '<p class="empty">全量扫描中…（约 3 秒）</p>';
  try {
    const d = await getJSON('/api/task-inventory');
    if (d.error) {
      box.innerHTML = '<p class="empty">采集失败：' + escapeHtml(d.error) + '</p>';
      return;
    }
    invData = d;
    $('inv-scan-time').textContent = '扫描于 ' + (d.scannedAt || '—');
    renderInventory();
  } catch (e) {
    box.innerHTML = '<p class="empty">加载失败：' + escapeHtml(e.message) + '</p>';
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderInventory() {
  const box = $('inv-body');
  if (!invData) return;
  const s = invData.summary || {};
  const tasks = invData.tasks || [];

  /* --- 摘要卡片（同时就是筛选器） ---
     🔴 6 个维度互不重叠，不做「需要关注 = orphan + review」这种求和卡：
        求和卡会跟子项数字重复（可关闭=0 时需要关注=待确认=8），
        反而让人以为有两个不同的 8。合计信息交给「任务总数」和 chips 的计数。 */
  const stats = [
    { k: 'orphan',    n: s.orphan || 0,    label: '可安全关闭', cls: 'orphan' },
    { k: 'review',    n: s.review || 0,    label: '待人工确认', cls: 'attention' },
    { k: 'idle',      n: s.idle || 0,      label: '闲置零开销', cls: 'idle' },
    { k: 'keep',      n: s.keep || 0,      label: '第三方在用', cls: 'keep' },
    { k: 'disabled',  n: s.disabled || 0,  label: '已禁用',     cls: '' },
    { k: 'system',    n: s.system || 0,    label: '系统自带',   cls: 'system' },
  ];
  $('inv-summary').innerHTML = stats.map(x =>
    `<div class="inv-stat ${x.cls} ${invFilter === x.k ? 'active' : ''}" data-inv-filter="${x.k}">
      <div class="n">${x.n}</div><div class="k">${x.label}</div>
    </div>`).join('');

  /* --- chip 计数 --- */
  document.querySelectorAll('#inv-filters .chip').forEach(c => {
    const f = c.dataset.filter;
    const n = tasks.filter(INV_FILTERS[f] || (() => false)).length;
    let cnt = c.querySelector('.c');
    if (!cnt) {
      cnt = document.createElement('span');
      cnt.className = 'c';
      c.appendChild(cnt);
    }
    cnt.textContent = n;
    c.classList.toggle('active', invFilter === f);
  });

  /* --- 列表 --- */
  const q = invQuery.trim().toLowerCase();
  let list = tasks.filter(INV_FILTERS[invFilter] || (() => false));
  if (q) {
    list = list.filter(t =>
      (t.name || '').toLowerCase().includes(q) ||
      (t.path || '').toLowerCase().includes(q) ||
      (t.exe || '').toLowerCase().includes(q) ||
      (t.comment || '').toLowerCase().includes(q));
  }

  if (!list.length) {
    box.innerHTML = '<p class="empty">这个筛选下没有任务。' +
      (q ? '（换个关键词，或清空搜索）' : '') + '</p>';
    bindInventoryEvents();
    return;
  }

  box.innerHTML = list.map(t => renderInvItem(t)).join('');
  bindInventoryEvents();
}

function renderInvItem(t) {
  const lv = t.level;
  const badge = `<span class="badge lv-${lv}">${INV_LEVEL_LABEL[lv] || lv}</span>`;
  const owner = t.owner === 'Microsoft'
    ? '<span class="badge">系统</span>'
    : '<span class="badge">第三方</span>';

  const reasons = (t.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');

  /* 身份说明：SYSTEM 不在桌面会话 */
  let userTxt = escapeHtml(t.user || '—');
  if (t.user && /SYSTEM/i.test(t.user)) userTxt += '（后台，不弹窗）';
  else if (t.user && /INTERACTIVE/i.test(t.user)) userTxt += '（桌面会话，可能弹窗）';

  const period = t.periodMin ? `每 ${t.periodMin} 分钟` : '—';

  /* 🔴 系统任务不给按钮；已禁用的第三方给「启用」 */
  let actions = '';
  if (t.owner !== 'Microsoft') {
    if (t.state === 'Disabled') {
      actions = `<button class="btn btn-sm inv-toggle" data-inv-name="${escapeHtml(t.path)}"
                   data-inv-enable="1">启用</button>
                 <span class="hint">当前已禁用，启用后按原配置运行</span>`;
    } else {
      actions = `<button class="btn btn-sm inv-toggle" data-inv-name="${escapeHtml(t.path)}"
                   data-inv-enable="0">禁用</button>
                 <span class="hint">禁用可随时恢复，配置不会丢</span>`;
    }
  } else {
    actions = '<span class="hint">系统自带任务不提供修改入口，避免误伤更新 / 证书等功能</span>';
  }

  return `<div class="inv-item level-${lv}">
    <div class="i-head">
      <span class="i-name">${escapeHtml(t.name)}</span>
      ${badge}${owner}
      <span class="i-path">${escapeHtml(t.path)}</span>
    </div>
    <div class="i-verdict">${escapeHtml(t.verdict || '')}</div>
    ${reasons ? `<ul class="i-reasons">${reasons}</ul>` : ''}
    <div class="i-meta">
      <div>状态：<b>${escapeHtml(t.state || '—')}</b></div>
      <div>上次运行：<b>${escapeHtml(t.lastRun || '—')}</b></div>
      <div>下次运行：<b>${escapeHtml(t.nextRun || '—')}</b></div>
      <div>频率：<b>${period}</b></div>
      <div>运行身份：<b>${userTxt}</b></div>
      <div>上次结果：<b>${t.result === null || t.result === undefined ? '—' : t.result}</b>
        （${escapeHtml(t.resultMeaning || '')}）</div>
    </div>
    ${t.exe ? `<div class="i-exe">${escapeHtml(t.exe)}${t.args ? ' ' + escapeHtml(t.args) : ''}</div>` : ''}
    <div class="i-actions">${actions}</div>
  </div>`;
}

function bindInventoryEvents() {
  document.querySelectorAll('[data-inv-filter]').forEach(el => {
    el.addEventListener('click', () => {
      invFilter = el.dataset.invFilter;
      renderInventory();
    });
  });
  document.querySelectorAll('#inv-filters .chip').forEach(c => {
    c.addEventListener('click', () => {
      invFilter = c.dataset.filter;
      renderInventory();
    });
  });
  document.querySelectorAll('.inv-toggle').forEach(btn => {
    btn.addEventListener('click', async () => {
      const name = btn.dataset.invName;
      const enable = btn.dataset.invEnable === '1';
      const act = enable ? '启用' : '禁用';
      if (!confirm(
        `确认${act}这个计划任务？\n\n${name}\n\n` +
        (enable
          ? '启用后它会按原有触发条件重新开始运行。'
          : '禁用是可逆的：任务配置、触发器、参数全部保留，随时可以启用回来。'))) {
        return;
      }
      btn.disabled = true;
      try {
        const r = await postJSON('/api/task-inventory/state',
          { name, enable, confirm: true });
        if (r.ok) {
          toast(`已${act}：${name.split('\\').pop()}`, 'ok');
          await loadInventory();
        } else {
          toast('失败：' + (r.error || '未知'), 'err');
          btn.disabled = false;
        }
      } catch (e) {
        toast('失败：' + e.message, 'err');
        btn.disabled = false;
      }
    });
  });
}

/* ---------------------------------------------------------------- 历史 */
async function loadHistory() {
  try {
    const d = await getJSON('/api/history');
    const reps = d.reports || [];
    const s = d.stats || {};
    // 🔴 「没有该字段」≠「值为 0」。旧报告根本没有 4b 章节，
    //    异常候选数是 null（缺证据），不是 0。趋势图必须画成断点，
    //    填 0 会在图上造一段假的「零异常」低谷。
    const withAvail = reps.filter(r => r.ts && r.avail_mb !== null && r.avail_mb !== undefined);
    const missingAnom = reps.filter(r => r.anomaly_candidates === null || r.anomaly_candidates === undefined).length;
    const missingZomb = reps.filter(r => r.zombie_handles === null || r.zombie_handles === undefined).length;

    $('hist-stats').textContent =
      `${s.audit_count || 0} 份体检 · ${s.kill_count || 0} 次终止 · ` +
      `${s.suggest_count || 0} 条建议 · ${s.skip_count || 0} 次跳过` +
      (missingAnom || missingZomb ? ` · ${missingAnom} 份缺异常判定 · ${missingZomb} 份缺僵尸分解` : '');

    drawLine('chart-avail', withAvail.map(r => ({ x: r.ts, y: r.avail_mb })), '可用内存', '#185fa5');
    drawLine('chart-zombie', reps.map(r => ({ x: r.ts, y: r.zombie_handles })), '僵尸句柄', '#a32d2d');
    drawLine('chart-anom', reps.map(r => ({ x: r.ts, y: r.anomaly_candidates })), '异常候选', '#a32d2d');

    const logs = (d.logs || []).slice(-40).reverse();
    $('log-body').innerHTML = logs.length ? logs.map(l =>
      `<div class="log ${l.action}">
        <span class="t">${(l.ts || '').slice(5, 16)}</span>
        <span class="m">${escapeHtml(l.msg)}</span>
      </div>`).join('')
      : '<p class="empty">还没有管控动作记录。</p>';
  } catch (e) {
    $('hist-stats').textContent = '历史加载失败';
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* 手写折线图（不引 CDN，离线可用）
   🔴 y 为 null 表示「这一期没有该指标」（旧报告没这个章节），
      必须画成断点而不是连成直线或填 0。 */
function drawLine(canvasId, points, label, color) {
  const cv = $(canvasId);
  if (!cv) return;
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = cv.clientHeight;
  cv.width = w * dpr; cv.height = h * dpr;
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const valid = points.filter(p => p.y !== null && p.y !== undefined && !isNaN(p.y));
  const gapCount = points.length - valid.length;

  if (valid.length < 2) {
    ctx.fillStyle = '#888780';
    ctx.font = '12px sans-serif';
    ctx.fillText(valid.length === 1
      ? '只有 1 个数据点（需要至少 2 次采样才能画趋势）'
      : '数据点不足（需要至少 2 次采样）', 12, h / 2);
    return;
  }
  const padL = 44, padR = 10, padT = 10, padB = 22;
  const xs = points.map(p => new Date(p.x.replace(/-/g, '/')).getTime());
  const ys = valid.map(p => p.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  let minY = Math.min(...ys), maxY = Math.max(...ys);
  if (minY === maxY) { minY -= 1; maxY += 1; }
  const pad = (maxY - minY) * 0.12;
  minY -= pad; maxY += pad;
  // 🔴 Y 轴下界不能是负数：这些指标（内存 MB / 句柄个数 / 异常候选数）
  //    天然非负，padding 把它推到 -244 会画出「负多少个句柄」的荒谬刻度。
  if (Math.min(...ys) >= 0) minY = Math.max(0, minY);

  const X = (v) => padL + (v - minX) / (maxX - minX || 1) * (w - padL - padR);
  const Y = (v) => padT + (1 - (v - minY) / (maxY - minY || 1)) * (h - padT - padB);

  // 网格 + Y 轴
  ctx.strokeStyle = 'rgba(0,0,0,.08)';
  ctx.fillStyle = '#888780';
  ctx.font = '10px sans-serif';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const v = minY + (maxY - minY) * i / 3;
    const y = Y(v);
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ctx.fillText(Math.round(v).toLocaleString('zh-CN'), padL - 6, y);
  }

  // 面积 + 线（null 处断开）
  let started = false;
  ctx.beginPath();
  points.forEach((p, i) => {
    if (p.y === null || p.y === undefined || isNaN(p.y)) { started = false; return; }
    const x = X(xs[i]), y = Y(p.y);
    if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();

  // 面积填充（按连续段分别闭合）
  let seg = [];
  const segs = [];
  points.forEach((p, i) => {
    if (p.y === null || p.y === undefined || isNaN(p.y)) {
      if (seg.length) segs.push(seg);
      seg = [];
    } else seg.push({ x: X(xs[i]), y: Y(p.y) });
  });
  if (seg.length) segs.push(seg);
  segs.forEach(sg => {
    if (sg.length < 2) return;
    ctx.beginPath();
    ctx.moveTo(sg[0].x, sg[0].y);
    sg.slice(1).forEach(pt => ctx.lineTo(pt.x, pt.y));
    ctx.lineTo(sg[sg.length - 1].x, h - padB);
    ctx.lineTo(sg[0].x, h - padB);
    ctx.closePath();
    ctx.fillStyle = color + '18';
    ctx.fill();
  });

  // 点（缺数据的点画空心圈做提示）
  points.forEach((p, i) => {
    const x = X(xs[i]);
    if (p.y === null || p.y === undefined || isNaN(p.y)) {
      ctx.beginPath();
      ctx.arc(x, h - padB, 2, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0,0,0,.18)';
      ctx.lineWidth = 1;
      ctx.stroke();
      return;
    }
    ctx.beginPath();
    ctx.arc(x, Y(p.y), 2.5, 0, Math.PI * 2);
    ctx.fillStyle = color; ctx.fill();
  });

  // X 轴首尾时间
  ctx.fillStyle = '#888780';
  ctx.font = '10px sans-serif';
  ctx.textBaseline = 'top';
  ctx.textAlign = 'left';
  ctx.fillText(points[0].x.slice(5, 16), padL, h - padB + 6);
  ctx.textAlign = 'right';
  ctx.fillText(points[points.length - 1].x.slice(5, 16), w - padR, h - padB + 6);

  if (gapCount) {
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillStyle = '#a08a5a';
    ctx.fillText(`${gapCount} 期缺该指标（图上断开）`, (padL + w - padR) / 2, 2);
  }
}

/* ---------------------------------------------------------------- 主循环 */
async function refreshAll() {
  $('health-dot').className = 'dot pulse';
  try {
    const st = await getJSON('/api/status');
    renderStatus(st);
    $('health-dot').className = 'dot ' + (st.findings.length ? 'warn' : 'ok');
  } catch (e) {
    $('health-dot').className = 'dot danger';
    toast('状态加载失败：' + e.message, 'err');
  }
  loadRecipes();
  loadHistory();
  // 🔴 计划任务单独异步拉：实测首次要 6.3 秒（Windows 计划任务接口慢），
  //    串在这里会把整页首屏都卡住 6 秒。任务面板自己显示加载态。
  loadTasks();
  // 🔴 全量任务盘点也要 2.6 秒，同样不串进首屏；独立低频刷新。
  loadInventory();
}

function startAuto() {
  if (autoTimer) clearInterval(autoTimer);
  autoTimer = setInterval(() => {
    getJSON('/api/status').then(st => {
      renderStatus(st);
      $('health-dot').className = 'dot ' + (st.findings.length ? 'warn' : 'ok');
    }).catch(() => {});
  }, 10000);

  // 🔴 盘点接口单次要 2.6 秒（schtasks 全量扫描），不能跟 10 秒的
  //    状态轮询同频 —— 后端已有 60 秒缓存，前端再压到 60 秒即可。
  if (invTimer) clearInterval(invTimer);
  invTimer = setInterval(loadInventory, 60000);
}

$('btn-refresh').addEventListener('click', refreshAll);
$('btn-tasks').addEventListener('click', loadTasks);

const _invSearch = $('inv-search');
if (_invSearch) {
  _invSearch.addEventListener('input', () => {
    invQuery = _invSearch.value;
    renderInventory();
  });
}
const _btnInvRefresh = $('btn-inv-refresh');
if (_btnInvRefresh) _btnInvRefresh.addEventListener('click', loadInventory);

refreshAll();
startAuto();
