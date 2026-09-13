(() => {
  const state = { workspaceId: '', apiKey: '', bearer: '', actor: '', changes: [] };
  const sensitive = path => /(identity|auth|session|role|egress|secret|payment|database|github|mcp|approval|quota|workload|sign|trust)/i.test(path || '');
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));

  function headers() {
    const out = { 'X-TrustKernel-Key': state.apiKey };
    if (state.bearer) out.Authorization = `Bearer ${state.bearer}`;
    else if (state.actor) out['X-TrustKernel-Actor'] = state.actor;
    return out;
  }

  function setStatus(text, tone = '') {
    const pill = document.getElementById('governanceSessionState');
    if (!pill) return;
    pill.textContent = text;
    pill.className = `pill governance-session-pill ${tone}`.trim();
  }

  function setRail(change) {
    const set = (id, status) => {
      const el = document.getElementById(id);
      if (el) el.className = `governance-step ${status || ''}`.trim();
    };
    if (!change) return;
    const status = String(change.status || '').toUpperCase();
    set('govAuthor', 'done');
    set('govReview', 'done');
    if (status === 'REJECTED') {
      set('govFourEyes', 'blocked'); set('govActivate', 'blocked'); set('govEvidence', '');
      return;
    }
    if (status === 'ACTIVATED') {
      set('govFourEyes', 'done'); set('govActivate', 'done'); set('govEvidence', 'active');
      return;
    }
    set('govFourEyes', 'active'); set('govActivate', ''); set('govEvidence', '');
  }

  function requestCard(change) {
    const approvals = Number(change.approval_count || 0);
    const required = Math.max(1, Number(change.required_approvals || 1));
    const pct = Math.min(100, Math.round((approvals / required) * 100));
    const diff = Array.isArray(change.diff) ? change.diff : [];
    const sensitiveCount = diff.filter(item => sensitive(item.path)).length;
    const pending = String(change.status).toUpperCase() === 'PENDING';
    const votes = Array.isArray(change.votes) ? change.votes : [];
    return `<article class="governance-request">
      <div class="governance-request-head"><div><span class="governance-status ${esc(String(change.status).toLowerCase())}">${esc(change.status)}</span><b>${esc(change.profile)} · ${esc(change.bundle_id)}</b><small>${esc(change.id)} · requested by ${esc(change.requested_by)}</small></div><span class="pill">${sensitiveCount} sensitive</span></div>
      <div class="governance-progress"><span style="width:${pct}%"></span></div>
      <div class="governance-meta"><span>Approvals <b>${approvals}/${required}</b></span><span>Group <b>${esc(change.approval_group)}</b></span><span>Four-eyes <b>${change.four_eyes ? 'ON' : 'OFF'}</b></span><span>Votes <b>${votes.length}</b></span></div>
      <div class="governance-diff-preview">${diff.slice(0, 4).map(item => `<div><code>${esc(item.path)}</code><span>${sensitive(item.path) ? 'SECURITY-SENSITIVE' : 'CONTROL'}</span></div>`).join('') || '<div class="empty">No semantic control drift recorded.</div>'}</div>
      ${pending ? `<div class="governance-actions"><button class="approve" onclick="window.votePolicyGovernance('${esc(change.id)}','APPROVE')">Approve</button><button class="reject" onclick="window.votePolicyGovernance('${esc(change.id)}','REJECT')">Reject</button></div>` : ''}
    </article>`;
  }

  function render(changes) {
    const target = document.getElementById('governanceRequests');
    if (!target) return;
    const items = [...changes].sort((a, b) => Number(b.created_at || 0) - Number(a.created_at || 0));
    target.innerHTML = items.length ? items.map(requestCard).join('') : '<div class="empty">No governed policy-change requests exist for this workspace yet.</div>';
    setRail(items[0]);
    const pending = items.filter(item => String(item.status).toUpperCase() === 'PENDING').length;
    document.getElementById('governancePendingCount').textContent = String(pending);
    document.getElementById('governanceActivatedCount').textContent = String(items.filter(item => String(item.status).toUpperCase() === 'ACTIVATED').length);
    document.getElementById('governanceRejectedCount').textContent = String(items.filter(item => String(item.status).toUpperCase() === 'REJECTED').length);
    document.getElementById('governanceFourEyesCount').textContent = String(items.filter(item => item.four_eyes).length);
  }

  async function loadGovernance() {
    const workspaceId = document.getElementById('governanceWorkspace').value.trim();
    const apiKey = document.getElementById('governanceApiKey').value.trim();
    const bearer = document.getElementById('governanceBearer').value.trim();
    const actor = document.getElementById('governanceActor').value.trim().toLowerCase();
    if (!workspaceId || !apiKey || (!bearer && !actor)) {
      setStatus('WORKSPACE + KEY + PRINCIPAL REQUIRED', 'degraded-pill');
      return;
    }
    Object.assign(state, { workspaceId, apiKey, bearer, actor });
    setStatus('CONNECTING…');
    try {
      const response = await fetch(`/api/workspaces/${encodeURIComponent(workspaceId)}/policy-changes`, { headers: headers() });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
      state.changes = Array.isArray(body) ? body : [];
      render(state.changes);
      setStatus(`CONNECTED · ${state.changes.length} REQUESTS`, 'ready-pill');
    } catch (error) {
      setStatus(`ACCESS DENIED · ${String(error.message || error).slice(0, 70)}`, 'degraded-pill');
    }
  }

  async function votePolicyGovernance(requestId, decision) {
    if (!state.workspaceId || !state.apiKey) return;
    setStatus(`${decision}…`);
    try {
      const response = await fetch(`/api/workspaces/${encodeURIComponent(state.workspaceId)}/policy-changes/${encodeURIComponent(requestId)}/vote/${decision}`, { method: 'POST', headers: headers() });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
      await loadGovernance();
    } catch (error) {
      setStatus(`VOTE FAILED · ${String(error.message || error).slice(0, 72)}`, 'degraded-pill');
    }
  }

  function install() {
    const studio = document.getElementById('policy-studio');
    const grid = studio?.querySelector('.studio-grid');
    if (!studio || !grid || document.getElementById('governanceConsole')) return;
    const console = document.createElement('div');
    console.id = 'governanceConsole';
    console.className = 'governance-console';
    console.innerHTML = `<div class="governance-console-head"><div><p class="eyebrow">LIVE GOVERNANCE SESSION</p><h3>Reviewer quorum + activation state</h3><p>Credentials remain in memory only. Use a signed member session in production; the legacy actor field exists only for development environments where that compatibility path is enabled.</p></div><span id="governanceSessionState" class="pill governance-session-pill">NOT CONNECTED</span></div>
      <div class="governance-connect"><label>Workspace ID<input id="governanceWorkspace" autocomplete="off" placeholder="ws_…"></label><label>Workspace API key<input id="governanceApiKey" type="password" autocomplete="off" placeholder="tk_…"></label><label>Bearer member session<input id="governanceBearer" type="password" autocomplete="off" placeholder="preferred in production"></label><label>Legacy actor email<input id="governanceActor" type="email" autocomplete="off" placeholder="dev only"></label><button class="judge-button" id="governanceConnectButton">LOAD GOVERNANCE</button></div>
      <div class="governance-kpis"><div><span>Pending</span><b id="governancePendingCount">0</b></div><div><span>Activated</span><b id="governanceActivatedCount">0</b></div><div><span>Rejected</span><b id="governanceRejectedCount">0</b></div><div><span>Four-eyes</span><b id="governanceFourEyesCount">0</b></div></div>
      <div id="governanceRequests" class="governance-requests"><div class="empty">Connect a workspace to inspect real policy-change requests and reviewer quorum state.</div></div>`;
    studio.insertBefore(console, grid);
    document.getElementById('governanceConnectButton').addEventListener('click', loadGovernance);
  }

  window.loadPolicyGovernance = loadGovernance;
  window.votePolicyGovernance = votePolicyGovernance;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install);
  else install();
})();
