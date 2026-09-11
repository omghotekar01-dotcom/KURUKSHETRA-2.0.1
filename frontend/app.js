let currentAuditId = null;
const $ = id => document.getElementById(id);

async function loadScenarios(){
  const data = await fetch('/api/scenarios').then(r=>r.json());
  $('scenarioList').innerHTML = data.map((s,i)=>`<button class="scenario" onclick="runScenario('${s.id}','${s.title.replaceAll("'", "\\'")}')"><div class="scenario-line"><b>${String(i+1).padStart(2,'0')} · ${s.title}</b><span class="category ${s.category}">${s.category}</span></div><small>Run through identity → policy → provenance → repair/approval → evidence</small></button>`).join('');
}

async function loadSystem(){
  const [status, agents, policy, audit, ready, history, capabilities, oidc] = await Promise.all([
    fetch('/api/status').then(r=>r.json()),
    fetch('/api/agents').then(r=>r.json()),
    fetch('/api/policies/enterprise-default').then(r=>r.json()),
    fetch('/api/audit/verify').then(r=>r.json()),
    fetch('/ready').then(r=>r.json()),
    fetch('/api/policy-bundles/enterprise-default').then(r=>r.json()),
    fetch('/api/v13/capabilities').then(r=>r.json()),
    fetch('/api/v13/identity/oidc/status').then(r=>r.json()),
  ]);
  $('agentsCount').textContent = status.agents;
  $('readinessPill').textContent = ready.ready ? 'READY' : 'DEGRADED';
  $('readinessPill').className = `pill ${ready.ready ? 'ready-pill' : 'degraded-pill'}`;
  const posture = ready.security_posture || {};
  $('readinessSummary').innerHTML = Object.entries(ready.checks || {}).map(([name,value])=>`<div class="policy-row"><span>${name.replaceAll('_',' ')}</span><b>${value ? 'PASS' : 'FAIL'}</b></div>`).join('') + `<div class="policy-row"><span>Environment</span><b>${String(posture.environment || 'development').toUpperCase()}</b></div><div class="policy-row"><span>Posture warnings</span><b>${(posture.warnings || []).length}</b></div><div class="policy-row"><span>Tenant boundary</span><b>WORKSPACE-SCOPED</b></div><div class="policy-row"><span>Gateway quotas</span><b>ENFORCED</b></div>`;
  $('policyHistory').innerHTML = history.length ? history.slice(0,5).map(b=>`<div class="policy-row"><span>v${b.version} · ${String(b.sha256).slice(0,10)}…</span><b>${b.signature_valid ? 'SIGNED' : 'INVALID'}</b></div>`).join('') : '<div class="empty">No immutable bundle published yet. Runtime currently uses the reviewed filesystem baseline.</div>';
  $('incidentMetric').textContent = status.open_incidents ?? 0;
  $('auditIntegrity').textContent = audit.valid ? `Ledger verified · ${audit.entries} entries` : 'Ledger integrity error';
  $('agentList').innerHTML = agents.map(a=>`<div class="agent-card"><div><b>${a.name}</b><small>${a.id} · ${a.owner}</small></div><span>${a.allowed_tools.join(' · ')}</span></div>`).join('');
  const destructive = policy.database?.destructive_operations?.join(', ') || 'configured';
  $('policySummary').innerHTML = `
    <div class="policy-row"><span>Registered identity</span><b>${policy.identity?.require_registered_agent ? 'REQUIRED' : 'OPTIONAL'}</b></div>
    <div class="policy-row"><span>Secret → untrusted egress</span><b>${policy.egress?.block_secret_to_untrusted ? 'BLOCK' : 'MONITOR'}</b></div>
    <div class="policy-row"><span>Payment auto-limit</span><b>₹${Number(policy.payments?.default_auto_limit || 0).toLocaleString('en-IN')}</b></div>
    <div class="policy-row"><span>DB destructive ops</span><b>${destructive}</b></div>
    <div class="policy-row"><span>Protected Git branches</span><b>${(policy.github?.protected_branches || []).join(', ')}</b></div>
    <div class="policy-row"><span>MCP provenance</span><b>${policy.mcp?.require_verified_provenance ? 'REQUIRED' : 'OPTIONAL'}</b></div>
    <div class="policy-row"><span>Policy integrity</span><b>v${status.policy_version} · ${String(status.policy_sha256 || '').slice(0,10)}…</b></div>`;

  $('identityPill').textContent = oidc.enabled ? 'OIDC ACTIVE' : 'LOCAL + WORKLOAD IAM';
  $('identitySummary').innerHTML = `
    <div class="policy-row"><span>Human identity</span><b>${oidc.enabled ? 'OIDC / JWT' : 'SIGNED SESSION'}</b></div>
    <div class="policy-row"><span>OIDC issuer</span><b>${oidc.issuer || 'NOT CONFIGURED'}</b></div>
    <div class="policy-row"><span>JWT algorithms</span><b>${(oidc.allowed_algorithms || []).join(', ')}</b></div>
    <div class="policy-row"><span>Workload identity</span><b>Ed25519</b></div>
    <div class="policy-row"><span>Agent replay defense</span><b>NONCE + TIMESTAMP</b></div>
    <div class="policy-row"><span>Policy self-approval</span><b>BLOCKED</b></div>`;

  $('capabilitySummary').innerHTML = `
    <div class="policy-row"><span>Version</span><b>${capabilities.version}</b></div>
    <div class="policy-row"><span>Governance</span><b>${(capabilities.governance || []).length} controls</b></div>
    <div class="policy-row"><span>Framework adapters</span><b>${(capabilities.integrations || []).join(', ')}</b></div>
    <div class="policy-row"><span>Telemetry</span><b>OTLP / HTTP</b></div>
    <div class="policy-row"><span>Benchmark model</span><b>SECURITY + UTILITY</b></div>
    <div class="policy-row"><span>MCP trust changes</span><b>FOUR-EYES</b></div>`;
}

function decisionClass(d){
  if(d==='BLOCK') return 'block';
  if(d==='REQUIRE_APPROVAL') return 'approval';
  if(d==='REWRITE') return 'rewrite';
  return 'allow';
}

function renderGraph(graph){
  if(!graph.nodes?.length){$('graph').innerHTML='<div class="empty">No actions.</div>';return;}
  $('graph').innerHTML = graph.nodes.map((n,i)=>`${i?'<div class="arrow">→</div>':''}<div class="node ${n.sensitivity==='SECRET'?'secret':''}"><strong>${n.label}</strong><small>${n.resource||n.destination||'runtime action'}</small><small>${n.sensitivity} · ${n.trust}</small>${n.labels?.length?`<em>${n.labels.join(' · ')}</em>`:''}</div>`).join('');
  const labels = graph.taint?.labels || [];
  $('taintBadge').textContent = labels.length ? labels.join(' + ') : 'No active taint';
}

function renderRepairs(actionResults){
  const repaired = actionResults.filter(a=>a.rewritten_action);
  if(!repaired.length){$('repairBox').style.display='none'; $('repairBox').innerHTML=''; return;}
  $('repairBox').style.display='block';
  $('repairBox').innerHTML = `<p class="eyebrow">SAFE PLAN REPAIR</p>${repaired.map(item=>`<div class="repair-row"><div><b>Original</b><code>${item.action.tool}.${item.action.operation} ${item.action.resource||''}</code></div><span>→</span><div><b>Repaired</b><code>${item.rewritten_action.tool}.${item.rewritten_action.operation} ${item.rewritten_action.resource||''}</code></div></div>`).join('')}`;
}

async function runScenario(id,title){
  $('resultTitle').textContent = 'Evaluating…';
  const r = await fetch(`/api/scenarios/${id}/run`,{method:'POST'}).then(r=>r.json());
  $('riskMetric').textContent = r.risk_score;
  $('riskBand').textContent = r.risk_score>=80?'Critical exposure':r.risk_score>=60?'High risk':r.risk_score>=35?'Medium risk':'Low risk';
  $('decisionMetric').textContent = r.decision.replaceAll('_',' ');
  $('latencyMetric').textContent = `${r.metrics.evaluation_latency_ms} ms`;
  $('resultTitle').textContent = title;
  $('riskScore').textContent = r.risk_score;
  $('resultSummary').textContent = r.summary;
  currentAuditId = r.audit_id;
  $('auditId').textContent = `Audit record: ${r.audit_id} · Policy: ${r.metrics.policy_profile}`;
  $('approvalControls').style.display = r.approval_required ? 'flex' : 'none';
  const badge = $('decisionBadge');
  badge.textContent = r.decision.replaceAll('_',' ');
  badge.className = `decision ${decisionClass(r.decision)}`;
  $('findings').innerHTML = r.findings.length ? r.findings.map(f=>`<div class="finding ${f.severity==='CRITICAL'?'critical':''}"><b>${f.severity} · ${f.code}</b><p>${f.detail}</p></div>`).join('') : '<div class="finding"><b>SAFE · No policy violation</b><p>The planned action remains within the user-authorized boundary.</p></div>';
  renderRepairs(r.action_results);
  renderGraph(r.graph);
  loadSystem();
}

async function resolveApproval(resolution){
  if(!currentAuditId) return;
  const r = await fetch(`/api/approvals/${currentAuditId}/${resolution}`, {method:'POST'});
  if(!r.ok) return;
  const body = await r.json();
  $('approvalControls').style.display='none';
  $('auditId').textContent = `Human decision: ${body.resolution} · ${body.audit_id}`;
  loadSystem();
}

async function runJudgeMode(){
  $('resultTitle').textContent = 'Running TrustKernel v1.3 Judge Mode…';
  const demo = await fetch('/api/v13/judge-demo/run',{method:'POST'}).then(r=>r.json());
  $('findings').innerHTML = demo.sequence.map(item=>`<div class="finding ${item.decision==='BLOCK'?'critical':''}"><b>${item.decision.replaceAll('_',' ')} · ${item.title}</b><p>Risk ${item.risk_score}/100 · Audit ${item.audit_id}${item.repairs?` · ${item.repairs} repair`:''}</p></div>`).join('');
  $('resultTitle').textContent = `TrustKernel ${demo.version} Judge Mode complete`;
  $('resultSummary').textContent = demo.message;
  $('decisionBadge').textContent = `${demo.sequence.length} LIVE SCENARIOS`;
  $('decisionBadge').className = 'decision rewrite';
  $('auditId').textContent = demo.audit_chain.valid ? `Audit chain verified · ${demo.audit_chain.entries} entries` : 'Audit chain verification failed';
  $('repairBox').style.display='none';
  loadSystem();
}

Promise.all([loadScenarios(), loadSystem()]).catch(()=>{$('scenarioList').innerHTML='<div class="empty">Backend unavailable.</div>'});
