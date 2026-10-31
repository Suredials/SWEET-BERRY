// Model output is always escaped text. The analyst can publish reports only.
let analystStamp = '', observerStamp = '';
document.getElementById('analyze-now').addEventListener('click', async () => {
  try {
    await request('/api/soc/analyze', 'POST', {});
    toast('SOC N2 analysis queued. Live evidence only.');
  } catch (error) { toast(error.message, true); }
});
setInterval(() => {
  if (!data) return;
  const analyst = data.soc_n2 || {status:{},reports:[]};
  const stamp = JSON.stringify([analyst,scope,selected]);
  if (stamp !== analystStamp) {
    analystStamp = stamp;
    const status = analyst.status;
    const sources=new Set(scopedSessions().map(s=>s.source_ip));
    const latest=[...analyst.reports].reverse().find(r=>r.evidence?.some(e=>sources.has(e.source_ip)));
    $('soc-n2-preview').innerHTML = scope === 'replay' ? '' : latest ? `<div class="divider"></div><div class="section-label">SOC N2 / ${escapeHTML(latest.mode.toUpperCase())}</div><div class="assessment-note"><b>${escapeHTML(latest.title)}</b><p>${escapeHTML(latest.summary.slice(0,280))}${latest.summary.length>280?'...':''}</p><button class="text-button" data-go="analyst">Read analyst report</button></div>` : '<div class="assessment-note">SOC N2 awaiting live evidence.</div>';
    $('analyst-status').textContent = `${status.provider || 'local'} / ${status.model || 'unconfigured'} · ${status.mode || 'mock'} · ${status.state || 'waiting'}${status.error ? ' · ' + status.error : ''} · Publishes validated reports only. Live telemetry, no replay fixtures.`;
    $('analyst-reports').innerHTML = analyst.reports.length ? [...analyst.reports].reverse().map((report,index) => `
      ${index ? `<details class="analyst-history"><summary>${escapeHTML(time(report.timestamp))} / ${escapeHTML(report.title)} / ${escapeHTML(report.mode.toUpperCase())}</summary>` : ''}
      <article class="analyst-report">
        <div class="panel-heading"><div><span class="panel-kicker">${escapeHTML(report.model)} · ${escapeHTML(time(report.timestamp))}</span><h2>${escapeHTML(report.title)}</h2></div>${pill(report.mode.toUpperCase(),report.mode==='live'?'mint':'amber')}</div>
        <p class="analyst-summary">${escapeHTML(report.summary)}</p>
        <div class="analyst-meta">${pill(report.severity.toUpperCase(),'purple')} <span>Confidence ${Math.round(report.confidence*100)}% · ${report.evidence_count} evidence items</span></div>
        ${report.findings.map(finding=>`<div class="analyst-finding"><b>${escapeHTML(finding.hypothesis)}</b><div class="small-muted">${Math.round(finding.confidence*100)}% confidence</div><div class="evidence-refs">${finding.evidence_ids.map(id=>`<span class="pill">${escapeHTML(id)}</span>`).join(' ')}</div></div>`).join('')}
        <div class="analyst-columns"><div><div class="section-label">RECOMMENDATIONS</div><ul>${report.recommendations.map(text=>`<li>${escapeHTML(text)}</li>`).join('')}</ul></div><div><div class="section-label">UNCERTAINTIES</div><ul>${report.uncertainties.map(text=>`<li>${escapeHTML(text)}</li>`).join('')}</ul></div></div>
        <details><summary class="text-button">Evidence snapshot</summary><pre class="analyst-evidence">${escapeHTML(JSON.stringify(report.evidence,null,2))}</pre></details>
      </article>${index ? '</details>' : ''}`).join('') : '<div class="table-empty">Waiting for live telemetry. DeepSeek will publish a report here; replay remains deterministic.</div>';
  }
  const observer = data.observer || {status:{},events:[]};
  const rows = scope === 'replay' ? [] : observer.events.slice(-60).reverse();
  const nextStamp = JSON.stringify([observer.status,rows]);
  if (nextStamp !== observerStamp) {
    observerStamp = nextStamp;
    $('observer-status').textContent = Object.values(observer.status).filter(value=>value==='attached').length+' targets traced';
    $('observer-events').innerHTML = rows.length ? '<table><thead><tr><th>TIME</th><th>KIND</th><th>CONTAINER / PID</th><th>EXECUTABLE / DESTINATION</th><th>RESULT</th></tr></thead><tbody>' + rows.map(row=>`<tr><td class="time-cell">${escapeHTML(time(row.timestamp))}</td><td>${pill(row.kind.toUpperCase(),row.kind==='network_connect'?'amber':'purple')}</td><td>${escapeHTML(row.container)} / ${escapeHTML(row.pid ?? '—')}</td><td class="mono">${escapeHTML(row.executable || row.path || row.paths?.join(', ') || (row.destination ? row.destination+':'+row.port : row.child_pid ? 'child PID '+row.child_pid : row.kind))}</td><td>${escapeHTML(row.result)}</td></tr>`).join('')+'</tbody></table>' : '<div class="table-empty">No host observations in this scope.</div>';
  }
}, 1500);
