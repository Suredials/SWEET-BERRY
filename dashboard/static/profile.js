// Distinguish observed interaction style from proving a human or AI identity.
let operatorStamp='';
setInterval(()=>{
  if(!data)return;
  const session=[...scopedSessions()].sort((a,b)=>b.risk-a.risk)[0];
  const profile=session?.profile||{likely_type:'insufficient_evidence',confidence:0,signals:[],features:{}};
  const report=[...(data.soc_n2?.reports||[])].reverse().find(r=>r.operator_assessment&&r.evidence?.some(e=>e.source_ip===session?.source_ip));
  const stamp=JSON.stringify([scope,selected,profile,report?.timestamp]);if(stamp===operatorStamp)return;operatorStamp=stamp;
  const labels={human_like:'Human-like',automation_like:'Automation-like',agent_compatible:'Agent-compatible',insufficient_evidence:'Insufficient evidence'};
  const color=profile.likely_type==='agent_compatible'?'purple':profile.likely_type==='automation_like'?'amber':'mint';
  $('operator-profile').innerHTML=`<div class="divider"></div><div class="section-label">OPERATOR STYLE / ESTIMATE</div><div class="operator-head">${pill(labels[profile.likely_type]||'Insufficient evidence',color)}<span>${Math.round((profile.confidence||0)*100)}% heuristic support</span></div><div class="small-muted">${escapeHTML(session?.source_ip||'No selected source')} / ${profile.features?.independent_interactions||0} independent interactions / ${profile.features?.unique_services||0} services</div><ul class="operator-signals">${(profile.signals||[]).slice(0,3).map(text=>`<li>${escapeHTML(text)}</li>`).join('')}</ul>${report?`<div class="assessment-note"><b>SOC N2: ${escapeHTML(labels[report.operator_assessment.style])}</b><p>${escapeHTML(report.operator_assessment.rationale)}</p></div>`:''}<div class="operator-caveat">Heuristic, not a calibrated probability or proof of AI control. Humans using scripts can look agentic. Shared source IPs may represent multiple operators.</div>`;
},1500);
