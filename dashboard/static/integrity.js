// A separate, unscored environment view. No attacker identity is invented.
let lastIntegrityHash = '';
setInterval(() => {
  if (typeof data === 'undefined' || !data) return;
  const rows = scope === 'replay' ? [] : (data.environment?.file_changes || []).slice(-40).reverse();
  const container = document.getElementById('file-changes');
  if (!container || !document.getElementById('view-evidence').classList.contains('active')) return;
  const stamp = JSON.stringify(rows);
  if (stamp === lastIntegrityHash) return;
  lastIntegrityHash = stamp;
  container.innerHTML = rows.length ? '<table><thead><tr><th>TIME</th><th>CHANGE</th><th>PATH</th><th>SIZE</th><th>HASH / FIRST 64 KiB</th></tr></thead><tbody>' + rows.map(row => '<tr><td class="time-cell">' + escapeHTML(time(row.timestamp)) + '</td><td>' + pill(row.metadata.change.toUpperCase(), 'purple') + '</td><td class="mono">' + escapeHTML(row.target) + '</td><td>' + escapeHTML(row.metadata.current?.size ?? '—') + '</td><td class="mono">' + escapeHTML((row.metadata.current?.sha256_prefix64k || '—').slice(0, 16)) + '</td></tr>').join('') + '</tbody></table>' : '<div class="table-empty">No live filesystem changes in this view. Replay fixtures do not modify files.</div>';
}, 1500);
