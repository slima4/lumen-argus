/* allowlists.js — Allowlist management page (community).
   Three sections (secrets, pii, paths) with merged YAML + API entries.
   Pattern test panel against recent findings. */

const _alHtml = ''
  + '<div class="sh"><h2>Allowlists</h2></div>'
  + '<div class="panel al-test-panel" style="margin-bottom:20px">'
  + '<h3 style="font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;'
  + 'color:var(--text-secondary);margin-bottom:10px">Test pattern</h3>'
  + '<div class="al-add"><input id="al-test-pattern" placeholder="Pattern (e.g. sk-ant-* or *@example.com)">'
  + '<input id="al-test-value" placeholder="Test value (optional)">'
  + '<div class="btn btn-sm btn-primary" id="al-test-btn">Test</div></div>'
  + '<div id="al-test-result" style="margin-top:10px"></div></div>'
  + '<div id="al-sections"></div>';

registerPage('allowlists', 'Allowlists', {order: 45, loadFn: loadAllowlists, html: _alHtml});

let _alEventsWired = false;
function _wireAlEvents() {
  if (_alEventsWired) return;
  _alEventsWired = true;
  const testBtn = document.getElementById('al-test-btn');
  if (testBtn) testBtn.addEventListener('click', _testPattern);
}

function loadAllowlists() {
  _wireAlEvents();
  fetch('/api/v1/allowlists').then(function (r) { return r.json() }).then(function (data) {
    _renderSections(data);
  }).catch(function (e) {
    showPageError('al-sections', 'Failed to load allowlists: ' + e.message, loadAllowlists);
  });
}

function _renderSections(data) {
  const el = document.getElementById('al-sections'); if (!el) return; el.replaceChildren();
  const sections = [
    {key: 'secrets', label: 'Secrets', items: data.secrets || []},
    {key: 'pii', label: 'PII', items: data.pii || []},
    {key: 'paths', label: 'Paths', items: data.paths || []}
  ];
  sections.forEach(function (sec) {
    const div = document.createElement('div'); div.className = 'al-section';
    const h3 = document.createElement('h3');
    h3.textContent = sec.label + ' (' + sec.items.length + ')';
    div.appendChild(h3);
    if (!sec.items.length) {
      const empty = document.createElement('div'); empty.className = 'al-empty';
      empty.textContent = 'No ' + sec.label.toLowerCase() + ' allowlist entries';
      div.appendChild(empty);
    } else {
      sec.items.forEach(function (item) {
        div.appendChild(_alItem(item, sec.key));
      });
    }
    /* Inline add */
    const addRow = document.createElement('div'); addRow.className = 'al-add';
    const inp = document.createElement('input');
    inp.placeholder = 'Add ' + sec.label.toLowerCase() + ' pattern...';
    addRow.appendChild(inp);
    const addBtn = document.createElement('div');
    addBtn.className = 'btn btn-sm btn-primary'; addBtn.textContent = 'Add';
    addBtn.addEventListener('click', function () { _addEntry(sec.key, inp); });
    inp.addEventListener('keydown', function (e) { if (e.key === 'Enter') _addEntry(sec.key, inp); });
    addRow.appendChild(addBtn);
    div.appendChild(addRow);
    el.appendChild(div);
  });
}

function _alItem(item, listType) {
  const row = document.createElement('div'); row.className = 'al-item';
  const pat = document.createElement('span'); pat.className = 'al-pattern';
  pat.textContent = item.pattern; row.appendChild(pat);
  const src = document.createElement('span'); src.className = 'al-source';
  src.textContent = item.source || 'config'; row.appendChild(src);
  if (item.source === 'api' && item.id) {
    const del = document.createElement('div');
    del.className = 'btn btn-sm btn-danger'; del.textContent = '\u00D7';
    del.style.cssText = 'padding:2px 8px;min-width:0;line-height:1';
    del.addEventListener('click', function () { _deleteEntry(item.id); });
    row.appendChild(del);
  }
  return row;
}

function _addEntry(listType, input) {
  const pattern = input.value.trim();
  if (!pattern) return;
  fetch('/api/v1/allowlists', {
    method: 'POST', headers: csrfHeaders({'Content-Type': 'application/json'}),
    body: JSON.stringify({type: listType, pattern: pattern})
  }).then(function (r) {
    if (!r.ok) return r.json().then(function (d) { throw new Error(d.error || 'Failed'); });
    input.value = '';
    loadAllowlists();
  }).catch(function (e) {
    let errEl = input.parentNode.querySelector('.al-add-error');
    if (!errEl) {
      errEl = document.createElement('div'); errEl.className = 'al-add-error';
      errEl.style.cssText = 'color:var(--critical);font-size:.75rem;width:100%';
      input.parentNode.appendChild(errEl);
    }
    errEl.textContent = e.message;
    setTimeout(function () { errEl.textContent = ''; }, 4000);
  });
}

function _deleteEntry(id) {
  fetch('/api/v1/allowlists/' + id, {
    method: 'DELETE', headers: csrfHeaders()
  }).then(function (r) {
    if (!r.ok) throw new Error('Failed');
    loadAllowlists();
  }).catch(function () { loadAllowlists(); });
}

function _testPattern() {
  const pattern = document.getElementById('al-test-pattern').value.trim();
  const value = document.getElementById('al-test-value').value;
  const result = document.getElementById('al-test-result');
  if (!pattern) { result.replaceChildren(); return; }
  fetch('/api/v1/allowlists/test', {
    method: 'POST', headers: csrfHeaders({'Content-Type': 'application/json'}),
    body: JSON.stringify({pattern: pattern, value: value})
  }).then(function (r) { return r.json() }).then(function (d) {
    result.replaceChildren();
    /* Value match result */
    if (value) {
      const valRes = document.createElement('div');
      valRes.style.cssText = 'font-family:var(--font-data);font-size:.78rem;margin-bottom:6px';
      valRes.style.color = d.value_match ? 'var(--accent)' : 'var(--critical)';
      valRes.textContent = d.value_match ? 'Value matches pattern' : 'Value does not match';
      result.appendChild(valRes);
    }
    /* Matching findings */
    const countDiv = document.createElement('div');
    countDiv.style.cssText = 'font-family:var(--font-data);font-size:.78rem;color:var(--text-secondary);margin-bottom:6px';
    countDiv.textContent = d.matching_findings_count + ' recent finding(s) would be suppressed';
    result.appendChild(countDiv);
    if (d.matching_findings && d.matching_findings.length) {
      d.matching_findings.forEach(function (f) {
        const item = document.createElement('div');
        item.style.cssText = 'font-family:var(--font-data);font-size:.73rem;color:var(--text-muted);padding:2px 0';
        item.textContent = f.finding_type + ' — ' + f.value_preview + ' (' + f.severity + ')';
        result.appendChild(item);
      });
    }
  }).catch(function (e) {
    result.replaceChildren();
    const err = document.createElement('div');
    err.style.cssText = 'color:var(--critical);font-size:.78rem';
    err.textContent = 'Test failed: ' + e.message;
    result.appendChild(err);
  });
}
