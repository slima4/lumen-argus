/* audit.js — audit log viewer, detail panel, export */
function loadAudit(){
  let url='/api/v1/audit?limit='+auditPerPage+'&offset='+auditPage*auditPerPage;
  const actF=document.getElementById('a-action').value;
  const provF=document.getElementById('a-prov').value;
  const searchF=document.getElementById('a-search').value;
  if(actF)url+='&action='+encodeURIComponent(actF);
  if(provF)url+='&provider='+encodeURIComponent(provF);
  if(searchF)url+='&search='+encodeURIComponent(searchF);
  fetch(url).then(function(r){return r.json()}).then(function(data){
    document.getElementById('audit-total').textContent=(data.total||0)+' entries';
    if(data.providers){const sel=document.getElementById('a-prov'),cv=sel.value;
      while(sel.options.length>1)sel.removeChild(sel.lastChild);
      data.providers.forEach(function(p){const o=document.createElement('option');o.value=p;o.textContent=p;sel.appendChild(o)});
      sel.value=cv;}
    renderAuditTable(data.entries||[],data.total||0);
  }).catch(function(e){showPageError('audit-tbody','Failed to load audit log: '+e.message,loadAudit);});
}
function renderAuditTable(entries,total){
  const tbody=document.getElementById('audit-tbody');tbody.replaceChildren();
  if(!entries.length){const tr=document.createElement('tr');const td=document.createElement('td');
    td.colSpan=9;td.className='empty';td.textContent='No audit entries';
    tr.appendChild(td);tbody.appendChild(tr);}
  else{for(let i=0;i<entries.length;i++){(function(e){
    const tr=document.createElement('tr');
    const td0=document.createElement('td');td0.className='col-time';td0.textContent=fmtTime(e.timestamp);
    const td1=document.createElement('td');td1.className='col-time';td1.textContent=String(e.request_id||'');
    const td2=document.createElement('td');td2.textContent=e.provider||'';
    const td3=document.createElement('td');td3.textContent=e.model||'';
    const td4=document.createElement('td');td4.className='col-loc';td4.textContent=e.endpoint||'';td4.title=e.endpoint||'';
    const td5=document.createElement('td');
    const actionColors={pass:'info',alert:'warning',block:'critical'};
    const badge=document.createElement('span');
    badge.className='badge '+(actionColors[e.action]||'info');
    const dot=document.createElement('span');dot.className='badge-dot';badge.appendChild(dot);
    const atxt=document.createElement('span');atxt.textContent=e.action||'';badge.appendChild(atxt);
    td5.appendChild(badge);
    const td6=document.createElement('td');td6.className='col-time';
    td6.textContent=String(e.finding_count!=null?e.finding_count:(e.findings||[]).length);
    const td7=document.createElement('td');td7.className='col-time';
    td7.textContent=e.scan_duration_ms!=null?Number(e.scan_duration_ms).toFixed(1):'';
    const td8=document.createElement('td');td8.className='col-time';
    const sz=e.request_size_bytes||0;
    td8.textContent=sz>1024?(sz/1024).toFixed(1)+'K':String(sz);
    tr.appendChild(td0);tr.appendChild(td1);tr.appendChild(td2);tr.appendChild(td3);
    tr.appendChild(td4);tr.appendChild(td5);tr.appendChild(td6);tr.appendChild(td7);tr.appendChild(td8);
    tr.addEventListener('click',function(){showAuditDetail(e)});
    tbody.appendChild(tr);
  })(entries[i]);}}
  renderPager('audit-pager',auditPage,total,auditPerPage,
    function(pg){auditPage=pg;loadAudit();},
    function(pp){auditPerPage=pp;auditPage=0;loadAudit();});
}
function showAuditDetail(e){
  const panel=document.getElementById('audit-detail');
  panel.classList.add('visible');
  document.getElementById('audit-layout').classList.add('has-detail');
  if(window.innerWidth<=1000)setTimeout(function(){panel.scrollIntoView({behavior:'smooth',block:'start'})},50);
  const grid=document.getElementById('audit-detail-grid');grid.replaceChildren();
  const sz=e.request_size_bytes||0;
  const sizeStr=sz>1048576?(sz/1048576).toFixed(1)+' MB':sz>1024?(sz/1024).toFixed(1)+' KB':sz+' B';
  [['Timestamp',e.timestamp],['Request ID',e.request_id],['Provider',e.provider||'unknown'],
   ['Model',e.model||'unknown'],['Endpoint',e.endpoint||''],['Action',e.action||'pass'],
   ['Scan Duration',e.scan_duration_ms!=null?Number(e.scan_duration_ms).toFixed(1)+' ms':'n/a'],['Request Size',sizeStr],
   ['Findings',e.finding_count!=null?e.finding_count:(e.findings||[]).length],
   ['Passed',e.passed?'Yes':'No']
  ].forEach(function(pair){const item=document.createElement('div');item.className='detail-item';
    const lbl=document.createElement('label');lbl.textContent=pair[0];
    const val=document.createElement('div');val.className='val';val.textContent=String(pair[1]);
    item.appendChild(lbl);item.appendChild(val);grid.appendChild(item);});
  const fdiv=document.getElementById('audit-detail-findings');fdiv.replaceChildren();
  const findings=e.findings||[];
  if(findings.length){
    const fh=document.createElement('div');fh.className='sh';fh.style.marginTop='16px';
    const fhh=document.createElement('h2');fhh.textContent='Findings ('+findings.length+')';
    fh.appendChild(fhh);fdiv.appendChild(fh);
    for(let i=0;i<findings.length;i++){(function(f){
      const card=document.createElement('div');card.className='rule-card';
      const head=document.createElement('div');head.className='rule-head';
      const nm=document.createElement('span');nm.className='rule-name';nm.textContent=f.type||'';
      head.appendChild(nm);head.appendChild(makeBadge(f.severity||'info'));
      if(f.action_taken){const tag=document.createElement('span');tag.className='action-tag';
        tag.textContent=f.action_taken;head.appendChild(tag);}
      card.appendChild(head);
      const meta=document.createElement('div');meta.className='rule-meta';
      meta.textContent='Detector: '+(f.detector||'')+' | Location: '+(f.location||'');
      card.appendChild(meta);fdiv.appendChild(card);
    })(findings[i]);}
  }
}
document.getElementById('a-action').addEventListener('change',function(){auditPage=0;loadAudit()});
document.getElementById('a-prov').addEventListener('change',function(){auditPage=0;loadAudit()});
let auditSearchTimer=null;
document.getElementById('a-search').addEventListener('input',function(){
  clearTimeout(auditSearchTimer);auditSearchTimer=setTimeout(function(){auditPage=0;loadAudit()},300);});
document.getElementById('audit-export-csv').addEventListener('click',function(){exportAudit('csv')});
document.getElementById('audit-export-json').addEventListener('click',function(){exportAudit('json')});
document.getElementById('audit-detail-close').addEventListener('click',function(){
  document.getElementById('audit-detail').classList.remove('visible');
  document.getElementById('audit-layout').classList.remove('has-detail');});
function exportAudit(fmt){
  let url='/api/v1/audit/export?format='+fmt;
  const actF=document.getElementById('a-action').value;
  const provF=document.getElementById('a-prov').value;
  const searchF=document.getElementById('a-search').value;
  if(actF)url+='&action='+encodeURIComponent(actF);
  if(provF)url+='&provider='+encodeURIComponent(provF);
  if(searchF)url+='&search='+encodeURIComponent(searchF);
  window.location.href=url;
}
