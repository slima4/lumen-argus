/* findings.js — filterable paginated table, detail panel, export */
function _sessLabel(s){
  if(!s||!s.session_id)return '';
  const wd=s.working_directory||'';
  const short=wd?wd.split('/').pop()||wd:'';
  const sid=s.session_id.length>15?s.session_id.slice(0,15):s.session_id;
  const acct=s.account_id?s.account_id.slice(0,8)+'..':'';
  let label=short||acct||sid;
  if(label!==sid)label+=' ('+sid+')';
  return label;
}
function _dirShort(wd){if(!wd)return '';const parts=wd.split('/');return parts.pop()||wd;}
function _loadSessionFilter(){
  fetch('/api/v1/sessions?limit=50').then(function(r){return r.json()}).then(function(d){
    const sel=document.getElementById('f-sess');const cur=sel.value;
    while(sel.options.length>1)sel.lastChild.remove();
    (d.sessions||[]).forEach(function(s){
      const opt=document.createElement('option');opt.value=s.session_id;
      opt.textContent=_sessLabel(s);sel.appendChild(opt);});
    sel.value=cur;
  }).catch(function(){});}
function _fillSelect(elId,items){
  const sel=document.getElementById(elId),cur=sel.value;
  while(sel.options.length>1)sel.lastChild.remove();
  Object.keys(items).sort(function(a,b){return a.localeCompare(b)}).forEach(function(v){
    const o=document.createElement('option');o.value=v;o.textContent=v;sel.appendChild(o);});
  sel.value=cur;
}
let _lastFilterHash=null;
function _populateDynamicFilters(stats){
  const hash=JSON.stringify([
    Object.keys(stats.top_finding_types||{}),Object.keys(stats.by_detector||{}),
    Object.keys(stats.by_provider||{}),Object.keys(stats.by_client||{})]);
  if(hash===_lastFilterHash)return;
  _lastFilterHash=hash;
  if(stats.top_finding_types)_fillSelect('f-type',stats.top_finding_types);
  if(stats.by_detector)_fillSelect('f-det',stats.by_detector);
  if(stats.by_provider)_fillSelect('f-prov',stats.by_provider);
  if(stats.by_client)_fillSelect('f-client',stats.by_client);
}
function loadFindings(){
  _loadSessionFilter();
  let url='/api/v1/findings?limit='+findPerPage+'&offset='+findPage*findPerPage;
  const sevF=document.getElementById('f-sev').value;
  const detF=document.getElementById('f-det').value;
  const provF=document.getElementById('f-prov').value;
  const sessF=document.getElementById('f-sess').value;
  const actF=document.getElementById('f-action').value;
  const typeF=document.getElementById('f-type').value;
  const clientF=document.getElementById('f-client').value;
  const daysF=document.getElementById('f-days').value;
  if(sevF)url+='&severity='+encodeURIComponent(sevF);
  if(detF)url+='&detector='+encodeURIComponent(detF);
  if(provF)url+='&provider='+encodeURIComponent(provF);
  if(sessF)url+='&session_id='+encodeURIComponent(sessF);
  if(actF)url+='&action='+encodeURIComponent(actF);
  if(typeF)url+='&finding_type='+encodeURIComponent(typeF);
  if(clientF)url+='&client='+encodeURIComponent(clientF);
  if(daysF)url+='&days='+encodeURIComponent(daysF);
  fetch(url).then(function(r){return r.json()}).then(function(fd){
    allFindings=fd.findings||[];findTotal=fd.total;
    renderFindingsTable();
  }).catch(function(e){showPageError('find-tbody','Failed to load findings: '+e.message,loadFindings);});}
function renderFindingsTable(){
  const thead=document.getElementById('find-thead');thead.replaceChildren();
  const vis=ALL_COLS.filter(function(c){return c.on});
  for(let i=0;i<vis.length;i++){(function(col){
    const th=document.createElement('th');th.textContent=col.label;
    const arrow=document.createElement('span');arrow.className='sort-arrow';
    arrow.textContent=sortCol===col.key?(sortAsc?'\u25b2':'\u25bc'):'\u25bc';
    if(sortCol===col.key)th.classList.add('sorted');th.appendChild(arrow);
    th.addEventListener('click',function(){if(sortCol===col.key)sortAsc=!sortAsc;
      else{sortCol=col.key;sortAsc=true;}loadFindings();});
    thead.appendChild(th);})(vis[i]);}
  document.getElementById('find-total').textContent=findTotal+' findings';
  const tbody=document.getElementById('find-tbody');tbody.replaceChildren();
  if(!allFindings.length){const tr=document.createElement('tr');const td=document.createElement('td');
    td.colSpan=vis.length;td.className='empty';td.textContent='No findings match filters';
    tr.appendChild(td);tbody.appendChild(tr);return;}
  for(let j=0;j<allFindings.length;j++){(function(f){
    const tr=document.createElement('tr');if(f.id===selectedFindingId)tr.classList.add('selected');
    for(let k=0;k<vis.length;k++){const col=vis[k];const td=document.createElement('td');
      if(col.cls)td.className=col.cls;
      if(col.key==='severity')td.appendChild(makeBadge(f.severity));
      else if(col.key==='action_taken'&&f.action_taken){const tag=document.createElement('span');
        tag.className='action-tag';tag.textContent=f.action_taken;td.appendChild(tag);}
      else if(col.key==='finding_type'){td.textContent=f.finding_type||'';
        if(f.seen_count>1){const sc=document.createElement('span');sc.className='seen-count';
          sc.textContent='\u00d7'+f.seen_count;sc.title='Seen '+f.seen_count+' times across requests';
          td.appendChild(sc);}}
      else if(col.key==='timestamp')td.textContent=fmtTime(f.timestamp);
      else if(col.key==='location'){td.textContent=f[col.key]||'';td.title=f[col.key]||'';}
      else if(col.key==='session_id'&&f.session_id){
        const link=document.createElement('span');link.className='session-link';
        link.textContent=f.session_id;link.title='Filter by this session';
        link.addEventListener('click',function(e){e.stopPropagation();
          document.getElementById('f-sess').value=f.session_id;findPage=0;loadFindings();});
        td.appendChild(link);}
      else if(col.key==='working_directory'){
        td.textContent=_dirShort(f[col.key])||'\u2014';td.title=f[col.key]||'';}
      else if(col.key==='hostname'||col.key==='username'||col.key==='git_branch'||col.key==='client_name'){
        td.textContent=f[col.key]||'\u2014';}
      else td.textContent=f[col.key]!=null?String(f[col.key]):'';
      tr.appendChild(td);}
    tr.addEventListener('click',function(){showDetail(f)});
    tbody.appendChild(tr);})(allFindings[j]);}
  renderPager('find-pager',findPage,findTotal,findPerPage,
    function(pg){findPage=pg;loadFindings();},
    function(pp){findPerPage=pp;findPage=0;loadFindings();});}
function showDetail(f){selectedFindingId=f.id;
  const panel=document.getElementById('detail-panel');panel.classList.add('visible');
  document.querySelector('.findings-layout').classList.add('has-detail');
  if(window.innerWidth<=1000)setTimeout(function(){panel.scrollIntoView({behavior:'smooth',block:'start'})},50);
  const grid=document.getElementById('detail-grid');grid.replaceChildren();
  const fields=[['ID',f.id],['Timestamp',f.timestamp],['Detector',f.detector],['Type',f.finding_type],
   ['Severity',f.severity],['Action',f.action_taken||'none'],['Location',f.location],
   ['Provider',f.provider||'unknown'],['Model',f.model||'unknown'],['Preview',f.value_preview||'']];
  if(f.seen_count>1)fields.push(['Seen',f.seen_count+' times across requests']);
  if(f.value_hash)fields.push(['Value Hash',f.value_hash]);
  if(f.session_id)fields.push(['Session',f.session_id]);
  if(f.account_id)fields.push(['Account',f.account_id]);
  if(f.device_id)fields.push(['Device',f.device_id]);
  if(f.working_directory)fields.push(['Project',f.working_directory]);
  if(f.git_branch)fields.push(['Branch',f.git_branch]);
  if(f.os_platform)fields.push(['Platform',f.os_platform]);
  if(f.hostname)fields.push(['Machine',f.hostname]);
  if(f.username)fields.push(['User',f.username]);
  if(f.client_name)fields.push(['Agent',f.client_name]);
  if(f.sdk_name){let sdk=f.sdk_name;if(f.sdk_version)sdk+=' '+f.sdk_version;fields.push(['SDK',sdk]);}
  if(f.runtime)fields.push(['Runtime',f.runtime]);
  if(f.api_format)fields.push(['API Format',f.api_format]);
  if(f.raw_user_agent)fields.push(['User-Agent',f.raw_user_agent]);
  fields.forEach(function(pair){const item=document.createElement('div');item.className='detail-item';
    const lbl=document.createElement('label');lbl.textContent=pair[0];
    const val=document.createElement('div');val.className='val';val.textContent=String(pair[1]);
    item.appendChild(lbl);item.appendChild(val);grid.appendChild(item);});
  const ruleItem=document.createElement('div');ruleItem.className='detail-item';
  const ruleLbl=document.createElement('label');ruleLbl.textContent='Rule';
  const ruleVal=document.createElement('div');ruleVal.className='val';
  const ruleLink=document.createElement('a');
  const ruleQ=encodeURIComponent(f.finding_type||'');
  ruleLink.href='#rules?q='+ruleQ;
  ruleLink.textContent='View Rule \u2192';
  ruleLink.style.cssText='color:var(--accent);font-size:.78rem;text-decoration:none';
  ruleLink.addEventListener('click',function(e){e.stopPropagation();});
  ruleVal.appendChild(ruleLink);ruleItem.appendChild(ruleLbl);ruleItem.appendChild(ruleVal);
  grid.appendChild(ruleItem);
  renderFindingsTable();}
document.getElementById('f-sev').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('f-det').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('f-prov').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('f-sess').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('f-action').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('f-type').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('f-client').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('f-days').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('detail-panel-close').addEventListener('click',function(){
  document.getElementById('detail-panel').classList.remove('visible');
  document.querySelector('.findings-layout').classList.remove('has-detail');
  selectedFindingId=null;});
