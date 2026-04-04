/* dashboard.js — quick stats, trend chart, activity feed, sessions, pipeline health */
const QS_ICONS={
  findings:'<svg viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
  shield:'<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  sessions:'<svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>',
  clock:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>'
};
function makeBadge(sev){const b=document.createElement('span');b.className='badge '+sevCls(sev);
  const d=document.createElement('span');d.className='badge-dot';b.appendChild(d);
  const t=document.createElement('span');t.textContent=sev;b.appendChild(t);return b;}
function renderQuickStats(stats,sessionCount){
  const el=document.getElementById('quick-stats');el.replaceChildren();
  const total=stats.total_findings||0;
  const today=stats.today_count||0;
  const bySev=stats.by_severity||{};
  const crit=bySev.critical||0;const high=bySev.high||0;
  const warn=bySev.warning||0;const info=bySev.info||0;
  const sevParts=[];
  if(high)sevParts.push(high+' high');
  if(warn)sevParts.push(warn+' warning');
  if(info)sevParts.push(info+' info');
  const lastTime=stats.last_finding_time;
  const items=[
    {label:'Findings today',value:String(today),sub:total.toLocaleString()+' total',icon:'findings',
      alert:today>0&&crit>0},
    {label:'Severity',value:crit?crit+' critical':'0 critical',
      sub:sevParts.join(' \u00b7 ')||'no findings',icon:'shield',alert:crit>0},
    {label:'Active sessions',value:String(sessionCount),sub:'with findings in last 24h',icon:'sessions'},
    {label:'Last finding',value:lastTime?fmtTime(lastTime):'\u2014',sub:lastTime?new Date(lastTime).toLocaleString():'no findings yet',icon:'clock'}
  ];
  items.forEach(function(it){
    const card=document.createElement('div');
    card.className='qs-card'+(it.alert?' qs-alert':'');
    const lbl=document.createElement('div');lbl.className='qs-label';
    const lblText=document.createElement('span');lblText.textContent=it.label;lbl.appendChild(lblText);
    const icon=document.createElement('div');icon.className='qs-icon';
    /* Static SVG icon constants — NOT user data, safe for innerHTML */
    icon.innerHTML=QS_ICONS[it.icon]||QS_ICONS.findings;
    lbl.appendChild(icon);card.appendChild(lbl);
    const val=document.createElement('div');val.className='qs-value';val.textContent=it.value;card.appendChild(val);
    const sub=document.createElement('div');sub.className='qs-sub';sub.textContent=it.sub;card.appendChild(sub);
    el.appendChild(card);
  });
}
function renderChart(daily){const svg=document.getElementById('chart');
  while(svg.firstChild)svg.removeChild(svg.firstChild);
  const W=600,H=130,pB=16,pT=4,n=daily.length;if(n<2)return;
  let mx=0;for(let i=0;i<n;i++){if(daily[i].count>mx)mx=daily[i].count;}if(!mx)mx=1;
  for(let g=0;g<4;g++){const gy=pT+(H-pT-pB)*(g/3);
    const l=document.createElementNS('http://www.w3.org/2000/svg','line');
    l.setAttribute('x1',0);l.setAttribute('x2',W);l.setAttribute('y1',gy);l.setAttribute('y2',gy);
    l.setAttribute('class','chart-grid');svg.appendChild(l);}
  const pts=[];for(let j=0;j<n;j++){pts.push((W*(j/(n-1)))+','+(pT+(H-pT-pB)*(1-daily[j].count/mx)));}
  const area=document.createElementNS('http://www.w3.org/2000/svg','polygon');
  area.setAttribute('points',pts.join(' ')+' '+W+','+(H-pB)+' 0,'+(H-pB));
  area.setAttribute('class','chart-area');svg.appendChild(area);
  const pl=document.createElementNS('http://www.w3.org/2000/svg','polyline');
  pl.setAttribute('points',pts.join(' '));pl.setAttribute('class','chart-line');svg.appendChild(pl);
  for(let k=Math.max(0,n-3);k<n;k++){const pp=pts[k].split(',');
    const ci=document.createElementNS('http://www.w3.org/2000/svg','circle');
    ci.setAttribute('cx',pp[0]);ci.setAttribute('cy',pp[1]);ci.setAttribute('class','chart-dot');svg.appendChild(ci);}
  [0,Math.floor(n/2),n-1].forEach(function(li,m){const lx=W*(li/(n-1));
    const tx=document.createElementNS('http://www.w3.org/2000/svg','text');
    tx.setAttribute('x',lx);tx.setAttribute('y',H-2);tx.setAttribute('class','chart-label');
    tx.setAttribute('text-anchor',m===0?'start':m===2?'end':'middle');
    tx.textContent=(daily[li].date||'').slice(5);svg.appendChild(tx);});}
function renderBars(elId,data){const el=document.getElementById(elId);el.replaceChildren();
  const ent=[];for(const k in data){if(data.hasOwnProperty(k))ent.push({n:k,c:data[k]});}
  ent.sort(function(a,b){return b.c-a.c});const top=ent.slice(0,6);const mx=top.length?top[0].c:1;
  for(let i=0;i<top.length;i++){const row=document.createElement('div');row.className='det-row';
    const nm=document.createElement('span');nm.className='det-name';nm.textContent=top[i].n;
    const bg=document.createElement('div');bg.className='det-bar-bg';
    const bar=document.createElement('div');bar.className='det-bar';
    bar.style.width=Math.max(4,Math.round(top[i].c/mx*100))+'%';bg.appendChild(bar);
    const ct=document.createElement('span');ct.className='det-count';ct.textContent=String(top[i].c);
    row.appendChild(nm);row.appendChild(bg);row.appendChild(ct);el.appendChild(row);}
  if(!top.length){const em=document.createElement('div');em.className='empty';em.textContent='no data yet';el.appendChild(em);}}
function renderActivityFeed(findings){
  const el=document.getElementById('activity-feed');el.replaceChildren();
  const countEl=document.getElementById('feed-count');
  if(!findings||!findings.length){
    const em=document.createElement('div');em.className='empty';
    em.textContent='No findings yet \u2014 requests are being scanned';el.appendChild(em);
    if(countEl)countEl.textContent='';return;}
  if(countEl)countEl.textContent=findings.length+' recent';
  findings.forEach(function(f){
    const item=document.createElement('div');item.className='feed-item';
    item.addEventListener('click',function(){
      navigate('findings');
      /* Allow findings page to render, then select this finding */
      setTimeout(function(){showDetail(f)},100);
    });
    const sev=document.createElement('div');sev.className='feed-sev '+sevCls(f.severity);
    item.appendChild(sev);
    const body=document.createElement('div');body.className='feed-body';
    const type=document.createElement('div');type.className='feed-type';
    type.textContent=f.finding_type;body.appendChild(type);
    const meta=document.createElement('div');meta.className='feed-meta';
    const timeSpan=document.createElement('span');timeSpan.textContent=fmtTime(f.timestamp);meta.appendChild(timeSpan);
    const detSpan=document.createElement('span');detSpan.textContent=f.detector;meta.appendChild(detSpan);
    if(f.location){const locSpan=document.createElement('span');locSpan.textContent=f.location;meta.appendChild(locSpan);}
    body.appendChild(meta);item.appendChild(body);
    if(f.action_taken){const action=document.createElement('span');action.className='feed-action';
      action.textContent=f.action_taken;item.appendChild(action);}
    el.appendChild(item);
  });
}
function renderActiveSessions(sessions){
  const el=document.getElementById('active-sessions');el.replaceChildren();
  if(!sessions||!sessions.length){
    const em=document.createElement('div');em.className='empty';
    em.textContent='No active sessions';el.appendChild(em);return;}
  sessions.forEach(function(s){
    const card=document.createElement('div');card.className='session-card';
    card.style.cursor='pointer';
    card.addEventListener('click',function(){
      navigate('findings');
      setTimeout(function(){
        document.getElementById('f-sess').value=s.session_id;
        findPage=0;loadFindings();
      },100);
    });
    const head=document.createElement('div');head.className='session-head';
    const idEl=document.createElement('div');idEl.className='session-id';
    idEl.textContent=s.client_name?(s.client_name+' \u00b7 '):'';
    idEl.textContent+=(s.session_id||'').slice(0,12)+(s.session_id&&s.session_id.length>12?'\u2026':'');
    idEl.title=s.session_id||'';head.appendChild(idEl);
    const cnt=document.createElement('div');cnt.className='session-count';
    cnt.textContent=s.finding_count+' finding'+(s.finding_count!==1?'s':'');head.appendChild(cnt);
    card.appendChild(head);
    if(s.working_directory||s.account_id){
      const meta=document.createElement('div');meta.className='session-meta';
      meta.textContent=s.working_directory||s.account_id||'';
      meta.title=meta.textContent;card.appendChild(meta);}
    const sevs=document.createElement('div');sevs.className='session-sevs';
    ['critical','high','warning','info'].forEach(function(sev){
      const count=s[sev+'_count']||0;if(!count)return;
      const dot=document.createElement('span');dot.className='session-sev-dot '+sev;
      dot.textContent=count+' '+sev;sevs.appendChild(dot);
    });
    if(sevs.children.length)card.appendChild(sevs);
    const timeEl=document.createElement('div');timeEl.className='session-meta';
    timeEl.textContent='Last seen: '+fmtTime(s.last_seen);card.appendChild(timeEl);
    el.appendChild(card);
  });
}
function renderPipelineHealth(stages){
  const el=document.getElementById('pipeline-health');el.replaceChildren();
  if(!stages||!stages.length){
    const em=document.createElement('div');em.className='empty';em.textContent='loading...';el.appendChild(em);return;}
  stages.forEach(function(s){
    const item=document.createElement('div');item.className='health-item';
    const cls=!s.available?'unavail':s.enabled?'on':'off';
    const dot=document.createElement('div');dot.className='health-dot '+cls;item.appendChild(dot);
    const name=document.createElement('div');name.className='health-name';name.textContent=s.label;item.appendChild(name);
    const status=document.createElement('div');status.className='health-status '+cls;
    status.textContent=!s.available?'n/a':s.enabled?'on':'off';item.appendChild(status);
    el.appendChild(item);
  });
}
function initColToggles(){const el=document.getElementById('col-toggle');el.replaceChildren();
  for(let i=0;i<ALL_COLS.length;i++){(function(idx){
    const btn=document.createElement('div');btn.className='col-btn'+(ALL_COLS[idx].on?' on':'');
    btn.textContent=ALL_COLS[idx].label;
    btn.addEventListener('click',function(){ALL_COLS[idx].on=!ALL_COLS[idx].on;
      btn.classList.toggle('on');renderFindingsTable();});
    el.appendChild(btn);})(i);}}
