/* dashboard.js — quick stats, trend chart, activity feed, sessions, pipeline health */
var QS_ICONS={
  findings:'<svg viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
  shield:'<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  sessions:'<svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>',
  clock:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>'
};
function makeBadge(sev){var b=document.createElement('span');b.className='badge '+sevCls(sev);
  var d=document.createElement('span');d.className='badge-dot';b.appendChild(d);
  var t=document.createElement('span');t.textContent=sev;b.appendChild(t);return b;}
function renderQuickStats(stats,sessionCount){
  var el=document.getElementById('quick-stats');el.replaceChildren();
  var total=stats.total_findings||0;
  var today=stats.today_count||0;
  var bySev=stats.by_severity||{};
  var crit=bySev.critical||0;var high=bySev.high||0;
  var warn=bySev.warning||0;var info=bySev.info||0;
  var sevParts=[];
  if(high)sevParts.push(high+' high');
  if(warn)sevParts.push(warn+' warning');
  if(info)sevParts.push(info+' info');
  var lastTime=stats.last_finding_time;
  var items=[
    {label:'Findings today',value:String(today),sub:total.toLocaleString()+' total',icon:'findings',
      alert:today>0&&crit>0},
    {label:'Severity',value:crit?crit+' critical':'0 critical',
      sub:sevParts.join(' \u00b7 ')||'no findings',icon:'shield',alert:crit>0},
    {label:'Active sessions',value:String(sessionCount),sub:'with findings in last 24h',icon:'sessions'},
    {label:'Last finding',value:lastTime?fmtTime(lastTime):'\u2014',sub:lastTime?new Date(lastTime).toLocaleString():'no findings yet',icon:'clock'}
  ];
  items.forEach(function(it){
    var card=document.createElement('div');
    card.className='qs-card'+(it.alert?' qs-alert':'');
    var lbl=document.createElement('div');lbl.className='qs-label';
    var lblText=document.createElement('span');lblText.textContent=it.label;lbl.appendChild(lblText);
    var icon=document.createElement('div');icon.className='qs-icon';
    /* Static SVG icon constants — NOT user data, safe for innerHTML */
    icon.innerHTML=QS_ICONS[it.icon]||QS_ICONS.findings;
    lbl.appendChild(icon);card.appendChild(lbl);
    var val=document.createElement('div');val.className='qs-value';val.textContent=it.value;card.appendChild(val);
    var sub=document.createElement('div');sub.className='qs-sub';sub.textContent=it.sub;card.appendChild(sub);
    el.appendChild(card);
  });
}
function renderChart(daily){var svg=document.getElementById('chart');
  while(svg.firstChild)svg.removeChild(svg.firstChild);
  var W=600,H=130,pB=16,pT=4,n=daily.length;if(n<2)return;
  var mx=0;for(var i=0;i<n;i++){if(daily[i].count>mx)mx=daily[i].count;}if(!mx)mx=1;
  for(var g=0;g<4;g++){var gy=pT+(H-pT-pB)*(g/3);
    var l=document.createElementNS('http://www.w3.org/2000/svg','line');
    l.setAttribute('x1',0);l.setAttribute('x2',W);l.setAttribute('y1',gy);l.setAttribute('y2',gy);
    l.setAttribute('class','chart-grid');svg.appendChild(l);}
  var pts=[];for(var j=0;j<n;j++){pts.push((W*(j/(n-1)))+','+(pT+(H-pT-pB)*(1-daily[j].count/mx)));}
  var area=document.createElementNS('http://www.w3.org/2000/svg','polygon');
  area.setAttribute('points',pts.join(' ')+' '+W+','+(H-pB)+' 0,'+(H-pB));
  area.setAttribute('class','chart-area');svg.appendChild(area);
  var pl=document.createElementNS('http://www.w3.org/2000/svg','polyline');
  pl.setAttribute('points',pts.join(' '));pl.setAttribute('class','chart-line');svg.appendChild(pl);
  for(var k=Math.max(0,n-3);k<n;k++){var pp=pts[k].split(',');
    var ci=document.createElementNS('http://www.w3.org/2000/svg','circle');
    ci.setAttribute('cx',pp[0]);ci.setAttribute('cy',pp[1]);ci.setAttribute('class','chart-dot');svg.appendChild(ci);}
  [0,Math.floor(n/2),n-1].forEach(function(li,m){var lx=W*(li/(n-1));
    var tx=document.createElementNS('http://www.w3.org/2000/svg','text');
    tx.setAttribute('x',lx);tx.setAttribute('y',H-2);tx.setAttribute('class','chart-label');
    tx.setAttribute('text-anchor',m===0?'start':m===2?'end':'middle');
    tx.textContent=(daily[li].date||'').slice(5);svg.appendChild(tx);});}
function renderBars(elId,data){var el=document.getElementById(elId);el.replaceChildren();
  var ent=[];for(var k in data){if(data.hasOwnProperty(k))ent.push({n:k,c:data[k]});}
  ent.sort(function(a,b){return b.c-a.c});var top=ent.slice(0,6);var mx=top.length?top[0].c:1;
  for(var i=0;i<top.length;i++){var row=document.createElement('div');row.className='det-row';
    var nm=document.createElement('span');nm.className='det-name';nm.textContent=top[i].n;
    var bg=document.createElement('div');bg.className='det-bar-bg';
    var bar=document.createElement('div');bar.className='det-bar';
    bar.style.width=Math.max(4,Math.round(top[i].c/mx*100))+'%';bg.appendChild(bar);
    var ct=document.createElement('span');ct.className='det-count';ct.textContent=String(top[i].c);
    row.appendChild(nm);row.appendChild(bg);row.appendChild(ct);el.appendChild(row);}
  if(!top.length){var em=document.createElement('div');em.className='empty';em.textContent='no data yet';el.appendChild(em);}}
function renderActivityFeed(findings){
  var el=document.getElementById('activity-feed');el.replaceChildren();
  var countEl=document.getElementById('feed-count');
  if(!findings||!findings.length){
    var em=document.createElement('div');em.className='empty';
    em.textContent='No findings yet \u2014 requests are being scanned';el.appendChild(em);
    if(countEl)countEl.textContent='';return;}
  if(countEl)countEl.textContent=findings.length+' recent';
  findings.forEach(function(f){
    var item=document.createElement('div');item.className='feed-item';
    item.addEventListener('click',function(){
      navigate('findings');
      /* Allow findings page to render, then select this finding */
      setTimeout(function(){showDetail(f)},100);
    });
    var sev=document.createElement('div');sev.className='feed-sev '+sevCls(f.severity);
    item.appendChild(sev);
    var body=document.createElement('div');body.className='feed-body';
    var type=document.createElement('div');type.className='feed-type';
    type.textContent=f.finding_type;body.appendChild(type);
    var meta=document.createElement('div');meta.className='feed-meta';
    var timeSpan=document.createElement('span');timeSpan.textContent=fmtTime(f.timestamp);meta.appendChild(timeSpan);
    var detSpan=document.createElement('span');detSpan.textContent=f.detector;meta.appendChild(detSpan);
    if(f.location){var locSpan=document.createElement('span');locSpan.textContent=f.location;meta.appendChild(locSpan);}
    body.appendChild(meta);item.appendChild(body);
    if(f.action_taken){var action=document.createElement('span');action.className='feed-action';
      action.textContent=f.action_taken;item.appendChild(action);}
    el.appendChild(item);
  });
}
function renderActiveSessions(sessions){
  var el=document.getElementById('active-sessions');el.replaceChildren();
  if(!sessions||!sessions.length){
    var em=document.createElement('div');em.className='empty';
    em.textContent='No active sessions';el.appendChild(em);return;}
  sessions.forEach(function(s){
    var card=document.createElement('div');card.className='session-card';
    card.style.cursor='pointer';
    card.addEventListener('click',function(){
      navigate('findings');
      setTimeout(function(){
        document.getElementById('f-sess').value=s.session_id;
        findPage=0;loadFindings();
      },100);
    });
    var head=document.createElement('div');head.className='session-head';
    var idEl=document.createElement('div');idEl.className='session-id';
    idEl.textContent=s.client_name?(s.client_name+' \u00b7 '):'';
    idEl.textContent+=(s.session_id||'').slice(0,12)+(s.session_id&&s.session_id.length>12?'\u2026':'');
    idEl.title=s.session_id||'';head.appendChild(idEl);
    var cnt=document.createElement('div');cnt.className='session-count';
    cnt.textContent=s.finding_count+' finding'+(s.finding_count!==1?'s':'');head.appendChild(cnt);
    card.appendChild(head);
    if(s.working_directory||s.account_id){
      var meta=document.createElement('div');meta.className='session-meta';
      meta.textContent=s.working_directory||s.account_id||'';
      meta.title=meta.textContent;card.appendChild(meta);}
    var sevs=document.createElement('div');sevs.className='session-sevs';
    ['critical','high','warning','info'].forEach(function(sev){
      var count=s[sev+'_count']||0;if(!count)return;
      var dot=document.createElement('span');dot.className='session-sev-dot '+sev;
      dot.textContent=count+' '+sev;sevs.appendChild(dot);
    });
    if(sevs.children.length)card.appendChild(sevs);
    var timeEl=document.createElement('div');timeEl.className='session-meta';
    timeEl.textContent='Last seen: '+fmtTime(s.last_seen);card.appendChild(timeEl);
    el.appendChild(card);
  });
}
function renderPipelineHealth(stages){
  var el=document.getElementById('pipeline-health');el.replaceChildren();
  if(!stages||!stages.length){
    var em=document.createElement('div');em.className='empty';em.textContent='loading...';el.appendChild(em);return;}
  stages.forEach(function(s){
    var item=document.createElement('div');item.className='health-item';
    var cls=!s.available?'unavail':s.enabled?'on':'off';
    var dot=document.createElement('div');dot.className='health-dot '+cls;item.appendChild(dot);
    var name=document.createElement('div');name.className='health-name';name.textContent=s.label;item.appendChild(name);
    var status=document.createElement('div');status.className='health-status '+cls;
    status.textContent=!s.available?'n/a':s.enabled?'on':'off';item.appendChild(status);
    el.appendChild(item);
  });
}
function initColToggles(){var el=document.getElementById('col-toggle');el.replaceChildren();
  for(var i=0;i<ALL_COLS.length;i++){(function(idx){
    var btn=document.createElement('div');btn.className='col-btn'+(ALL_COLS[idx].on?' on':'');
    btn.textContent=ALL_COLS[idx].label;
    btn.addEventListener('click',function(){ALL_COLS[idx].on=!ALL_COLS[idx].on;
      btn.classList.toggle('on');renderFindingsTable();});
    el.appendChild(btn);})(i);}}
