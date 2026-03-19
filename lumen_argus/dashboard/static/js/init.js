/* init.js — hash router, SSE client, locked page registration, startup
   MUST be last — depends on all page modules */

/* Register community nav tabs in order */
registerPage('dashboard', 'Dashboard', {order: 10, loadFn: function(){}});
registerPage('findings', 'Findings', {order: 15, loadFn: loadFindings});
registerPage('audit', 'Audit', {order: 60, loadFn: loadAudit});
registerPage('settings', 'Settings', {order: 70, loadFn: loadSettings});

/* Register locked Pro placeholders */
registerPage('rules', 'Rules', {locked: true, order: 25,
  proDescription: 'Create custom detection rules with regex patterns, keywords, and size limits. Manage rule priorities and per-rule actions.'});
registerPage('patterns', 'Patterns', {locked: true, order: 35,
  proDescription: 'Browse and toggle 1,600+ secret detection patterns. Filter by category, confidence level, and enable/disable individual patterns.'});
registerPage('allowlists', 'Allowlists', {locked: true, order: 45,
  proDescription: 'Manage allowlist entries for secrets, PII, and file paths. Test patterns against recent findings before adding.'});
registerPage('notifications', 'Notifications', {order: 55, loadFn: loadNotifications});

/* Export helpers */
function exportFindings(fmt){
  var url='/api/v1/findings/export?format='+fmt;
  var sevF=document.getElementById('f-sev').value;
  var detF=document.getElementById('f-det').value;
  var provF=document.getElementById('f-prov').value;
  var sessF=document.getElementById('f-sess').value;
  if(sevF)url+='&severity='+encodeURIComponent(sevF);
  if(detF)url+='&detector='+encodeURIComponent(detF);
  if(provF)url+='&provider='+encodeURIComponent(provF);
  if(sessF)url+='&session_id='+encodeURIComponent(sessF);
  window.location.href=url;
}
document.getElementById('export-csv').addEventListener('click',function(){exportFindings('csv')});
document.getElementById('export-json').addEventListener('click',function(){exportFindings('json')});

/* SSE / POLLING TOGGLE */
var sseMode=localStorage.getItem('lumen_sse_mode')==='true';
var sseSource=null;
var pollTimer=null;

async function loadData(){try{
  var r=await Promise.all([fetch('/api/v1/status').then(function(r){return r.json()}),
    fetch('/api/v1/stats').then(function(r){return r.json()}),
    fetch('/api/v1/findings?limit='+dashPerPage+'&offset='+dashPage*dashPerPage).then(function(r){return r.json()})]);
  var st=r[0],stats=r[1],fd=r[2];
  document.getElementById('hdr-status').textContent='operational';
  document.getElementById('hdr-version').textContent='v'+st.version;
  document.getElementById('hdr-uptime').textContent=fmtUptime(st.uptime_seconds);
  document.getElementById('total-badge').textContent=stats.total_findings.toLocaleString()+' findings';
  var cards=document.getElementById('cards');cards.replaceChildren();
  ['critical','high','warning','info'].forEach(function(s){cards.appendChild(makeCard(s,stats.by_severity[s]||0));});
  if(stats.daily_trend&&stats.daily_trend.length>1)renderChart(stats.daily_trend);
  if(stats.by_detector)renderBars('det-list',stats.by_detector);
  if(stats.by_provider)renderBars('prov-list',stats.by_provider);
  var dtb=document.getElementById('dash-tbody');dtb.replaceChildren();
  var dashTotal=fd.total;
  var dashStart=dashPage*dashPerPage;
  var recent=fd.findings||[];
  document.getElementById('dash-showing').textContent=
    (dashTotal?dashStart+1+'\u2013'+Math.min(dashStart+recent.length,dashTotal):'0')+' of '+dashTotal;
  if(!recent.length){var tr=document.createElement('tr');var td=document.createElement('td');
    td.colSpan=6;td.className='empty';td.textContent='No findings yet';tr.appendChild(td);dtb.appendChild(tr);}
  else recent.forEach(function(f){dtb.appendChild(dashRow(f))});
  renderPager('dash-pager',dashPage,fd.total,dashPerPage,
    function(pg){dashPage=pg;loadData();},
    function(pp){dashPerPage=pp;dashPage=0;loadData();});
  if(stats.by_detector){
    var detSel=document.getElementById('f-det'),curVal=detSel.value;
    while(detSel.options.length>1)detSel.removeChild(detSel.lastChild);
    Object.keys(stats.by_detector).sort(function(a,b){return a.localeCompare(b)}).forEach(function(d){var opt=document.createElement('option');
      opt.value=d;opt.textContent=d;detSel.appendChild(opt);});
    detSel.value=curVal;}
  if(stats.by_provider){
    var provSel=document.getElementById('f-prov'),curProv=provSel.value;
    while(provSel.options.length>1)provSel.removeChild(provSel.lastChild);
    Object.keys(stats.by_provider).sort(function(a,b){return a.localeCompare(b)}).forEach(function(p){var opt=document.createElement('option');
      opt.value=p;opt.textContent=p;provSel.appendChild(opt);});
    provSel.value=curProv;}
  var findingsActive=document.getElementById('page-findings').classList.contains('active');
  if(findingsActive)loadFindings();
  }catch(e){document.getElementById('hdr-status').textContent='connection error';}}

function startPolling(){
  document.getElementById('live-label').textContent='5s';
  document.getElementById('live-toggle').classList.remove('live','reconnecting');
  if(pollTimer)return;
  pollTimer=setInterval(loadData,5000);
}
function stopPolling(){if(pollTimer){clearInterval(pollTimer);pollTimer=null;}}
function startSSE(){
  if(sseSource)return;
  sseSource=new EventSource('/api/v1/live');
  var sseConnectedOnce=false;
  sseSource.addEventListener('connected',function(){
    document.getElementById('live-label').textContent='Live';
    document.getElementById('live-toggle').classList.remove('reconnecting');
    document.getElementById('live-toggle').classList.add('live');
    if(sseConnectedOnce){var p=location.hash.replace('#','')||'dashboard';
      if(VALID_PAGES[p])navigate(p);}
    sseConnectedOnce=true;
  });
  sseSource.addEventListener('finding',function(){loadData();});
  sseSource.addEventListener('heartbeat',function(){
    document.getElementById('live-label').textContent='Live';
    document.getElementById('live-toggle').classList.remove('reconnecting');
    document.getElementById('live-toggle').classList.add('live');
  });
  sseSource.onerror=function(){
    document.getElementById('live-label').textContent='...';
    document.getElementById('live-toggle').classList.remove('live');
    document.getElementById('live-toggle').classList.add('reconnecting');
  };
}
function stopSSE(){if(sseSource){sseSource.close();sseSource=null;}
  document.getElementById('live-toggle').classList.remove('live','reconnecting');}
function toggleLiveMode(){
  sseMode=!sseMode;
  localStorage.setItem('lumen_sse_mode',sseMode?'true':'false');
  if(sseMode){stopPolling();startSSE();}
  else{stopSSE();startPolling();}
}
document.getElementById('live-toggle').addEventListener('click',toggleLiveMode);

/* Initialize */
initColToggles();loadData();
if(sseMode){startSSE();}else{startPolling();}
initRoute();
window.addEventListener('hashchange',initRoute);
