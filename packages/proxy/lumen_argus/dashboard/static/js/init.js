/* init.js — hash router, SSE client, locked page registration, startup
   MUST be last — depends on all page modules */

/* Register community nav tabs in order */
registerPage('dashboard', 'Dashboard', {order: 10, loadFn: loadData});
registerPage('findings', 'Findings', {order: 15, loadFn: loadFindings});
registerPage('audit', 'Audit', {order: 60, loadFn: loadAudit});
registerPage('pipeline', 'Pipeline', {order: 65, loadFn: loadPipeline});
registerPage('settings', 'Settings', {order: 90, loadFn: loadSettings});

/* Rules page is registered in rules.js (community-owned) */
/* Allowlists page is registered in allowlists.js (community-owned) */
registerPage('notifications', 'Notifications', {order: 55, loadFn: loadNotifications});
registerPage('enrollment', 'Enrollment', {hidden: true, order: 80});

/* Export helpers */
function exportFindings(fmt){
  let url='/api/v1/findings/export?format='+fmt;
  const filters={severity:'f-sev',detector:'f-det',provider:'f-prov',
    session_id:'f-sess',action:'f-action',finding_type:'f-type',
    client:'f-client',days:'f-days'};
  for(const k in filters){const v=document.getElementById(filters[k]).value;
    if(v)url+='&'+k+'='+encodeURIComponent(v);}
  window.location.href=url;
}
document.getElementById('export-csv').addEventListener('click',function(){exportFindings('csv')});
document.getElementById('export-json').addEventListener('click',function(){exportFindings('json')});

/* TIME RANGE TOGGLE */
let trendDays=Number.parseInt(localStorage.getItem('lumen_trend_days'))||30;
(function initRange(){
  const btns=document.querySelectorAll('#range-toggle .range-btn');
  btns.forEach(function(b){
    if(Number.parseInt(b.getAttribute('data-days'))===trendDays)
      {b.classList.add('active');}else{b.classList.remove('active');}
    b.addEventListener('click',function(){
      btns.forEach(function(x){x.classList.remove('active')});
      b.classList.add('active');
      trendDays=Number.parseInt(b.getAttribute('data-days'));
      localStorage.setItem('lumen_trend_days',String(trendDays));
      document.getElementById('trend-title').textContent=trendDays+'-day trend';
      _forceProCharts=true;loadData();
    });
  });
  document.getElementById('trend-title').textContent=trendDays+'-day trend';
})();

/* SSE / POLLING TOGGLE */
let _forceProCharts=true; /* force on initial load */
let sseMode=localStorage.getItem('lumen_sse_mode')==='true';
let sseSource=null;
let pollTimer=null;
let _pipelineStages=null; /* cached — fetched once */

async function loadData(){try{
  const fetches=[
    fetch('/api/v1/status').then(function(r){return r.json()}),
    fetch('/api/v1/stats?days='+trendDays).then(function(r){return r.json()}),
    fetch('/api/v1/findings?limit=8').then(function(r){return r.json()}),
    fetch('/api/v1/sessions/dashboard?limit=5').then(function(r){return r.json()})
  ];
  /* Fetch pipeline stages once (they rarely change) */
  if(!_pipelineStages){
    fetches.push(fetch('/api/v1/pipeline').then(function(r){return r.json()}));
  }
  const r=await Promise.all(fetches);
  const st=r[0],stats=r[1],fd=r[2],sess=r[3];
  if(r[4])_pipelineStages=r[4].stages||[];
  /* Expose status to plugin modules. Populated when this loadData()
     call resolves — plugin modules that need to read these during
     their own init or page loadFn should first await
     window._loadDataPromise (exposed at the bottom of this file).
     Once resolved, later reads are synchronous because polling /
     SSE refreshes update these in place. */
  window._statusData=st;
  window._licenseTier=(st&&st.tier)||'community';
  document.getElementById('hdr-status').textContent='operational';
  document.getElementById('hdr-version').textContent='v'+st.version;
  document.getElementById('hdr-uptime').textContent=fmtUptime(st.uptime_seconds);
  /* Quick stats */
  const sessionList=sess.sessions||[];
  const sessionTotal=sess.total||0;
  renderQuickStats(stats,sessionTotal);
  /* Trend chart */
  const chartSvg=document.getElementById('chart');
  if(stats.daily_trend&&stats.daily_trend.length){
    let trend=stats.daily_trend;
    if(trend.length===1){const ymd=trend[0].date.split('-');
      const d=new Date(Date.UTC(+ymd[0],+ymd[1]-1,+ymd[2]-1));
      const prev=d.toISOString().slice(0,10);trend=[{date:prev,count:0}].concat(trend);}
    chartSvg.parentNode.classList.remove('chart-empty');
    renderChart(trend);
  } else {
    while(chartSvg.firstChild)chartSvg.removeChild(chartSvg.firstChild);
    chartSvg.parentNode.classList.add('chart-empty');
    let emptyEl=chartSvg.parentNode.querySelector('.chart-empty-msg');
    if(!emptyEl){emptyEl=document.createElement('div');emptyEl.className='chart-empty-msg';
      emptyEl.textContent='Findings will appear here as requests are scanned';
      chartSvg.parentNode.appendChild(emptyEl);}
  }
  if(stats.by_detector)renderBars('det-list',stats.by_detector);
  if(stats.by_provider)renderBars('prov-list',stats.by_provider);
  const _f=_forceProCharts;_forceProCharts=false;renderProCharts(trendDays,_f);
  /* Bottom panels */
  renderActivityFeed(fd.findings||[]);
  renderActiveSessions(sessionList);
  if(_pipelineStages)renderPipelineHealth(_pipelineStages);
  /* Populate findings page filter dropdowns from stats */
  _populateDynamicFilters(stats);
  const findingsActive=document.getElementById('page-findings').classList.contains('active');
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
  let sseConnectedOnce=false;
  sseSource.addEventListener('connected',function(){
    document.getElementById('live-label').textContent='Live';
    document.getElementById('live-toggle').classList.remove('reconnecting');
    document.getElementById('live-toggle').classList.add('live');
    if(sseConnectedOnce){const p=location.hash.replace('#','')||'dashboard';
      if(VALID_PAGES[p])navigate(p);}
    sseConnectedOnce=true;
  });
  sseSource.addEventListener('finding',function(){loadData();});
  sseSource.addEventListener('rule_analysis_complete',function(){
    if(typeof loadRuleAnalysis==='function')loadRuleAnalysis();
    document.dispatchEvent(new CustomEvent('rule_analysis_complete'));
  });
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

/* Invalidate pipeline cache when pipeline page saves */
document.addEventListener('pipeline-rendered',function(){_pipelineStages=null;});

/* Initialize */
initColToggles();
/* Expose the initial loadData() promise so plugin modules can await
   the first /api/v1/status fetch before reading window._statusData /
   window._licenseTier. Without this, a plugin that runs at script-parse
   time or during a direct-hash navigation loadFn (e.g. bookmarking
   #mcp) would see undefined globals because loadData() is not awaited
   before initRoute() fires. See the "Dashboard Status Data Sharing"
   contract in docs/development/extensions.md. Only the initial call
   is tracked — once it resolves, subsequent polling/SSE refreshes
   update window._statusData in place, so plugin code can read the
   globals synchronously after the first await. */
window._loadDataPromise=loadData();
if(sseMode){startSSE();}else{startPolling();}
initRoute();
window.addEventListener('hashchange',initRoute);
