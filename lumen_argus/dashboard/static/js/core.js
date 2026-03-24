/* core.js — registerPage API, navigation, CSRF, fetch helpers, pagination */
var SEV_VALID={critical:1,high:1,warning:1,info:1};
var VALID_PAGES={dashboard:1,findings:1,audit:1,settings:1};
var _registeredPages={};

function csrfToken(){var m=document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);return m?m[1]:'';}
function csrfHeaders(extra){var h={'X-CSRF-Token':csrfToken()};if(extra)for(var k in extra)h[k]=extra[k];return h;}

/* Static SVG icon constants — NOT user data, safe for innerHTML */
var ICONS={
 critical:'<svg viewBox="0 0 24 24" fill="none" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
 high:'<svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
 warning:'<svg viewBox="0 0 24 24" fill="none" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
 info:'<svg viewBox="0 0 24 24" fill="none" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
};

var ALL_COLS=[
  {key:'timestamp',label:'Time',cls:'col-time',on:true},{key:'detector',label:'Detector',cls:'',on:true},
  {key:'finding_type',label:'Type',cls:'col-type',on:true},{key:'severity',label:'Severity',cls:'',on:true},
  {key:'action_taken',label:'Action',cls:'',on:true},{key:'location',label:'Location',cls:'col-loc',on:true},
  {key:'provider',label:'Provider',cls:'',on:false},{key:'model',label:'Model',cls:'',on:false},
  {key:'session_id',label:'Session',cls:'col-loc',on:false},{key:'account_id',label:'Account',cls:'col-loc',on:false},
  {key:'device_id',label:'Device',cls:'col-loc',on:false},{key:'working_directory',label:'Directory',cls:'col-loc',on:false},
  {key:'git_branch',label:'Branch',cls:'',on:false},{key:'client_name',label:'Client',cls:'',on:false},
  {key:'id',label:'ID',cls:'col-time',on:false}
];

var sortCol='id',sortAsc=false,selectedFindingId=null,allFindings=[],findTotal=0;
var findPage=0,findPerPage=25,auditPage=0,auditPerPage=25;

function _ensureNavTab(name, label, order) {
  var nav = document.getElementById('nav');
  var existing = nav.querySelector('[data-page="'+name+'"]');
  if (existing) {
    var lbl = existing.querySelector('.nav-label');
    if (lbl) lbl.textContent = label;
    return;
  }
  var tab = document.createElement('div');
  tab.className = 'nav-tab';
  tab.setAttribute('data-page', name);
  tab.setAttribute('data-order', order || 99);
  var lblSpan = document.createElement('span');
  lblSpan.className = 'nav-label';
  lblSpan.textContent = label;
  tab.appendChild(lblSpan);
  if (_registeredPages[name] && _registeredPages[name].locked) {
    var lock = document.createElement('span');
    lock.className = 'lock-icon';
    lock.textContent = '\uD83D\uDD12';
    tab.appendChild(lock);
  }
  /* Insert in order */
  var tabs = nav.querySelectorAll('.nav-tab');
  var inserted = false;
  for (var i = 0; i < tabs.length; i++) {
    var tabOrder = Number.parseInt(tabs[i].getAttribute('data-order') || '99');
    if ((order || 99) < tabOrder) {
      nav.insertBefore(tab, tabs[i]);
      inserted = true;
      break;
    }
  }
  if (!inserted) nav.appendChild(tab);
}

function registerPage(name, label, options) {
  options = options || {};
  var existing = _registeredPages[name];
  /* If unlocking a locked placeholder, clear the upgrade prompt */
  if (existing && existing.locked && !options.locked) {
    var container = document.getElementById('page-' + name);
    if (container) container.replaceChildren();
    /* Remove lock icon from nav tab */
    var nav = document.getElementById('nav');
    var tab = nav.querySelector('[data-page="'+name+'"]');
    if (tab) {
      var lockIcon = tab.querySelector('.lock-icon');
      if (lockIcon) lockIcon.remove();
    }
  }
  _registeredPages[name] = options;
  VALID_PAGES[name] = 1;
  _ensureNavTab(name, label, options.order);
  if (!document.getElementById('page-' + name)) {
    var div = document.createElement('div');
    div.className = 'page';
    div.id = 'page-' + name;
    document.querySelector('.shell').appendChild(div);
  }
  /* If plugin provides HTML template, inject safely into the page container */
  if (options.html) {
    var container = document.getElementById('page-' + name);
    if (container && !container.children.length) {
      _safeInjectHTML(container, options.html);
    }
  }
  /* If locked, render upgrade prompt */
  if (options.locked) {
    var page = document.getElementById('page-' + name);
    if (page && !page.children.length) {
      _renderUpgradePrompt(page, label, options.proDescription || '');
    }
  }
  /* If this page is currently active, call loadFn immediately
     (handles case where user navigated via URL hash before plugin loaded) */
  if (options.loadFn) {
    var activePage = document.getElementById('page-' + name);
    if (activePage && activePage.classList.contains('active')) {
      options.loadFn();
    }
  }
}

function _renderUpgradePrompt(container, label, description) {
  var wrap = document.createElement('div');
  wrap.className = 'upgrade-prompt';
  var card = document.createElement('div');
  card.className = 'upgrade-card';
  var h3 = document.createElement('h3');
  h3.textContent = '\uD83D\uDD12 ' + label + ' ';
  var badge = document.createElement('span');
  badge.className = 'pro-badge';
  badge.textContent = 'PRO';
  h3.appendChild(badge);
  card.appendChild(h3);
  var p = document.createElement('p');
  p.textContent = description;
  card.appendChild(p);
  var btns = document.createElement('div');
  btns.className = 'upgrade-btns';
  var trial = document.createElement('a');
  trial.className = 'btn btn-primary btn-sm';
  trial.textContent = 'Start Free Trial';
  trial.href = 'https://lumen-argus.com/trial';
  trial.target = '_blank';
  btns.appendChild(trial);
  var license = document.createElement('div');
  license.className = 'btn btn-sm';
  license.textContent = 'Enter License Key';
  license.addEventListener('click', function(){navigate('settings')});
  btns.appendChild(license);
  card.appendChild(btns);
  wrap.appendChild(card);
  container.appendChild(wrap);
}

function navigate(p){
  if(!VALID_PAGES[p])return;
  document.querySelectorAll('.page').forEach(function(e){e.classList.remove('active')});
  document.querySelectorAll('.nav-tab').forEach(function(e){e.classList.remove('active')});
  var el=document.getElementById('page-'+p);if(el)el.classList.add('active');
  var tabs=document.querySelectorAll('.nav-tab');
  for(var i=0;i<tabs.length;i++){if(tabs[i].getAttribute('data-page')===p)tabs[i].classList.add('active');}
  var curHash=location.hash.replace('#','');
  if(curHash.split('?')[0]!==p)location.hash=p;
  /* Call page's loadFn if registered */
  var reg = _registeredPages[p];
  if (reg && reg.loadFn) reg.loadFn();
  if(p==='findings')loadFindings();
  if(p==='audit')loadAudit();
  if(p==='settings')loadSettings();
}

document.getElementById('nav').addEventListener('click',function(e){
  var t=e.target.closest('.nav-tab');if(t)navigate(t.getAttribute('data-page'));});

function initRoute(){var h=location.hash.replace('#','');
  var p=h.split('?')[0];
  if(VALID_PAGES[p])navigate(p);}

function fmtTime(ts){try{var d=new Date(ts),now=new Date(),s=(now-d)/1000;
  if(s<60)return Math.floor(s)+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';
  if(s<86400)return Math.floor(s/3600)+'h ago';
  return d.toISOString().slice(5,16).replace('T',' ');}catch(e){return ts}}

function fmtUptime(s){if(s<60)return Math.round(s)+'s';
  if(s<3600)return Math.floor(s/60)+'m '+Math.round(s%60)+'s';
  return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';}

function sevCls(s){return SEV_VALID[s]?s:'info'}

function renderPager(containerId,currentPage,totalItems,perPage,onPageChange,onPerPageChange){
  var el=document.getElementById(containerId);el.replaceChildren();
  if(totalItems<=0){el.style.display='none';return;}
  el.style.display='flex';
  var info=document.createElement('div');info.className='pager-info';
  var start=currentPage*perPage+1;var end=Math.min((currentPage+1)*perPage,totalItems);
  info.textContent=start+'\u2013'+end+' of '+totalItems;
  el.appendChild(info);
  var totalPages=Math.ceil(totalItems/perPage);
  var sizeWrap=document.createElement('div');sizeWrap.className='pager-size';
  var sizeLbl=document.createElement('label');sizeLbl.textContent='Show';
  var sizeSel=document.createElement('select');
  [10,15,25,50,100].forEach(function(n){
    var opt=document.createElement('option');opt.value=String(n);opt.textContent=String(n);
    if(n===perPage)opt.selected=true;sizeSel.appendChild(opt);});
  sizeSel.addEventListener('change',function(){onPerPageChange(Number.parseInt(sizeSel.value))});
  sizeWrap.appendChild(sizeLbl);sizeWrap.appendChild(sizeSel);
  el.appendChild(sizeWrap);
  if(totalPages>1){
    var btns=document.createElement('div');btns.className='pager-btns';
    var prev=document.createElement('div');prev.className='pager-btn'+(currentPage===0?' disabled':'');
    prev.textContent='\u2190 Prev';
    if(currentPage>0)prev.addEventListener('click',function(){onPageChange(currentPage-1)});
    btns.appendChild(prev);
    var startP=Math.max(0,currentPage-3);var endP=Math.min(totalPages,startP+7);
    if(endP-startP<7)startP=Math.max(0,endP-7);
    for(var i=startP;i<endP;i++){(function(pg){
      var btn=document.createElement('div');btn.className='pager-btn'+(pg===currentPage?' active':'');
      btn.textContent=String(pg+1);
      btn.addEventListener('click',function(){onPageChange(pg)});
      btns.appendChild(btn);
    })(i);}
    var next=document.createElement('div');next.className='pager-btn'+(currentPage>=totalPages-1?' disabled':'');
    next.textContent='Next \u2192';
    if(currentPage<totalPages-1)next.addEventListener('click',function(){onPageChange(currentPage+1)});
    btns.appendChild(next);
    el.appendChild(btns);
  }
}

function _safeInjectHTML(container, html) {
  var parser = new DOMParser();
  var doc = parser.parseFromString(html, 'text/html');
  doc.querySelectorAll('script').forEach(function(s) { s.remove(); });
  doc.body.querySelectorAll('*').forEach(function(el) {
    for (var i = el.attributes.length - 1; i >= 0; i--) {
      if (el.attributes[i].name.startsWith('on')) {
        el.removeAttribute(el.attributes[i].name);
      }
    }
  });
  while (doc.body.firstChild) {
    container.appendChild(doc.body.firstChild);
  }
}

/* Pro charts hook — Pro JS calls registerCharts(fn) to render advanced analytics */
var _proChartsRenderer=null;
var _proChartsLastFetch=0;
var _proChartsAvailable=null; /* null=unknown, true=Pro active, false=402 */
function registerCharts(fn){_proChartsRenderer=fn;_proChartsAvailable=true;}
function renderProCharts(days,force){
  var container=document.getElementById('pro-charts');
  if(!container||!_proChartsRenderer)return;
  if(_proChartsAvailable===false)return;
  /* Throttle: refresh at most every 60s unless forced (range toggle, initial load) */
  var now=Date.now();
  if(!force&&_proChartsLastFetch&&(now-_proChartsLastFetch)<60000)return;
  _proChartsLastFetch=now;
  fetch('/api/v1/stats/advanced?days='+days).then(function(r){
    if(r.status===402){_proChartsAvailable=false;container.replaceChildren();return;}
    _proChartsAvailable=true;
    return r.json();
  }).then(function(data){
    if(data)_proChartsRenderer(container,data);
  }).catch(function(){});
}

function showPageError(containerId,msg,retryFn){
  var el=document.getElementById(containerId);if(!el)return;el.replaceChildren();
  var wrap=document.createElement('div');wrap.className='empty';
  var txt=document.createElement('div');txt.style.color='var(--critical)';txt.textContent=msg||'Failed to load data';
  wrap.appendChild(txt);
  if(retryFn){var btn=document.createElement('div');btn.className='btn btn-sm';btn.textContent='Retry';
    btn.style.cssText='margin:12px auto 0;display:inline-block';
    btn.addEventListener('click',retryFn);wrap.appendChild(btn);}
  el.appendChild(wrap);
}
