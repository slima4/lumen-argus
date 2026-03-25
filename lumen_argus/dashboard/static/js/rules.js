/* rules.js — Detection rules management page (community).
   Paginated list with search/filters, stat chips, tag chips, rule cards
   with toggle/action/clone/delete, add/edit form with regex test. */

var _rulesPage=0,_rulesPerPage=25,_rulesTotal=0,_rulesTag='',_editingRule=null;

var _rulesHtml=''
+'<div class="sh"><h2>Detection Rules</h2><span class="count" id="rules-total"></span>'
+'<div class="btn btn-primary btn-sm" id="add-rule-btn">+ Add Rule</div></div>'
+'<div id="rules-stats" class="rules-stat-row"></div>'
+'<div id="rules-tags" class="rules-tag-row"></div>'
+'<div class="add-form" id="rule-form">'
+'<h3 id="rule-form-title">Add custom rule</h3>'
+'<div class="form-row"><label>Name</label><input id="rf-name" placeholder="internal_api_token"></div>'
+'<div class="form-row"><label>Pattern</label><input id="rf-pattern" placeholder="itk_[a-zA-Z0-9]{32}"></div>'
+'<div class="form-row"><label>Detector</label>'
+'<select id="rf-detector"><option value="secrets">Secrets</option>'
+'<option value="pii">PII</option><option value="injection">Injection</option>'
+'<option value="custom">Custom</option></select></div>'
+'<div class="form-row"><label>Severity</label>'
+'<select id="rf-severity"><option value="critical">Critical</option>'
+'<option value="high">High</option><option value="warning" selected>Warning</option>'
+'<option value="info">Info</option></select></div>'
+'<div class="form-row"><label>Action</label>'
+'<select id="rf-action"><option value="">Default</option><option value="log">Log</option>'
+'<option value="alert">Alert</option><option value="block">Block</option></select></div>'
+'<div class="form-row"><label>Description</label><input id="rf-desc" placeholder="Human-readable description"></div>'
+'<div class="form-row"><label>Tags</label><input id="rf-tags" placeholder="cloud, credentials (comma-separated)"></div>'
+'<div class="form-row"><label>Test</label>'
+'<input id="rf-test-input" placeholder="Enter sample text to test pattern">'
+'<div class="btn btn-sm btn-cancel" id="rf-test-btn">Test</div></div>'
+'<div id="rf-test-result" style="font-family:var(--font-data);font-size:.78rem;margin-bottom:8px;color:var(--text-secondary)"></div>'
+'<div class="form-error" id="rf-error"></div>'
+'<div class="form-actions">'
+'<div class="btn btn-primary" id="rf-save">Save</div>'
+'<div class="btn btn-cancel" id="rf-cancel">Cancel</div>'
+'</div></div>'
+'<div class="filter-bar">'
+'<input id="r-search" type="text" placeholder="Search rules..." style="flex:1;min-width:160px">'
+'<div class="filter-group"><label>Tier</label><select id="r-tier"><option value="">All</option>'
+'<option value="community">Community</option><option value="pro">Pro</option>'
+'<option value="custom">Custom</option></select></div>'
+'<div class="filter-group"><label>Detector</label><select id="r-det"><option value="">All</option>'
+'<option value="secrets">Secrets</option><option value="pii">PII</option>'
+'<option value="injection">Injection</option><option value="custom">Custom</option></select></div>'
+'<div class="filter-group"><label>Severity</label><select id="r-sev"><option value="">All</option>'
+'<option value="critical">Critical</option><option value="high">High</option>'
+'<option value="warning">Warning</option><option value="info">Info</option></select></div>'
+'<div class="filter-group"><label>Status</label><select id="r-enabled"><option value="">All</option>'
+'<option value="true">Enabled</option><option value="false">Disabled</option></select></div>'
+'</div>'
+'<div id="rules-list"></div>'
+'<div class="pager" id="rules-pager"></div>';

registerPage('rules','Rules',{order:25,loadFn:loadRules,html:_rulesHtml});

function loadRules(){
  _wireRulesEvents();
  /* Read hash query params (e.g. #rules?q=stripe_secret_key) */
  var hashParts=location.hash.replace('#','').split('?');
  if(hashParts.length>1){
    var hp={};hashParts[1].split('&').forEach(function(p){
      var kv=p.split('=');if(kv.length===2)hp[kv[0]]=decodeURIComponent(kv[1]);});
    if(hp.q){
      var si=document.getElementById('r-search');
      if(si){si.value=hp.q;_rulesPage=0;}
    }
    /* Clear hash params after applying — keep just the page name */
    history.replaceState(null,'','#rules');
  }
  var url='/api/v1/rules?limit='+_rulesPerPage+'&offset='+_rulesPage*_rulesPerPage;
  var search=document.getElementById('r-search');if(search&&search.value)url+='&search='+encodeURIComponent(search.value);
  var tier=document.getElementById('r-tier');if(tier&&tier.value)url+='&tier='+encodeURIComponent(tier.value);
  var det=document.getElementById('r-det');if(det&&det.value)url+='&detector='+encodeURIComponent(det.value);
  var sev=document.getElementById('r-sev');if(sev&&sev.value)url+='&severity='+encodeURIComponent(sev.value);
  var en=document.getElementById('r-enabled');if(en&&en.value)url+='&enabled='+en.value;
  if(_rulesTag)url+='&tag='+encodeURIComponent(_rulesTag);
  Promise.all([
    fetch(url).then(function(r){return r.json()}),
    fetch('/api/v1/rules/stats').then(function(r){return r.json()})
  ]).then(function(res){
    var data=res[0],stats=res[1];
    _rulesTotal=data.total;
    document.getElementById('rules-total').textContent=_rulesTotal+' rules';
    _renderRulesStats(stats);
    _renderRulesTags(stats.tags||[]);
    _renderRulesList(data.rules||[]);
    renderPager('rules-pager',_rulesPage,_rulesTotal,_rulesPerPage,
      function(p){_rulesPage=p;loadRules()},
      function(pp){_rulesPerPage=pp;_rulesPage=0;loadRules()});
  }).catch(function(e){
    showPageError('rules-list','Failed to load rules: '+e.message,loadRules);
  });
}

function _renderRulesStats(stats){
  var el=document.getElementById('rules-stats');if(!el)return;el.replaceChildren();
  var items=[
    {label:'Total',value:stats.total||0,cls:''},
    {label:'Community',value:(stats.by_tier||{}).community||0,cls:'community'},
    {label:'Pro',value:(stats.by_tier||{}).pro||0,cls:'pro'},
    {label:'Custom',value:(stats.by_tier||{}).custom||0,cls:'custom'},
    {label:'Enabled',value:stats.enabled||0,cls:''},
    {label:'Disabled',value:stats.disabled||0,cls:''}
  ];
  items.forEach(function(it){
    var chip=document.createElement('span');chip.className='stat-chip'+(it.cls?' '+it.cls:'');
    chip.textContent=it.label+': '+it.value;el.appendChild(chip);
  });
}

function _renderRulesTags(tags){
  var el=document.getElementById('rules-tags');if(!el)return;el.replaceChildren();
  if(!tags.length)return;
  tags.forEach(function(t){
    var chip=document.createElement('span');
    chip.className='cat-chip'+(_rulesTag===t.tag?' active':'');
    chip.textContent=t.tag;
    var cnt=document.createElement('span');cnt.className='cat-count';
    cnt.textContent=' '+t.total;chip.appendChild(cnt);
    chip.addEventListener('click',function(){
      _rulesTag=(_rulesTag===t.tag)?'':t.tag;_rulesPage=0;loadRules();
    });
    el.appendChild(chip);
  });
}

function _renderRulesList(rules){
  var el=document.getElementById('rules-list');if(!el)return;el.replaceChildren();
  if(!rules.length){var empty=document.createElement('div');empty.className='empty';
    empty.textContent='No rules found';el.appendChild(empty);return;}
  rules.forEach(function(r){el.appendChild(_ruleCard(r))});
}

function _ruleCard(r){
  var card=document.createElement('div');card.className='rule-card';
  /* Head: name + badges + actions */
  var head=document.createElement('div');head.className='rule-head';
  var name=document.createElement('span');name.className='rule-name';name.textContent=r.name;
  head.appendChild(name);
  /* Tier badge */
  var tier=document.createElement('span');tier.className='rule-source '+(r.tier||'community');
  tier.textContent=r.tier||'community';head.appendChild(tier);
  /* Source badge */
  if(r.source&&r.source!==r.tier){
    var src=document.createElement('span');src.className='rule-src-badge';
    src.textContent=r.source;head.appendChild(src);
  }
  /* Severity badge */
  var sev=document.createElement('span');sev.className='badge '+sevCls(r.severity);
  var dot=document.createElement('span');dot.className='badge-dot';sev.appendChild(dot);
  sev.appendChild(document.createTextNode(r.severity));head.appendChild(sev);
  /* Actions area */
  var acts=document.createElement('div');acts.className='rule-actions';
  /* Toggle */
  var toggle=document.createElement('label');toggle.className='toggle';
  var cb=document.createElement('input');cb.type='checkbox';cb.checked=r.enabled;
  var track=document.createElement('span');track.className='toggle-track'+(r.enabled?' on':'');
  var thumb=document.createElement('span');thumb.className='toggle-thumb'+(r.enabled?' on':'');
  toggle.appendChild(cb);toggle.appendChild(track);toggle.appendChild(thumb);
  cb.addEventListener('change',function(){
    _updateRule(r.name,{enabled:cb.checked});
    track.className='toggle-track'+(cb.checked?' on':'');
    thumb.className='toggle-thumb'+(cb.checked?' on':'');
  });
  acts.appendChild(toggle);
  /* Action select */
  var actSel=document.createElement('select');actSel.className='rule-action-sel';
  actSel.dataset.action=r.action||'';
  [['','Default'],['log','Log'],['alert','Alert'],['block','Block']].forEach(function(opt){
    var o=document.createElement('option');o.value=opt[0];o.textContent=opt[1];
    if((r.action||'')===opt[0])o.selected=true;actSel.appendChild(o);
  });
  actSel.addEventListener('change',function(){_updateRule(r.name,{action:actSel.value})});
  acts.appendChild(actSel);
  /* Clone button */
  var cloneBtn=document.createElement('div');cloneBtn.className='btn btn-sm btn-cancel';
  cloneBtn.textContent='Clone';
  cloneBtn.addEventListener('click',function(){_cloneRule(r.name)});
  acts.appendChild(cloneBtn);
  /* Edit/Delete for dashboard rules */
  if(r.source==='dashboard'){
    var editBtn=document.createElement('div');editBtn.className='btn btn-sm btn-cancel';
    editBtn.textContent='Edit';
    editBtn.addEventListener('click',function(){_openEditForm(r)});
    acts.appendChild(editBtn);
    var delBtn=document.createElement('div');delBtn.className='btn btn-sm btn-danger';
    delBtn.textContent='Delete';
    delBtn.addEventListener('click',function(){_deleteRule(r.name)});
    acts.appendChild(delBtn);
  }
  head.appendChild(acts);card.appendChild(head);
  /* Description */
  if(r.description){
    var desc=document.createElement('div');desc.className='rule-desc';
    desc.textContent=r.description;card.appendChild(desc);
  }
  /* Pattern preview */
  var meta=document.createElement('div');meta.className='rule-meta';
  meta.textContent=r.pattern;card.appendChild(meta);
  /* Tags */
  var tags=r.tags||[];
  if(tags.length){
    var tagRow=document.createElement('div');tagRow.className='rule-tags';
    tags.forEach(function(t){
      var chip=document.createElement('span');chip.className='cat-chip';
      chip.textContent=t;chip.style.cssText='font-size:.65rem;padding:2px 6px;cursor:pointer';
      chip.addEventListener('click',function(){_rulesTag=t;_rulesPage=0;loadRules()});
      tagRow.appendChild(chip);
    });
    card.appendChild(tagRow);
  }
  return card;
}

function _updateRule(name,data){
  fetch('/api/v1/rules/'+encodeURIComponent(name),{
    method:'PUT',headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify(data)
  }).then(function(r){if(!r.ok)throw new Error('update failed');return r.json()})
  .catch(function(e){loadRules()});
}

function _cloneRule(name){
  fetch('/api/v1/rules/'+encodeURIComponent(name)+'/clone',{
    method:'POST',headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify({})
  }).then(function(r){if(!r.ok)throw new Error('clone failed');return r.json()})
  .then(function(){loadRules()})
  .catch(function(e){loadRules()});
}

function _deleteRule(name){
  if(!confirm('Delete rule "'+name+'"?'))return;
  fetch('/api/v1/rules/'+encodeURIComponent(name),{
    method:'DELETE',headers:csrfHeaders()
  }).then(function(r){if(!r.ok)throw new Error('delete failed');return r.json()})
  .then(function(){loadRules()})
  .catch(function(e){loadRules()});
}

function _resetForm(rule){
  var form=document.getElementById('rule-form');
  _editingRule=rule?rule.name:null;
  document.getElementById('rule-form-title').textContent=rule?'Edit rule: '+rule.name:'Add custom rule';
  document.getElementById('rf-name').value=rule?rule.name:'';
  document.getElementById('rf-name').disabled=!!rule;
  document.getElementById('rf-pattern').value=rule?rule.pattern:'';
  document.getElementById('rf-detector').value=rule?rule.detector||'secrets':'secrets';
  document.getElementById('rf-severity').value=rule?rule.severity||'warning':'warning';
  document.getElementById('rf-action').value=rule?rule.action||'':'';
  document.getElementById('rf-desc').value=rule?rule.description||'':'';
  document.getElementById('rf-tags').value=rule?(rule.tags||[]).join(', '):'';
  document.getElementById('rf-error').style.display='none';
  document.getElementById('rf-test-result').textContent='';
  form.classList.add('visible');
}

function _openEditForm(rule){_resetForm(rule)}
function _openAddForm(){_resetForm(null)}

function _closeForm(){
  document.getElementById('rule-form').classList.remove('visible');
  _editingRule=null;
}

function _saveRule(){
  var name=document.getElementById('rf-name').value.trim();
  var pattern=document.getElementById('rf-pattern').value.trim();
  var err=document.getElementById('rf-error');
  err.style.display='none';
  if(!name){err.textContent='Name is required';err.style.display='block';return;}
  if(!pattern){err.textContent='Pattern is required';err.style.display='block';return;}
  try{new RegExp(pattern)}catch(e){err.textContent='Invalid regex: '+e.message;err.style.display='block';return;}
  var tags=document.getElementById('rf-tags').value.split(',').map(function(t){return t.trim()}).filter(Boolean);
  var data={
    name:name,pattern:pattern,
    detector:document.getElementById('rf-detector').value,
    severity:document.getElementById('rf-severity').value,
    action:document.getElementById('rf-action').value,
    description:document.getElementById('rf-desc').value.trim(),
    tags:tags
  };
  var url,method;
  if(_editingRule){
    delete data.name;
    url='/api/v1/rules/'+encodeURIComponent(_editingRule);method='PUT';
  }else{
    url='/api/v1/rules';method='POST';
  }
  fetch(url,{method:method,headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify(data)
  }).then(function(r){return r.json().then(function(d){return{ok:r.ok,data:d}})})
  .then(function(res){
    if(!res.ok){err.textContent=res.data.error||'Save failed';err.style.display='block';return;}
    _closeForm();loadRules();
  }).catch(function(e){err.textContent=e.message;err.style.display='block'});
}

function _testPattern(){
  var pattern=document.getElementById('rf-pattern').value;
  var input=document.getElementById('rf-test-input').value;
  var result=document.getElementById('rf-test-result');
  if(!pattern||!input){result.textContent='Enter pattern and test text';return;}
  try{
    var re=new RegExp(pattern,'g');
    var matches=input.match(re);
    if(matches){
      result.textContent='Match: '+matches.join(', ');
      result.style.color='var(--accent)';
    }else{
      result.textContent='No match';
      result.style.color='var(--critical)';
    }
  }catch(e){result.textContent='Invalid regex: '+e.message;result.style.color='var(--critical)';}
}

/* Debounced search */
var _rulesSearchTimer=null;
function _onRulesSearch(){
  if(_rulesSearchTimer)clearTimeout(_rulesSearchTimer);
  _rulesSearchTimer=setTimeout(function(){_rulesPage=0;loadRules()},300);
}

/* Wire up form event listeners on first loadRules call */
var _rulesEventsWired=false;
function _wireRulesEvents(){
  if(_rulesEventsWired)return;
  _rulesEventsWired=true;
  var addBtn=document.getElementById('add-rule-btn');
  if(addBtn)addBtn.addEventListener('click',_openAddForm);
  var saveBtn=document.getElementById('rf-save');
  if(saveBtn)saveBtn.addEventListener('click',_saveRule);
  var cancelBtn=document.getElementById('rf-cancel');
  if(cancelBtn)cancelBtn.addEventListener('click',_closeForm);
  var testBtn=document.getElementById('rf-test-btn');
  if(testBtn)testBtn.addEventListener('click',_testPattern);
  var searchInput=document.getElementById('r-search');
  if(searchInput)searchInput.addEventListener('input',_onRulesSearch);
  ['r-tier','r-det','r-sev','r-enabled'].forEach(function(id){
    var el=document.getElementById(id);
    if(el)el.addEventListener('change',function(){_rulesPage=0;loadRules()});
  });
}
