/* notifications.js — notification channels page (source-aware) */
let notifTypes={};let editingChannelId=null;
const _eventOptions=[{value:'block',label:'Block'},{value:'alert',label:'Alert'},{value:'log',label:'Log'}];
function _buildEventChips(container,selected){
  container.replaceChildren();
  const sel=selected||['block','alert'];
  _eventOptions.forEach(function(opt){
    const chip=document.createElement('div');
    chip.className='col-btn'+(sel.includes(opt.value)?' on':'');
    chip.dataset.event=opt.value;
    chip.textContent=opt.label;
    chip.addEventListener('click',function(){
      this.classList.toggle('on');
      const ne=document.getElementById('notif-error');ne.textContent='';ne.style.display='none';
    });
    container.appendChild(chip);
  });
}
function _getSelectedEvents(){
  const events=[];
  document.querySelectorAll('#notif-events .col-btn.on').forEach(function(el){events.push(el.dataset.event);});
  return events;
}
function loadNotifications(){
  Promise.all([
    fetch('/api/v1/notifications/channels').then(function(r){return r.json()}),
    fetch('/api/v1/notifications/types').then(function(r){return r.json()})
  ]).then(function(res){
    const chData=res[0],typeData=res[1];
    notifTypes=typeData.types||{};
    if(chData.notifications_unavailable){
      _showUnavailable(chData.message||'');
      /* Still render any YAML channels that exist in DB */
      if(chData.channels&&chData.channels.length){
        _renderChannels(chData.channels,true);
      }
      return;
    }
    _populateTypeSelect();
    _renderChannels(chData.channels||[],false);
  }).catch(function(e){showPageError('notif-channels','Failed to load: '+e.message,loadNotifications);});
}
function _showUnavailable(message){
  const el=document.getElementById('notif-unavailable');el.style.display='block';
  el.replaceChildren();
  const banner=document.createElement('div');banner.className='panel';
  banner.style.cssText='padding:14px 18px;margin-bottom:16px;border-left:3px solid var(--warning)';
  const title=document.createElement('div');
  title.style.cssText='font-weight:600;margin-bottom:6px;color:var(--warning)';
  title.textContent='Notification dispatch unavailable';
  const desc=document.createElement('div');desc.style.cssText='font-size:.82rem;color:var(--text-secondary)';
  desc.textContent=message||'Notification dispatch requires the published package.';
  const codeWrap=document.createElement('div');codeWrap.style.cssText='margin-top:8px';
  const code=document.createElement('code');code.style.cssText='font-size:.82rem;padding:2px 6px;background:var(--bg-card);border-radius:3px';
  code.textContent='pip install lumen-argus';
  codeWrap.appendChild(code);
  const hint=document.createElement('div');hint.style.cssText='font-size:.75rem;color:var(--text-muted);margin-top:6px';
  hint.textContent='YAML-configured channels are shown below but will not dispatch until the published package is installed.';
  banner.appendChild(title);banner.appendChild(desc);banner.appendChild(codeWrap);banner.appendChild(hint);
  el.appendChild(banner);
  document.getElementById('notif-add-btn').style.display='none';
  document.getElementById('notif-enable-all').style.display='none';
  document.getElementById('notif-disable-all').style.display='none';
  document.getElementById('notif-delete-all').style.display='none';
}
function _populateTypeSelect(){
  const sel=document.getElementById('notif-type');sel.replaceChildren();
  const def=document.createElement('option');def.value='';def.textContent='Select type\u2026';sel.appendChild(def);
  for(const t in notifTypes){if(notifTypes.hasOwnProperty(t)){
    const o=document.createElement('option');o.value=t;o.textContent=notifTypes[t].label;sel.appendChild(o);}}
}
document.getElementById('notif-type').addEventListener('change',function(){
  const t=this.value;const container=document.getElementById('notif-type-fields');container.replaceChildren();
  if(!t||!notifTypes[t])return;
  const fields=notifTypes[t].fields;
  for(const key in fields){if(fields.hasOwnProperty(key)&&key!=='min_severity'){
    const f=fields[key];const row=document.createElement('div');row.className='form-row';
    const lbl=document.createElement('label');lbl.textContent=f.label+(f.required?' *':'');
    let inp;
    if(f.type==='boolean'){
      inp=document.createElement('select');inp.setAttribute('data-field',key);
      const y=document.createElement('option');y.value='true';y.textContent='Yes';
      const n=document.createElement('option');n.value='false';n.textContent='No';
      inp.appendChild(y);inp.appendChild(n);
    }else{
      inp=document.createElement('input');inp.setAttribute('data-field',key);
      inp.type=f.type==='password'?'password':(f.type==='number'?'number':'text');
      if(f.placeholder)inp.placeholder=f.placeholder;
    }
    const errMsg=document.createElement('div');errMsg.className='field-error-msg';
    errMsg.setAttribute('data-error-for',key);
    let hintEl=null;
    if(f.hint){hintEl=document.createElement('div');
      hintEl.style.cssText='font-size:.68rem;color:var(--text-muted);width:100%;padding-left:80px;margin-top:-2px';
      hintEl.textContent=f.hint;}
    inp.addEventListener('input',function(){
      this.classList.remove('field-error');
      const r=this.closest('.form-row');if(r)r.classList.remove('shake');
      const em=r&&r.querySelector('.field-error-msg');if(em)em.classList.remove('visible');
      const ne=document.getElementById('notif-error');ne.textContent='';ne.style.display='none';
    });
    row.appendChild(lbl);row.appendChild(inp);
    if(hintEl)row.appendChild(hintEl);
    row.appendChild(errMsg);container.appendChild(row);
  }}
  this.classList.remove('field-error');
  const ne=document.getElementById('notif-error');ne.textContent='';ne.style.display='none';
});
function _renderChannels(channels,readOnly){
  const el=document.getElementById('notif-channels');el.replaceChildren();
  _apiChannelIds=channels.filter(function(c){return c.source!=='yaml';}).map(function(c){return c.id;});
  if(!channels.length){const empty=document.createElement('div');empty.className='empty';
    empty.textContent='No notification channels configured. Add one to get started.';
    el.appendChild(empty);return;}
  channels.forEach(function(ch){
    const card=document.createElement('div');card.className='panel';
    card.style.cssText='margin-bottom:10px;padding:14px 18px';
    const hdr=document.createElement('div');hdr.style.cssText='display:flex;align-items:center;justify-content:space-between;margin-bottom:8px';
    const left=document.createElement('div');
    const nameEl=document.createElement('span');nameEl.style.cssText='font-weight:600;margin-right:12px';nameEl.textContent=ch.name;
    left.appendChild(nameEl);
    if(ch.source==='yaml'){const badge=document.createElement('span');badge.className='badge info';badge.textContent='YAML';left.appendChild(badge);}
    const typeBadge=document.createElement('span');typeBadge.className='badge '+(ch.enabled?'info':'');
    typeBadge.textContent=(notifTypes[ch.type]||{}).label||ch.type;left.appendChild(typeBadge);
    const right=document.createElement('div');right.style.cssText='display:flex;gap:6px;align-items:center';
    let dotColor='var(--warning)';let statusLabel='No sends';
    if(!ch.enabled){dotColor='var(--text-muted)';statusLabel='Disabled';}
    else if(ch.last_status==='sent'){dotColor='var(--accent)';statusLabel='Sent '+(typeof fmtTime==='function'?fmtTime(ch.last_status_at):'');}
    else if(ch.last_status==='failed'){dotColor='var(--critical)';statusLabel='Failed '+(typeof fmtTime==='function'?fmtTime(ch.last_status_at):'');}
    const dot=document.createElement('span');
    dot.style.cssText='display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px;background:'+dotColor;
    const statusTxt=document.createElement('span');statusTxt.style.cssText='font-size:.75rem;color:var(--text-secondary);margin-right:8px';
    statusTxt.textContent=statusLabel;
    if(ch.last_status==='failed'&&ch.last_error)statusTxt.title=ch.last_error;
    right.appendChild(dot);right.appendChild(statusTxt);
    if(!readOnly){
      if(ch.source!=='yaml'){
        const editBtn=document.createElement('div');editBtn.className='btn btn-sm';editBtn.textContent='Edit';
        editBtn.style.cssText='font-size:.72rem;padding:3px 10px';
        editBtn.addEventListener('click',(function(id){return function(){_editChannel(id)};})(ch.id));
        right.appendChild(editBtn);}
      const testBtn=document.createElement('div');testBtn.className='btn btn-sm';testBtn.textContent='Test';
      testBtn.style.cssText='font-size:.72rem;padding:3px 10px';
      testBtn.addEventListener('click',(function(id){return function(){_testChannel(id)};})(ch.id));
      right.appendChild(testBtn);
      const togBtn=document.createElement('div');togBtn.className='btn btn-sm';
      togBtn.textContent=ch.enabled?'Disable':'Enable';
      togBtn.style.cssText='font-size:.72rem;padding:3px 10px';
      togBtn.addEventListener('click',(function(id,enabled){return function(){_toggleChannel(id,!enabled)};})(ch.id,ch.enabled));
      right.appendChild(togBtn);
      if(ch.source!=='yaml'){
        const delBtn=document.createElement('div');delBtn.className='btn btn-sm btn-danger';delBtn.textContent='Delete';
        delBtn.style.cssText='font-size:.72rem;padding:3px 10px';
        delBtn.addEventListener('click',(function(id){return function(){if(confirm('Delete this channel?'))_deleteChannel(id);};})(ch.id));
        right.appendChild(delBtn);}
    }
    hdr.appendChild(left);hdr.appendChild(right);card.appendChild(hdr);
    const cfg=ch.config_masked||{};
    if(Object.keys(cfg).length){
      const cfgRow=document.createElement('div');cfgRow.style.cssText='font-family:var(--font-data);font-size:.75rem;color:var(--text-muted);display:flex;flex-wrap:wrap;gap:6px 16px';
      for(const k in cfg){if(cfg.hasOwnProperty(k)){
        const pair=document.createElement('span');
        const kSpan=document.createElement('span');kSpan.style.color='var(--text-secondary)';kSpan.textContent=k+': ';
        const vSpan=document.createElement('span');vSpan.textContent=typeof cfg[k]==='object'?JSON.stringify(cfg[k]):String(cfg[k]);
        pair.appendChild(kSpan);pair.appendChild(vSpan);cfgRow.appendChild(pair);}}
      card.appendChild(cfgRow);}
    const testResult=document.createElement('div');testResult.id='notif-test-'+ch.id;
    testResult.style.cssText='font-family:var(--font-data);font-size:.75rem;margin-top:6px';
    card.appendChild(testResult);el.appendChild(card);
  });
}
function _testChannel(id){
  const el=document.getElementById('notif-test-'+id);if(!el)return;
  el.style.color='var(--text-secondary)';el.textContent='Sending test\u2026 0s';
  const startTime=Date.now();
  const timer=setInterval(function(){
    const elapsed=Math.round((Date.now()-startTime)/1000);
    if(elapsed>=15){clearInterval(timer);el.style.color='var(--critical)';el.textContent='Test timed out (15s)';return;}
    el.textContent='Sending test\u2026 '+elapsed+'s';
  },1000);
  fetch('/api/v1/notifications/channels/'+id+'/test',{method:'POST',headers:csrfHeaders()}).then(function(r){return r.json()}).then(function(res){
    clearInterval(timer);
    if(res.status==='sent'){el.style.color='var(--accent)';el.textContent='Test sent successfully';}
    else{el.style.color='var(--critical)';el.textContent='Test failed: '+(res.error||'unknown error');}
  }).catch(function(e){clearInterval(timer);el.style.color='var(--critical)';el.textContent='Test failed: '+e.message;});
}
function _editChannel(id){
  fetch('/api/v1/notifications/channels/'+id).then(function(r){return r.json()}).then(function(ch){
    if(ch.error)return;
    editingChannelId=ch.id;
    document.getElementById('notif-add-form').classList.add('visible');
    document.getElementById('notif-error').textContent='';document.getElementById('notif-error').style.display='none';
    document.getElementById('notif-save').textContent='Update Channel';
    document.getElementById('notif-name').value=ch.name||'';
    document.getElementById('notif-enabled').value=ch.enabled?'1':'0';
    const typeSel=document.getElementById('notif-type');typeSel.value=ch.type||'';
    typeSel.dispatchEvent(new Event('change'));
    setTimeout(function(){
      const cfg=ch.config||{};
      const minSev=cfg.min_severity||ch.min_severity||'warning';
      document.getElementById('notif-severity').value=minSev;
      let evts=ch.events||['block','alert'];
      if(typeof evts==='string'){try{evts=JSON.parse(evts);}catch(e){evts=['block','alert'];}}
      _buildEventChips(document.getElementById('notif-events'),evts);
      const fields=document.querySelectorAll('#notif-type-fields [data-field]');
      for(let i=0;i<fields.length;i++){
        const key=fields[i].getAttribute('data-field');
        if(cfg[key]!=null){
          if(Array.isArray(cfg[key]))fields[i].value=cfg[key].join(', ');
          else if(typeof cfg[key]==='boolean')fields[i].value=String(cfg[key]);
          else if(typeof cfg[key]==='object')fields[i].value=JSON.stringify(cfg[key]);
          else fields[i].value=String(cfg[key]);
        }
      }
    },50);
  }).catch(function(){});
}
function _toggleChannel(id,enabled){
  fetch('/api/v1/notifications/channels/'+id,{method:'PUT',headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify({enabled:enabled})}).then(function(){loadNotifications();}).catch(function(){});
}
function _deleteChannel(id){
  fetch('/api/v1/notifications/channels/'+id,{method:'DELETE',headers:csrfHeaders()}).then(function(){loadNotifications();}).catch(function(){});
}
document.getElementById('notif-add-btn').addEventListener('click',function(){
  editingChannelId=null;
  const form=document.getElementById('notif-add-form');form.classList.toggle('visible');
  document.getElementById('notif-error').textContent='';document.getElementById('notif-error').style.display='none';
  document.getElementById('notif-name').value='';
  document.getElementById('notif-type').value='';
  document.getElementById('notif-type-fields').replaceChildren();
  document.getElementById('notif-severity').value='warning';
  _buildEventChips(document.getElementById('notif-events'));
  document.getElementById('notif-enabled').value='1';
  document.getElementById('notif-save').textContent='Save Channel';
});
document.getElementById('notif-cancel').addEventListener('click',function(){
  editingChannelId=null;document.getElementById('notif-save').textContent='Save Channel';
  document.getElementById('notif-add-form').classList.remove('visible');
});
let _apiChannelIds=[];
function _bulkAction(action){
  if(!_apiChannelIds.length)return;
  const msg=action==='delete'?'Delete all '+_apiChannelIds.length+' channels?':
    (action==='enable'?'Enable':'Disable')+' all '+_apiChannelIds.length+' channels?';
  if(!confirm(msg))return;
  fetch('/api/v1/notifications/channels/batch',{method:'POST',headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify({action:action,ids:_apiChannelIds})}).then(function(){loadNotifications();}).catch(function(){});
}
document.getElementById('notif-enable-all').addEventListener('click',function(){_bulkAction('enable');});
document.getElementById('notif-disable-all').addEventListener('click',function(){_bulkAction('disable');});
document.getElementById('notif-delete-all').addEventListener('click',function(){_bulkAction('delete');});
function _markFieldError(fieldKey,msg){
  const inp=document.querySelector('#notif-type-fields [data-field="'+fieldKey+'"]');
  if(inp){const row=inp.closest('.form-row');
    inp.classList.add('field-error');
    if(row){row.classList.remove('shake');void row.offsetWidth;row.classList.add('shake');}
    inp.focus();
    const em=row&&row.querySelector('.field-error-msg');if(em){em.textContent=msg;em.classList.add('visible');}}
}
function _clearAllFieldErrors(){
  document.querySelectorAll('#notif-type-fields .field-error').forEach(function(el){el.classList.remove('field-error')});
  document.querySelectorAll('#notif-type-fields .shake').forEach(function(el){el.classList.remove('shake')});
  document.querySelectorAll('#notif-type-fields .field-error-msg').forEach(function(el){el.classList.remove('visible');el.textContent=''});
  ['notif-type','notif-name'].forEach(function(id){const el=document.getElementById(id);if(el)el.classList.remove('field-error')});
}
document.getElementById('notif-name').addEventListener('input',function(){this.classList.remove('field-error');
  const ne=document.getElementById('notif-error');ne.textContent='';ne.style.display='none';});
document.getElementById('notif-save').addEventListener('click',function(){
  const errEl=document.getElementById('notif-error');errEl.textContent='';errEl.style.display='none';
  _clearAllFieldErrors();
  const chType=document.getElementById('notif-type').value;
  const name=document.getElementById('notif-name').value.trim();
  const minSev=document.getElementById('notif-severity').value;
  const enabled=document.getElementById('notif-enabled').value==='1';
  if(!chType){const el=document.getElementById('notif-type');el.classList.add('field-error');
    const r=el.closest('.form-row');r.classList.remove('shake');void r.offsetWidth;r.classList.add('shake');
    errEl.textContent='Select a channel type';errEl.style.display='block';el.focus();return;}
  if(!name){const el=document.getElementById('notif-name');el.classList.add('field-error');
    const r=el.closest('.form-row');r.classList.remove('shake');void r.offsetWidth;r.classList.add('shake');
    errEl.textContent='Name is required';errEl.style.display='block';el.focus();return;}
  const config={};const fields=document.querySelectorAll('#notif-type-fields [data-field]');
  for(let i=0;i<fields.length;i++){
    const key=fields[i].getAttribute('data-field');
    let val=fields[i].value;
    if(fields[i].tagName==='SELECT'&&(val==='true'||val==='false'))val=val==='true';
    config[key]=val;}
  if(notifTypes[chType]){
    const typeFields=notifTypes[chType].fields;
    for(const fk in typeFields){if(typeFields.hasOwnProperty(fk)&&typeFields[fk].required&&fk!=='min_severity'){
      if(!config[fk]){_markFieldError(fk,typeFields[fk].label+' is required');
        errEl.textContent=typeFields[fk].label+' is required';errEl.style.display='block';return;}}}}
  if(config.headers&&typeof config.headers==='string'&&config.headers.trim()){
    try{config.headers=JSON.parse(config.headers);}catch(e){_markFieldError('headers','Must be valid JSON');
      errEl.textContent='Invalid JSON in headers';errEl.style.display='block';return;}}
  if(config.to_addrs&&typeof config.to_addrs==='string'){
    config.to_addrs=config.to_addrs.split(',').map(function(a){return a.trim()}).filter(Boolean);}
  if(config.smtp_port)config.smtp_port=Number.parseInt(config.smtp_port)||587;
  const events=_getSelectedEvents();
  if(!events.length){errEl.textContent='Select at least one trigger';errEl.style.display='block';return;}
  const payload={name:name,type:chType,config:config,min_severity:minSev,enabled:enabled,events:events};
  let url='/api/v1/notifications/channels';let method='POST';
  if(editingChannelId){url+='/'+editingChannelId;method='PUT';}
  fetch(url,{method:method,headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify(payload)}).then(function(r){return r.json()}).then(function(res){
    if(res.error){errEl.textContent=res.message||res.error;errEl.style.display='block';return;}
    document.getElementById('notif-add-form').classList.remove('visible');
    editingChannelId=null;document.getElementById('notif-save').textContent='Save Channel';
    loadNotifications();
  }).catch(function(e){errEl.textContent='Failed: '+e.message;errEl.style.display='block';});
});
