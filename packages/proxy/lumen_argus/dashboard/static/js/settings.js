/* settings.js — Settings page (community).
   Renders proxy, license, detector, and logs sections. Plugin modules
   register their own sections via registerSettingsSection(name, renderFn);
   each renderFn receives (cfg, status) and returns a DOM node or null. */
function loadSettings(){
  Promise.all([
    fetch('/api/v1/config').then(function(r){return r.json()}),
    fetch('/api/v1/status').then(function(r){return r.json()})
  ]).then(function(results){
    const cfg=results[0],status=results[1];
    const el=document.getElementById('settings-content');el.replaceChildren();
    const community=cfg.community||{};

    /* === 1. Proxy (always editable) === */
    const proxyGrp=_mkSG('Proxy (hot-reloadable)');
    const timeout=community.proxy?community.proxy.timeout:120;
    const connectTimeout=community.proxy?community.proxy.connect_timeout:10;
    const retries=community.proxy?community.proxy.retries:1;
    _addEditRow(proxyGrp,'Idle-read timeout (seconds)','proxy.timeout','number',timeout,{min:1,max:300});
    _addEditRow(proxyGrp,'Connect timeout (seconds)','proxy.connect_timeout','number',connectTimeout,{min:1,max:120});
    _addEditRow(proxyGrp,'Retries','proxy.retries','number',retries,{min:0,max:10});
    if(community.proxy){
      const port=community.proxy.port||8080;
      const bind=community.proxy.bind||'127.0.0.1';
      _addEditRow(proxyGrp,'Port','proxy.port','number',port,{min:1,max:65535});
      _addEditRow(proxyGrp,'Bind','proxy.bind','text',bind);
    }
    el.appendChild(proxyGrp);

    /* === 2. Scanning link === */
    const scanGrp=_mkSG('Scanning');
    const scanNote=document.createElement('div');scanNote.className='setting-row';
    const scanMsg=document.createElement('span');scanMsg.className='setting-val';
    scanMsg.style.cssText='text-align:left;width:100%';
    const scanLink=document.createElement('a');scanLink.href='#pipeline';
    scanLink.textContent='Pipeline page';
    scanLink.style.cssText='color:var(--accent);text-decoration:none';
    scanMsg.textContent='Detection stages and actions are configured on the ';
    scanMsg.appendChild(scanLink);
    scanNote.appendChild(scanMsg);
    scanGrp.appendChild(scanNote);
    el.appendChild(scanGrp);

    /* === 3. Save Settings === */
    const saveRow=document.createElement('div');saveRow.style.cssText='display:flex;gap:8px;margin-bottom:24px';
    const saveBtn=document.createElement('div');saveBtn.className='btn btn-primary';saveBtn.textContent='Save Settings';
    const saveStatus=document.createElement('span');saveStatus.id='settings-save-status';
    saveStatus.style.cssText='font-family:var(--font-data);font-size:.78rem;color:var(--text-muted);align-self:center';
    saveBtn.addEventListener('click',function(){_saveSettings(saveStatus)});
    saveRow.appendChild(saveBtn);saveRow.appendChild(saveStatus);
    el.appendChild(saveRow);

    /* === 4. License === */
    const licGrp=_mkSG('License');
    const tier=(status.tier||'community');
    const tierRow=document.createElement('div');tierRow.className='setting-row';
    const tierKey=document.createElement('div');tierKey.className='setting-key';tierKey.textContent='Tier';
    const tierVal=document.createElement('div');tierVal.className='setting-val';
    tierVal.textContent=titlecase(tier);
    tierVal.classList.add('tier-'+tier);
    tierRow.appendChild(tierKey);tierRow.appendChild(tierVal);licGrp.appendChild(tierRow);
    if(status.license){
      const lic=status.license;
      /* Status with color */
      const statusRow=document.createElement('div');statusRow.className='setting-row';
      const statusKey=document.createElement('div');statusKey.className='setting-key';statusKey.textContent='Status';
      const statusVal=document.createElement('div');statusVal.className='setting-val';
      if(lic.trial){statusVal.textContent='Trial';statusVal.style.color='var(--warning)';}
      else if(lic.valid){statusVal.textContent='Valid';statusVal.classList.add('enabled');}
      else{statusVal.textContent='Expired';statusVal.style.color='var(--critical)';}
      statusRow.appendChild(statusKey);statusRow.appendChild(statusVal);licGrp.appendChild(statusRow);
      /* Expiry */
      if(lic.expiry)_addReadRow(licGrp,'Expiry',lic.expiry);
      /* Days remaining */
      if(lic.days_remaining!=null){
        const daysRow=document.createElement('div');daysRow.className='setting-row';
        const daysKey=document.createElement('div');daysKey.className='setting-key';daysKey.textContent='Days remaining';
        const daysVal=document.createElement('div');daysVal.className='setting-val';
        daysVal.textContent=String(lic.days_remaining);
        daysVal.style.color=lic.days_remaining<=7?'var(--critical)':lic.days_remaining<=30?'var(--warning)':'var(--text-muted)';
        daysRow.appendChild(daysKey);daysRow.appendChild(daysVal);licGrp.appendChild(daysRow);
      }
      /* Grace period warning */
      if(lic.grace_period){
        const graceRow=document.createElement('div');graceRow.className='setting-row';
        const graceKey=document.createElement('div');graceKey.className='setting-key';graceKey.textContent='Grace period';
        const graceVal=document.createElement('div');graceVal.className='setting-val';
        let graceText='Active \u2014 renew soon';
        if(lic.grace_days_remaining!=null)graceText+=(' ('+lic.grace_days_remaining+' days left)');
        graceVal.textContent=graceText;graceVal.style.color='var(--warning)';
        graceRow.appendChild(graceKey);graceRow.appendChild(graceVal);licGrp.appendChild(graceRow);
      }
    }
    /* License key input (always shown) */
    const licRow=document.createElement('div');licRow.className='form-row';licRow.style.marginTop='12px';
    const licLbl=document.createElement('label');licLbl.textContent='Key';
    const licInput=document.createElement('input');licInput.type='text';licInput.id='license-key-input';
    licInput.placeholder='Enter license key';licInput.style.flex='1';
    const licBtn=document.createElement('div');licBtn.className='btn btn-primary btn-sm';licBtn.textContent='Activate';
    licBtn.addEventListener('click',function(){
      const key=document.getElementById('license-key-input').value.trim();if(!key)return;
      fetch('/api/v1/license',{method:'POST',headers:csrfHeaders({'Content-Type':'application/json'}),
        body:JSON.stringify({key:key})}).then(function(r){return r.json()}).then(function(res){
        const msg=document.getElementById('license-result');
        msg.textContent=res.message||res.error||'Done';
        msg.style.color=res.error?'var(--critical)':'var(--accent)';msg.style.display='block';
      }).catch(function(e){
        const msg=document.getElementById('license-result');
        msg.textContent='Failed: '+e.message;msg.style.color='var(--critical)';msg.style.display='block';
      });
    });
    licRow.appendChild(licLbl);licRow.appendChild(licInput);licRow.appendChild(licBtn);
    licGrp.appendChild(licRow);
    const licResult=document.createElement('div');licResult.id='license-result';
    licResult.style.cssText='font-family:var(--font-data);font-size:.78rem;margin-top:6px;display:none';
    licGrp.appendChild(licResult);
    el.appendChild(licGrp);

    /* === 5. Detectors (always shown) === */
    if(community.detectors){
      const detRows=[];
      for(const dd in community.detectors){if(community.detectors.hasOwnProperty(dd)){
        const ddet=community.detectors[dd];
        detRows.push([dd,ddet.enabled?'Enabled':'Disabled',ddet.enabled]);
      }}
      _addSG(el,'Detectors',detRows);
    }

    /* === 6. Logs (download) === */
    const logGrp=_mkSG('Logs');
    _addDlButton(logGrp);
    el.appendChild(logGrp);

    /* === Plugin settings sections === */
    for(const ss of _settingsSections){
      try{
        const section=ss.render(cfg,status);
        if(section)el.appendChild(section);
      }catch(e){
        const errGrp=_mkSG(ss.name);
        const errMsg=document.createElement('div');errMsg.className='setting-row';
        errMsg.style.color='var(--critical)';
        errMsg.textContent='Failed to load section: '+e.message;
        errGrp.appendChild(errMsg);el.appendChild(errGrp);
      }
    }

  }).catch(function(e){showPageError('settings-content','Failed to load settings: '+e.message,loadSettings);});}

/* --- Helper: create setting group --- */
function _mkSG(title){
  const grp=document.createElement('div');grp.className='setting-group';
  const h=document.createElement('h3');h.textContent=title;grp.appendChild(h);return grp;}

/* --- Helper: read-only row --- */
function _addReadRow(parent,label,value){
  const row=document.createElement('div');row.className='setting-row';
  const k=document.createElement('div');k.className='setting-key';k.textContent=label;
  const v=document.createElement('div');v.className='setting-val';v.textContent=String(value);
  v.style.color='var(--text-muted)';row.appendChild(k);row.appendChild(v);parent.appendChild(row);}

/* --- Helper: editable row (input or select) --- */
function _addEditRow(parent,label,key,type,value,opts){opts=opts||{};
  const row=document.createElement('div');row.className='setting-row';
  const k=document.createElement('div');k.className='setting-key';k.textContent=label;
  let v;
  if(type==='select'){
    v=document.createElement('select');
    v.style.cssText='font-family:var(--font-data);font-size:.78rem;background:var(--bg-base);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);padding:4px 8px;outline:none';
    (opts.options||[]).forEach(function(o){const opt=document.createElement('option');opt.value=o;opt.textContent=o;
      if(o===value)opt.selected=true;v.appendChild(opt);});
  }else{
    v=document.createElement('input');v.type=type||'text';v.value=value;
    v.style.cssText='font-family:var(--font-data);font-size:.78rem;background:var(--bg-base);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);padding:4px 8px;outline:none;width:'+(opts.width||'80px');
    if(opts.min!=null)v.min=opts.min;if(opts.max!=null)v.max=opts.max;
  }
  v.setAttribute('data-config-key',key);v.setAttribute('data-original',String(value));
  v.className='config-input';
  row.appendChild(k);row.appendChild(v);parent.appendChild(row);}

/* --- Helper: section group with rows --- */
function _addSG(parent,title,rows){
  const grp=_mkSG(title);
  for(let i=0;i<rows.length;i++){
    const row=document.createElement('div');row.className='setting-row';
    const k=document.createElement('div');k.className='setting-key';k.textContent=rows[i][0];
    const v=document.createElement('div');v.className='setting-val';v.textContent=String(rows[i][1]);
    if(rows[i].length>2)v.classList.add(rows[i][2]?'enabled':'disabled');
    row.appendChild(k);row.appendChild(v);grp.appendChild(row);
  }
  parent.appendChild(grp);}

/* --- Helper: download logs button --- */
function _addDlButton(parent){
  const dlBtn=document.createElement('button');dlBtn.textContent='Download Sanitized Logs';
  dlBtn.style.cssText='font-family:var(--font-data);font-size:.78rem;padding:6px 14px;background:var(--bg-base);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--accent);cursor:pointer;margin-top:8px';
  dlBtn.addEventListener('click',function(){window.location.href='/api/v1/logs/download'});
  parent.appendChild(dlBtn);
  const dlNote=document.createElement('span');dlNote.style.cssText='font-size:.72rem;color:var(--text-muted);margin-left:8px';
  dlNote.textContent='IPs and file paths are sanitized for safe sharing';
  parent.appendChild(dlNote);}

/* --- Plugin settings sections registry --- */
const _settingsSections=[];

/* Called by Pro enhancers to register additional settings groups.
   renderFn(cfg, statusData) receives GET /config and GET /status responses.
   Return a DOM element (e.g. from _mkSG) or null to skip. */
function registerSettingsSection(name,renderFn){
  _settingsSections.push({name:name,render:renderFn});}

/* --- Save settings --- */
function _saveSettings(statusEl){
  const inputs=document.querySelectorAll('.config-input');
  const changes={};let count=0;
  for(let i=0;i<inputs.length;i++){
    const inp=inputs[i];const key=inp.getAttribute('data-config-key');
    const orig=inp.getAttribute('data-original');
    const raw=inp.value;
    if(raw!==orig){changes[key]=(inp.type==='number')?Number(raw):raw;count++;}
  }
  if(!count){statusEl.textContent='No changes';statusEl.style.color='var(--text-muted)';return;}
  statusEl.textContent='Saving...';statusEl.style.color='var(--text-muted)';
  fetch('/api/v1/config',{method:'PUT',headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify(changes)}).then(function(r){
    return r.json().then(function(d){return{status:r.status,data:d};});
  }).then(function(res){
    if(res.data.applied){
      const n=Object.keys(res.data.applied).length;
      statusEl.textContent=n+' setting(s) saved \u2014 applied immediately';
      statusEl.style.color='var(--accent)';
      const applied=res.data.applied||{};
      for(let j=0;j<inputs.length;j++){const ak=inputs[j].getAttribute('data-config-key');
        if(applied.hasOwnProperty(ak))inputs[j].setAttribute('data-original',inputs[j].value);}
      if(res.data.errors&&res.data.errors.length){
        statusEl.textContent+=' ('+res.data.errors.length+' error(s))';
        statusEl.style.color='var(--warning)';
      }
    }else if(res.data.error){
      statusEl.textContent=res.data.error;statusEl.style.color='var(--critical)';
    }
  }).catch(function(e){statusEl.textContent='Failed: '+e.message;statusEl.style.color='var(--critical)';});}
