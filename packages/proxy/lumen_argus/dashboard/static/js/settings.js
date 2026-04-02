/* settings.js — unified Settings page for both community and Pro tiers.
   Detects tier from /api/v1/status and renders Pro sections as locked/dimmed
   when no Pro license is active. Pro enriches GET /api/v1/config with
   license, pro, and logging sections — this JS renders them when present. */
function loadSettings(){
  Promise.all([
    fetch('/api/v1/config').then(function(r){return r.json()}),
    fetch('/api/v1/status').then(function(r){return r.json()})
  ]).then(function(results){
    var cfg=results[0],status=results[1];
    var el=document.getElementById('settings-content');el.replaceChildren();
    var isProActive=(status.tier==='pro'||status.tier==='enterprise');
    var community=cfg.community||{};

    /* === 1. Proxy (always editable) === */
    var proxyGrp=_mkSG('Proxy (hot-reloadable)');
    var timeout=community.proxy?community.proxy.timeout:120;
    var retries=community.proxy?community.proxy.retries:1;
    _addEditRow(proxyGrp,'Timeout (seconds)','proxy.timeout','number',timeout,{min:1,max:300});
    _addEditRow(proxyGrp,'Retries','proxy.retries','number',retries,{min:0,max:10});
    if(community.proxy){
      var port=community.proxy.port||8080;
      var bind=community.proxy.bind||'127.0.0.1';
      _addEditRow(proxyGrp,'Port','proxy.port','number',port,{min:1,max:65535});
      _addEditRow(proxyGrp,'Bind','proxy.bind','text',bind);
    }
    el.appendChild(proxyGrp);

    /* === 2. Scanning link === */
    var scanGrp=_mkSG('Scanning');
    var scanNote=document.createElement('div');scanNote.className='setting-row';
    var scanMsg=document.createElement('span');scanMsg.className='setting-val';
    scanMsg.style.cssText='text-align:left;width:100%';
    var scanLink=document.createElement('a');scanLink.href='#pipeline';
    scanLink.textContent='Pipeline page';
    scanLink.style.cssText='color:var(--accent);text-decoration:none';
    scanMsg.textContent='Detection stages and actions are configured on the ';
    scanMsg.appendChild(scanLink);
    scanNote.appendChild(scanMsg);
    scanGrp.appendChild(scanNote);
    el.appendChild(scanGrp);

    /* === 3. Save Settings === */
    var saveRow=document.createElement('div');saveRow.style.cssText='display:flex;gap:8px;margin-bottom:24px';
    var saveBtn=document.createElement('div');saveBtn.className='btn btn-primary';saveBtn.textContent='Save Settings';
    var saveStatus=document.createElement('span');saveStatus.id='settings-save-status';
    saveStatus.style.cssText='font-family:var(--font-data);font-size:.78rem;color:var(--text-muted);align-self:center';
    saveBtn.addEventListener('click',function(){_saveSettings(saveStatus)});
    saveRow.appendChild(saveBtn);saveRow.appendChild(saveStatus);
    el.appendChild(saveRow);

    /* === 4. License === */
    var licGrp=_mkSG('License');
    /* Tier badge */
    var tierRow=document.createElement('div');tierRow.className='setting-row';
    var tierKey=document.createElement('div');tierKey.className='setting-key';tierKey.textContent='Tier';
    var tierVal=document.createElement('div');tierVal.className='setting-val';
    tierVal.textContent=isProActive?(status.tier.charAt(0).toUpperCase()+status.tier.slice(1)):'Community';
    tierVal.classList.add(isProActive?'enabled':'disabled');
    tierRow.appendChild(tierKey);tierRow.appendChild(tierVal);licGrp.appendChild(tierRow);
    /* Pro version */
    if(isProActive&&status.pro_version)_addReadRow(licGrp,'Pro version',status.pro_version);
    /* License details from status API (Pro enriches this) */
    if(status.license){
      var lic=status.license;
      /* Status with color */
      var statusRow=document.createElement('div');statusRow.className='setting-row';
      var statusKey=document.createElement('div');statusKey.className='setting-key';statusKey.textContent='Status';
      var statusVal=document.createElement('div');statusVal.className='setting-val';
      if(lic.trial){statusVal.textContent='Trial';statusVal.style.color='var(--warning)';}
      else if(lic.valid){statusVal.textContent='Valid';statusVal.classList.add('enabled');}
      else{statusVal.textContent='Expired';statusVal.style.color='var(--critical)';}
      statusRow.appendChild(statusKey);statusRow.appendChild(statusVal);licGrp.appendChild(statusRow);
      /* Expiry */
      if(lic.expiry)_addReadRow(licGrp,'Expiry',lic.expiry);
      /* Days remaining */
      if(lic.days_remaining!=null){
        var daysRow=document.createElement('div');daysRow.className='setting-row';
        var daysKey=document.createElement('div');daysKey.className='setting-key';daysKey.textContent='Days remaining';
        var daysVal=document.createElement('div');daysVal.className='setting-val';
        daysVal.textContent=String(lic.days_remaining);
        daysVal.style.color=lic.days_remaining<=7?'var(--critical)':lic.days_remaining<=30?'var(--warning)':'var(--text-muted)';
        daysRow.appendChild(daysKey);daysRow.appendChild(daysVal);licGrp.appendChild(daysRow);
      }
      /* Grace period warning */
      if(lic.grace_period){
        var graceRow=document.createElement('div');graceRow.className='setting-row';
        var graceKey=document.createElement('div');graceKey.className='setting-key';graceKey.textContent='Grace period';
        var graceVal=document.createElement('div');graceVal.className='setting-val';
        var graceText='Active \u2014 renew soon';
        if(lic.grace_days_remaining!=null)graceText+=(' ('+lic.grace_days_remaining+' days left)');
        graceVal.textContent=graceText;graceVal.style.color='var(--warning)';
        graceRow.appendChild(graceKey);graceRow.appendChild(graceVal);licGrp.appendChild(graceRow);
      }
    }
    /* License key input (always shown) */
    var licRow=document.createElement('div');licRow.className='form-row';licRow.style.marginTop='12px';
    var licLbl=document.createElement('label');licLbl.textContent='Key';
    var licInput=document.createElement('input');licInput.type='text';licInput.id='license-key-input';
    licInput.placeholder='Enter license key';licInput.style.flex='1';
    var licBtn=document.createElement('div');licBtn.className='btn btn-primary btn-sm';licBtn.textContent='Activate';
    licBtn.addEventListener('click',function(){
      var key=document.getElementById('license-key-input').value.trim();if(!key)return;
      fetch('/api/v1/license',{method:'POST',headers:csrfHeaders({'Content-Type':'application/json'}),
        body:JSON.stringify({key:key})}).then(function(r){return r.json()}).then(function(res){
        var msg=document.getElementById('license-result');
        msg.textContent=res.message||res.error||'Done';
        msg.style.color=res.error?'var(--critical)':'var(--accent)';msg.style.display='block';
      }).catch(function(e){
        var msg=document.getElementById('license-result');
        msg.textContent='Failed: '+e.message;msg.style.color='var(--critical)';msg.style.display='block';
      });
    });
    licRow.appendChild(licLbl);licRow.appendChild(licInput);licRow.appendChild(licBtn);
    licGrp.appendChild(licRow);
    var licResult=document.createElement('div');licResult.id='license-result';
    licResult.style.cssText='font-family:var(--font-data);font-size:.78rem;margin-top:6px;display:none';
    licGrp.appendChild(licResult);
    /* Trial link (community only) */
    if(!isProActive){
      var trialRow=document.createElement('div');trialRow.style.marginTop='10px';
      var trialLink=document.createElement('a');trialLink.href='https://lumen-argus.com/trial';
      trialLink.target='_blank';trialLink.className='btn btn-sm';trialLink.textContent='Start Free Trial';
      trialRow.appendChild(trialLink);licGrp.appendChild(trialRow);
    }
    el.appendChild(licGrp);

    /* === 5. Pro Features (locked when community) === */
    if(isProActive&&cfg.pro){
      var proRows=[];
      if(cfg.pro.redaction)proRows.push(['Redaction',cfg.pro.redaction.enabled?'Enabled':'Disabled',cfg.pro.redaction.enabled]);
      if(cfg.pro.custom_rules_count!=null)proRows.push(['Custom rules',cfg.pro.custom_rules_count+' rules']);
      if(cfg.pro.notifications){
        var chans=Object.keys(cfg.pro.notifications);
        proRows.push(['Notifications',(chans.join(', ')||'none')+' (manage \u2192 Notifications tab)']);
      }
      _addLockedSG(el,'Pro Features',proRows,false);
      /* Detection Rules — import button when Pro licensed but rules not imported */
      if(cfg.pro.pro_rules_imported!=null){
        var rulesInfo=_mkSG('Detection Rules');
        if(cfg.pro.pro_rules_imported>0){
          _addReadRow(rulesInfo,'Pro rules imported',cfg.pro.pro_rules_imported+' rules');
        }else{
          _addReadRow(rulesInfo,'Pro rules','Not imported yet');
          var importRow=document.createElement('div');
          importRow.style.cssText='margin-top:8px;display:flex;gap:8px;align-items:center';
          var importBtn=document.createElement('div');importBtn.className='btn btn-primary btn-sm';
          importBtn.textContent='Import Pro Rules';
          var importMsg=document.createElement('span');
          importMsg.style.cssText='font-family:var(--font-data);font-size:.78rem;color:var(--text-muted)';
          importBtn.addEventListener('click',function(){
            importMsg.textContent='Importing...';importBtn.style.opacity='0.5';
            importBtn.style.pointerEvents='none';
            fetch('/api/v1/rules/import-pro',{method:'POST',headers:csrfHeaders({'Content-Type':'application/json'})})
              .then(function(r){return r.json()}).then(function(res){
                if(res.error){importMsg.textContent=res.error;importMsg.style.color='var(--critical)';
                  importBtn.style.opacity='1';importBtn.style.pointerEvents='auto';}
                else{importMsg.textContent=res.message||'Done';importMsg.style.color='var(--accent)';
                  setTimeout(loadSettings,1500);}
              }).catch(function(e){importMsg.textContent='Failed';importMsg.style.color='var(--critical)';
                importBtn.style.opacity='1';importBtn.style.pointerEvents='auto';});
          });
          importRow.appendChild(importBtn);importRow.appendChild(importMsg);
          rulesInfo.appendChild(importRow);
        }
        el.appendChild(rulesInfo);
      }
    }else{
      _addLockedSG(el,'Pro Features',[
        ['Redaction','Requires Pro license'],
        ['Custom rules','Requires Pro license'],
        ['Notifications','Requires Pro license']
      ],true);
    }

    /* === 6. Detectors (always shown) === */
    if(community.detectors){
      var detRows=[];
      for(var dd in community.detectors){if(community.detectors.hasOwnProperty(dd)){
        var ddet=community.detectors[dd];
        detRows.push([dd,ddet.enabled?'Enabled':'Disabled',ddet.enabled]);
      }}
      _addSG(el,'Detectors',detRows);
    }

    /* === 7. Logging (locked when community, enriched by Pro) === */
    if(isProActive&&cfg.logging){
      var logGrp=_mkSG('Logging');
      _addReadRow(logGrp,'Format',cfg.logging.format||'text');
      _addReadRow(logGrp,'Output',cfg.logging.output||'file');
      if(cfg.logging.file_level)_addReadRow(logGrp,'File level',cfg.logging.file_level);
      if(cfg.logging.max_size_mb)_addReadRow(logGrp,'Max file size',cfg.logging.max_size_mb+' MB');
      if(cfg.logging.backup_count!=null)_addReadRow(logGrp,'Backup count',cfg.logging.backup_count);
      if(cfg.logging.paths){for(var fname in cfg.logging.paths){if(cfg.logging.paths.hasOwnProperty(fname)){
        var p=cfg.logging.paths[fname];
        var sizeStr=p.exists?(p.size_bytes/1024).toFixed(1)+' KB':'(not created)';
        _addReadRow(logGrp,fname,p.path+' \u2014 '+sizeStr);
      }}}
      _addDlButton(logGrp);
      el.appendChild(logGrp);
    }else{
      var logGrp2=_mkSG('Logs');
      _addDlButton(logGrp2);
      el.appendChild(logGrp2);
    }

    /* === Plugin settings sections === */
    for(var si=0;si<_settingsSections.length;si++){
      try{
        var section=_settingsSections[si].render(cfg,status);
        if(section)el.appendChild(section);
      }catch(e){
        var errGrp=_mkSG(_settingsSections[si].name);
        var errMsg=document.createElement('div');errMsg.className='setting-row';
        errMsg.style.color='var(--critical)';
        errMsg.textContent='Failed to load section: '+e.message;
        errGrp.appendChild(errMsg);el.appendChild(errGrp);
      }
    }

  }).catch(function(e){showPageError('settings-content','Failed to load settings: '+e.message,loadSettings);});}

/* --- Helper: create setting group --- */
function _mkSG(title){
  var grp=document.createElement('div');grp.className='setting-group';
  var h=document.createElement('h3');h.textContent=title;grp.appendChild(h);return grp;}

/* --- Helper: read-only row --- */
function _addReadRow(parent,label,value){
  var row=document.createElement('div');row.className='setting-row';
  var k=document.createElement('div');k.className='setting-key';k.textContent=label;
  var v=document.createElement('div');v.className='setting-val';v.textContent=String(value);
  v.style.color='var(--text-muted)';row.appendChild(k);row.appendChild(v);parent.appendChild(row);}

/* --- Helper: editable row (input or select) --- */
function _addEditRow(parent,label,key,type,value,opts){
  var row=document.createElement('div');row.className='setting-row';
  var k=document.createElement('div');k.className='setting-key';k.textContent=label;
  var v;
  if(type==='select'){
    v=document.createElement('select');
    v.style.cssText='font-family:var(--font-data);font-size:.78rem;background:var(--bg-base);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);padding:4px 8px;outline:none';
    (opts.options||[]).forEach(function(o){var opt=document.createElement('option');opt.value=o;opt.textContent=o;
      if(o===value)opt.selected=true;v.appendChild(opt);});
  }else{
    v=document.createElement('input');v.type=type||'text';v.value=value;
    v.style.cssText='font-family:var(--font-data);font-size:.78rem;background:var(--bg-base);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);padding:4px 8px;outline:none;width:80px';
    if(opts.min!=null)v.min=opts.min;if(opts.max!=null)v.max=opts.max;
  }
  v.setAttribute('data-config-key',key);v.setAttribute('data-original',String(value));
  v.className='config-input';
  row.appendChild(k);row.appendChild(v);parent.appendChild(row);}

/* --- Helper: section group with rows --- */
function _addSG(parent,title,rows){
  var grp=_mkSG(title);
  for(var i=0;i<rows.length;i++){
    var row=document.createElement('div');row.className='setting-row';
    var k=document.createElement('div');k.className='setting-key';k.textContent=rows[i][0];
    var v=document.createElement('div');v.className='setting-val';v.textContent=String(rows[i][1]);
    if(rows[i].length>2)v.classList.add(rows[i][2]?'enabled':'disabled');
    row.appendChild(k);row.appendChild(v);grp.appendChild(row);
  }
  parent.appendChild(grp);}

/* --- Helper: locked/dimmed section --- */
function _addLockedSG(parent,title,rows,isLocked){
  var grp=document.createElement('div');grp.className='setting-group';
  if(isLocked)grp.style.opacity='0.5';
  var h=document.createElement('h3');h.textContent=title;
  if(isLocked){var lock=document.createElement('span');lock.textContent=' (Pro)';
    lock.style.cssText='font-size:.65rem;color:var(--text-muted);font-weight:400';h.appendChild(lock);}
  grp.appendChild(h);
  for(var i=0;i<rows.length;i++){
    var row=document.createElement('div');row.className='setting-row';
    var k=document.createElement('div');k.className='setting-key';k.textContent=rows[i][0];
    var v=document.createElement('div');v.className='setting-val';v.textContent=String(rows[i][1]);
    if(isLocked)v.classList.add('disabled');
    else if(rows[i].length>2)v.classList.add(rows[i][2]?'enabled':'disabled');
    row.appendChild(k);row.appendChild(v);grp.appendChild(row);
  }
  parent.appendChild(grp);}

/* --- Helper: download logs button --- */
function _addDlButton(parent){
  var dlBtn=document.createElement('button');dlBtn.textContent='Download Sanitized Logs';
  dlBtn.style.cssText='font-family:var(--font-data);font-size:.78rem;padding:6px 14px;background:var(--bg-base);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--accent);cursor:pointer;margin-top:8px';
  dlBtn.addEventListener('click',function(){window.location.href='/api/v1/logs/download'});
  parent.appendChild(dlBtn);
  var dlNote=document.createElement('span');dlNote.style.cssText='font-size:.72rem;color:var(--text-muted);margin-left:8px';
  dlNote.textContent='IPs and file paths are sanitized for safe sharing';
  parent.appendChild(dlNote);}

/* --- Plugin settings sections registry --- */
var _settingsSections=[];

/* Called by Pro enhancers to register additional settings groups.
   renderFn(cfg, statusData) receives GET /config and GET /status responses.
   Return a DOM element (e.g. from _mkSG) or null to skip. */
function registerSettingsSection(name,renderFn){
  _settingsSections.push({name:name,render:renderFn});}

/* --- Save settings --- */
function _saveSettings(statusEl){
  var inputs=document.querySelectorAll('.config-input');
  var changes={};var count=0;
  for(var i=0;i<inputs.length;i++){
    var inp=inputs[i];var key=inp.getAttribute('data-config-key');
    var orig=inp.getAttribute('data-original');
    var raw=inp.value;
    if(raw!==orig){changes[key]=(inp.type==='number')?Number(raw):raw;count++;}
  }
  if(!count){statusEl.textContent='No changes';statusEl.style.color='var(--text-muted)';return;}
  statusEl.textContent='Saving...';statusEl.style.color='var(--text-muted)';
  fetch('/api/v1/config',{method:'PUT',headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify(changes)}).then(function(r){
    return r.json().then(function(d){return{status:r.status,data:d};});
  }).then(function(res){
    if(res.data.applied){
      var n=Object.keys(res.data.applied).length;
      statusEl.textContent=n+' setting(s) saved \u2014 applied immediately';
      statusEl.style.color='var(--accent)';
      var applied=res.data.applied||{};
      for(var j=0;j<inputs.length;j++){var ak=inputs[j].getAttribute('data-config-key');
        if(applied.hasOwnProperty(ak))inputs[j].setAttribute('data-original',inputs[j].value);}
      if(res.data.errors&&res.data.errors.length){
        statusEl.textContent+=' ('+res.data.errors.length+' error(s))';
        statusEl.style.color='var(--warning)';
      }
    }else if(res.data.error){
      statusEl.textContent=res.data.error;statusEl.style.color='var(--critical)';
    }
  }).catch(function(e){statusEl.textContent='Failed: '+e.message;statusEl.style.color='var(--critical)';});}
