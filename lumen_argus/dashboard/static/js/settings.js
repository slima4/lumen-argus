/* settings.js — config display, license input, editable settings, log download */
function loadSettings(){
  Promise.all([
    fetch('/api/v1/config').then(function(r){return r.json()}),
    fetch('/api/v1/status').then(function(r){return r.json()})
  ]).then(function(results){
    var cfg=results[0],status=results[1];
    var el=document.getElementById('settings-content');el.replaceChildren();
    var tier=status.tier||'community';
    var isProActive=tier==='pro'||tier==='enterprise';
    var community=cfg.community||{};

    /* === Editable Proxy Settings (community feature) === */
    var proxyGrp=_sg('Proxy (hot-reloadable)');
    var timeout=community.proxy?community.proxy.timeout:120;
    var retries=community.proxy?community.proxy.retries:1;
    _editRow(proxyGrp,'Timeout (seconds)','proxy.timeout','number',timeout,{min:1,max:300});
    _editRow(proxyGrp,'Retries','proxy.retries','number',retries,{min:0,max:10});
    if(community.proxy){
      _readRow(proxyGrp,'Port',community.proxy.port+' (requires restart)');
      _readRow(proxyGrp,'Bind',community.proxy.bind+' (requires restart)');
    }
    el.appendChild(proxyGrp);

    /* === Editable Action Settings (community feature) === */
    var actGrp=_sg('Actions (hot-reloadable)');
    var defAct=community.default_action||'alert';
    _editRow(actGrp,'Default action','default_action','select',defAct,
      {options:['log','alert','redact','block']});
    if(community.detectors){
      for(var d in community.detectors){if(community.detectors.hasOwnProperty(d)){
        var det=community.detectors[d];
        _editRow(actGrp,d+' action','detectors.'+d+'.action','select',det.action||defAct,
          {options:['log','alert','redact','block']});
      }}
    }
    el.appendChild(actGrp);

    /* === Save Button === */
    var saveRow=document.createElement('div');saveRow.style.cssText='display:flex;gap:8px;margin-bottom:24px';
    var saveBtn=document.createElement('div');saveBtn.className='btn btn-primary';saveBtn.textContent='Save Settings';
    var saveStatus=document.createElement('span');saveStatus.id='settings-save-status';
    saveStatus.style.cssText='font-family:var(--font-data);font-size:.78rem;color:var(--text-muted);align-self:center';
    saveBtn.addEventListener('click',function(){_saveSettings(saveStatus)});
    saveRow.appendChild(saveBtn);saveRow.appendChild(saveStatus);
    el.appendChild(saveRow);

    /* === License === */
    var licGrp=_sg('License');
    var tierRow=document.createElement('div');tierRow.className='setting-row';
    var tierKey=document.createElement('div');tierKey.className='setting-key';tierKey.textContent='Tier';
    var tierVal=document.createElement('div');tierVal.className='setting-val';
    tierVal.textContent=isProActive?tier.charAt(0).toUpperCase()+tier.slice(1):'Community';
    tierVal.classList.add(isProActive?'enabled':'disabled');
    tierRow.appendChild(tierKey);tierRow.appendChild(tierVal);licGrp.appendChild(tierRow);
    if(isProActive&&status.pro_version){_readRow(licGrp,'Pro version',status.pro_version);}

    /* Pro license details (locked when community) */
    if(cfg.license){
      _readRow(licGrp,'Status',cfg.license.valid?'Valid':'Invalid');
      if(cfg.license.expiry)_readRow(licGrp,'Expiry',cfg.license.expiry);
      if(cfg.license.grace_period)_readRow(licGrp,'Grace period','Active');
      if(cfg.license.max_developers)_readRow(licGrp,'Max developers',cfg.license.max_developers);
    }

    /* License key input */
    if(!isProActive){
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
      var trialRow=document.createElement('div');trialRow.style.marginTop='10px';
      var trialLink=document.createElement('a');trialLink.href='https://lumen-argus.com/trial';
      trialLink.target='_blank';trialLink.className='btn btn-sm';trialLink.textContent='Start Free Trial';
      trialRow.appendChild(trialLink);licGrp.appendChild(trialRow);
    }
    el.appendChild(licGrp);

    /* === Pro Features (locked when community) === */
    if(isProActive&&cfg.pro){
      var proRows=[];
      if(cfg.pro.redaction)proRows.push(['Redaction',cfg.pro.redaction.enabled?'Enabled':'Disabled',cfg.pro.redaction.enabled]);
      if(cfg.pro.custom_rules_count!=null)proRows.push(['Custom rules',cfg.pro.custom_rules_count+' rules']);
      if(cfg.pro.notifications){
        var chans=Object.keys(cfg.pro.notifications);
        proRows.push(['Notifications',(chans.join(', ')||'none')+' (manage \u2192 Notifications tab)']);
      }
      _addSG(el,'Pro Features',proRows);
    }else if(!isProActive){
      _addLockedSG(el,'Pro Features',[
        ['Redaction','Requires Pro license'],
        ['Custom rules','Requires Pro license'],
        ['Notifications','Requires Pro license']
      ]);
    }

    /* === Detectors === */
    if(community.detectors){
      var detRows=[];
      for(var dd in community.detectors){if(community.detectors.hasOwnProperty(dd)){
        var ddet=community.detectors[dd];
        detRows.push([dd,ddet.enabled?'Enabled':'Disabled',ddet.enabled]);
      }}
      _addSG(el,'Detectors',detRows);
    }

    /* === Logging === */
    if(isProActive&&cfg.logging){
      var logGrp=_sg('Logging');
      _readRow(logGrp,'Format',cfg.logging.format||'text');
      _readRow(logGrp,'Output',cfg.logging.output||'file');
      if(cfg.logging.file_level)_readRow(logGrp,'File level',cfg.logging.file_level);
      if(cfg.logging.max_size_mb)_readRow(logGrp,'Max file size',cfg.logging.max_size_mb+' MB');
      if(cfg.logging.backup_count!=null)_readRow(logGrp,'Backup count',cfg.logging.backup_count);
      if(cfg.logging.paths){for(var fname in cfg.logging.paths){if(cfg.logging.paths.hasOwnProperty(fname)){
        var p=cfg.logging.paths[fname];
        var sizeStr=p.exists?(p.size_bytes/1024).toFixed(1)+' KB':'(not created)';
        _readRow(logGrp,fname,p.path+' \u2014 '+sizeStr);
      }}}
      _addDlButton(logGrp);
      el.appendChild(logGrp);
    }else{
      var logGrp2=_sg('Logs');
      _addDlButton(logGrp2);
      el.appendChild(logGrp2);
    }

  }).catch(function(e){showPageError('settings-content','Failed to load settings: '+e.message,loadSettings);});}

/* --- Helpers --- */
function _sg(title){
  var grp=document.createElement('div');grp.className='setting-group';
  var h=document.createElement('h3');h.textContent=title;grp.appendChild(h);return grp;
}
function _readRow(parent,label,value){
  var row=document.createElement('div');row.className='setting-row';
  var k=document.createElement('div');k.className='setting-key';k.textContent=label;
  var v=document.createElement('div');v.className='setting-val';v.textContent=String(value);
  v.style.color='var(--text-muted)';row.appendChild(k);row.appendChild(v);parent.appendChild(row);
}
function _editRow(parent,label,key,type,value,opts){
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
  row.appendChild(k);row.appendChild(v);parent.appendChild(row);
}
function _addSG(parent,title,rows){
  var grp=_sg(title);
  for(var i=0;i<rows.length;i++){
    var row=document.createElement('div');row.className='setting-row';
    var k=document.createElement('div');k.className='setting-key';k.textContent=rows[i][0];
    var v=document.createElement('div');v.className='setting-val';v.textContent=String(rows[i][1]);
    if(rows[i].length>2)v.classList.add(rows[i][2]?'enabled':'disabled');
    row.appendChild(k);row.appendChild(v);grp.appendChild(row);
  }
  parent.appendChild(grp);
}
function _addLockedSG(parent,title,rows){
  var grp=document.createElement('div');grp.className='setting-group';grp.style.opacity='0.5';
  var h=document.createElement('h3');h.textContent=title;
  var lock=document.createElement('span');lock.textContent=' (Pro)';
  lock.style.cssText='font-size:.65rem;color:var(--text-muted);font-weight:400';
  h.appendChild(lock);grp.appendChild(h);
  for(var i=0;i<rows.length;i++){
    var row=document.createElement('div');row.className='setting-row';
    var k=document.createElement('div');k.className='setting-key';k.textContent=rows[i][0];
    var v=document.createElement('div');v.className='setting-val disabled';v.textContent=String(rows[i][1]);
    row.appendChild(k);row.appendChild(v);grp.appendChild(row);
  }
  parent.appendChild(grp);
}
function _addDlButton(parent){
  var dlBtn=document.createElement('button');dlBtn.textContent='Download Sanitized Logs';
  dlBtn.style.cssText='font-family:var(--font-data);font-size:.78rem;padding:6px 14px;background:var(--bg-base);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--accent);cursor:pointer;margin-top:8px';
  dlBtn.addEventListener('click',function(){window.location.href='/api/v1/logs/download'});
  parent.appendChild(dlBtn);
  var dlNote=document.createElement('span');dlNote.style.cssText='font-size:.72rem;color:var(--text-muted);margin-left:8px';
  dlNote.textContent='IPs and file paths are sanitized for safe sharing';
  parent.appendChild(dlNote);
}
function _saveSettings(statusEl){
  var inputs=document.querySelectorAll('.config-input');
  var changes={};var count=0;
  for(var i=0;i<inputs.length;i++){
    var inp=inputs[i];var key=inp.getAttribute('data-config-key');
    var orig=inp.getAttribute('data-original');
    var val=inp.value;
    if(val!==orig){changes[key]=val;count++;}
  }
  if(!count){statusEl.textContent='No changes';statusEl.style.color='var(--text-muted)';return;}
  statusEl.textContent='Saving...';statusEl.style.color='var(--text-muted)';
  fetch('/api/v1/config',{method:'PUT',headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify(changes)}).then(function(r){return r.json()}).then(function(res){
    if(res.error==='pro_required'){
      statusEl.textContent='Pro license required for config changes';
      statusEl.style.color='var(--warning)';return;
    }
    if(res.applied){
      statusEl.textContent=Object.keys(res.applied).length+' setting(s) saved \u2014 applied immediately';
      statusEl.style.color='var(--accent)';
      for(var j=0;j<inputs.length;j++){inputs[j].setAttribute('data-original',inputs[j].value);}
    }
    if(res.errors&&res.errors.length){
      statusEl.textContent+=' ('+res.errors.length+' error(s))';
      statusEl.style.color='var(--warning)';
    }
  }).catch(function(e){statusEl.textContent='Failed: '+e.message;statusEl.style.color='var(--critical)';});
}
