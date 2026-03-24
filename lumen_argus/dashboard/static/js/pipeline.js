/* pipeline.js — Pipeline configuration page.
   Displays scanning stages grouped by direction (request, response, protocol).
   Community: stage toggles, sub-detector toggles, default action selector.
   Pro: per-stage/per-detector action overrides (via plugin extension). */

var _pipelineActionOpts=['log','alert','block'];

function loadPipeline(){
  Promise.all([
    fetch('/api/v1/pipeline').then(function(r){return r.json()}),
    fetch('/api/v1/status').then(function(r){return r.json()})
  ]).then(function(results){
    var data=results[0],status=results[1];
    var isProActive=(status.tier==='pro'||status.tier==='enterprise');
    _pipelineActionOpts=isProActive?['log','alert','redact','block']:['log','alert','block'];

    var el=document.getElementById('page-pipeline');el.replaceChildren();

    /* Header bar with title + default action selector */
    var hdr=document.createElement('div');hdr.className='pipeline-header';
    var title=document.createElement('h2');title.textContent='Pipeline';
    title.style.cssText='margin:0;font-size:1.1rem;font-weight:600';
    hdr.appendChild(title);

    var actWrap=document.createElement('div');actWrap.className='pipeline-action-wrap';
    var actLabel=document.createElement('span');actLabel.textContent='Default action';
    actLabel.style.cssText='font-size:.72rem;color:var(--text-secondary);margin-right:8px';
    actWrap.appendChild(actLabel);
    var actSel=document.createElement('select');
    actSel.className='config-input pipeline-select';
    actSel.setAttribute('data-config-key','default_action');
    actSel.setAttribute('data-original',data.default_action);
    _pipelineActionOpts.forEach(function(a){
      var o=document.createElement('option');o.value=a;o.textContent=a;
      if(a===data.default_action)o.selected=true;actSel.appendChild(o);
    });
    actWrap.appendChild(actSel);
    hdr.appendChild(actWrap);
    el.appendChild(hdr);

    /* Group stages by direction */
    var groups={request:[],response:[],protocol:[]};
    var groupLabels={request:'Request Scanning',response:'Response Scanning',protocol:'Protocol Scanning'};
    (data.stages||[]).forEach(function(s){
      if(groups[s.group])groups[s.group].push(s);
    });

    for(var g in groups){if(!groups.hasOwnProperty(g))continue;
      var stages=groups[g];
      if(!stages.length)continue;
      var card=document.createElement('div');card.className='pipeline-group';
      var glabel=document.createElement('div');glabel.className='pipeline-group-label';
      glabel.textContent=groupLabels[g]||g;
      card.appendChild(glabel);

      stages.forEach(function(stage){
        var row=_pipelineStageRow(stage);
        card.appendChild(row);
      });
      el.appendChild(card);
    }

    /* Advanced settings */
    var advCard=document.createElement('div');advCard.className='pipeline-group';
    var advLabel=document.createElement('div');advLabel.className='pipeline-group-label';
    advLabel.textContent='Advanced';advCard.appendChild(advLabel);

    var parRow=document.createElement('div');parRow.className='pipeline-stage';
    var parTop=document.createElement('div');parTop.className='pipeline-stage-top';
    var parToggle=document.createElement('label');parToggle.className='pipeline-toggle';
    var parCb=document.createElement('input');parCb.type='checkbox';
    parCb.checked=!!data.parallel_batching;
    parCb.setAttribute('data-config-key','parallel_batching');
    parCb.setAttribute('data-original',String(!!data.parallel_batching));
    var parSlider=document.createElement('span');parSlider.className='pipeline-slider';
    parToggle.appendChild(parCb);parToggle.appendChild(parSlider);
    parTop.appendChild(parToggle);
    var parLabel=document.createElement('div');parLabel.className='pipeline-stage-info';
    var parName=document.createElement('div');parName.className='pipeline-stage-name';
    parName.textContent='Parallel rule evaluation';
    var parDesc=document.createElement('div');parDesc.className='pipeline-stage-desc';
    parDesc.textContent='Evaluate candidate rules in parallel threads (experimental)';
    parLabel.appendChild(parName);parLabel.appendChild(parDesc);
    parTop.appendChild(parLabel);
    parRow.appendChild(parTop);advCard.appendChild(parRow);
    el.appendChild(advCard);

    /* Save button */
    var saveBar=document.createElement('div');saveBar.className='pipeline-save-bar';
    var saveBtn=document.createElement('button');saveBtn.className='btn btn-primary';
    saveBtn.textContent='Save Pipeline Config';
    var saveStatus=document.createElement('span');saveStatus.className='pipeline-save-status';
    saveBtn.addEventListener('click',function(){_savePipeline(saveStatus)});
    saveBar.appendChild(saveStatus);
    saveBar.appendChild(saveBtn);
    el.appendChild(saveBar);

    /* Notify plugins that pipeline page has been (re)built */
    document.dispatchEvent(new CustomEvent('pipeline-rendered'));

  }).catch(function(e){
    showPageError('page-pipeline','Failed to load pipeline config: '+e.message,loadPipeline);
  });
}

function _pipelineStageRow(stage){
  var row=document.createElement('div');
  row.className='pipeline-stage'+(stage.available?'':' pipeline-stage-unavailable');

  /* Toggle + label line */
  var top=document.createElement('div');top.className='pipeline-stage-top';

  var toggle=document.createElement('label');toggle.className='pipeline-toggle';
  var cb=document.createElement('input');cb.type='checkbox';
  cb.checked=stage.enabled;cb.disabled=!stage.available;
  cb.setAttribute('data-stage',stage.name);
  cb.setAttribute('data-original',String(stage.enabled));
  cb.className='pipeline-cb';
  var slider=document.createElement('span');slider.className='pipeline-slider';
  toggle.appendChild(cb);toggle.appendChild(slider);
  top.appendChild(toggle);

  var info=document.createElement('div');info.className='pipeline-stage-info';
  var nameEl=document.createElement('span');nameEl.className='pipeline-stage-name';
  nameEl.textContent=stage.label;
  info.appendChild(nameEl);
  var desc=document.createElement('span');desc.className='pipeline-stage-desc';
  desc.textContent=stage.description;
  info.appendChild(desc);
  top.appendChild(info);

  /* Right side: badge */
  var badge=document.createElement('span');
  if(!stage.available){
    badge.className='badge info';badge.textContent='Coming soon';
  } else if(stage.finding_count>0){
    badge.className='badge';badge.style.cssText='background:var(--accent-dim);color:var(--accent)';
    badge.textContent=stage.finding_count+' finds';
  } else {
    badge.className='badge';badge.style.cssText='background:var(--bg-raised);color:var(--text-muted)';
    badge.textContent='0 finds';
  }
  top.appendChild(badge);
  row.appendChild(top);

  /* Sub-detectors (only for outbound_dlp) */
  if(stage.sub_detectors&&stage.sub_detectors.length){
    var subs=document.createElement('div');subs.className='pipeline-sub-detectors';
    stage.sub_detectors.forEach(function(det){
      var sub=document.createElement('div');sub.className='pipeline-sub-det';

      var subToggle=document.createElement('label');subToggle.className='pipeline-toggle pipeline-toggle-sm';
      var subCb=document.createElement('input');subCb.type='checkbox';
      subCb.checked=det.enabled;subCb.className='pipeline-cb';
      subCb.setAttribute('data-detector',det.name);
      subCb.setAttribute('data-original',String(det.enabled));
      var subSlider=document.createElement('span');subSlider.className='pipeline-slider';
      subToggle.appendChild(subCb);subToggle.appendChild(subSlider);
      sub.appendChild(subToggle);

      var subName=document.createElement('span');subName.className='pipeline-sub-name';
      subName.textContent=det.name.charAt(0).toUpperCase()+det.name.slice(1);
      sub.appendChild(subName);

      var subActionSel=document.createElement('select');
      subActionSel.className='pipeline-action-select config-input';
      subActionSel.setAttribute('data-config-key','detectors.'+det.name+'.action');
      subActionSel.setAttribute('data-original',det.action);
      ['default'].concat(_pipelineActionOpts).forEach(function(a){
        var o=document.createElement('option');o.value=a;o.textContent=a;
        subActionSel.appendChild(o);
      });
      subActionSel.value=det.action;
      sub.appendChild(subActionSel);

      if(det.finding_count>0){
        var subCount=document.createElement('span');subCount.className='pipeline-sub-count';
        subCount.textContent=det.finding_count;sub.appendChild(subCount);
      }
      subs.appendChild(sub);
    });
    row.appendChild(subs);
  }

  /* Encoding settings (only for encoding_decode) */
  if(stage.encoding_settings){
    var enc=stage.encoding_settings;
    var encWrap=document.createElement('div');encWrap.className='pipeline-sub-detectors';

    /* Encoding toggles row */
    var encToggles=document.createElement('div');encToggles.className='pipeline-enc-row';
    var encLabel=document.createElement('span');encLabel.className='pipeline-enc-label';
    encLabel.textContent='Encodings';encToggles.appendChild(encLabel);
    ['base64','hex','url','unicode'].forEach(function(e){
      var item=document.createElement('label');item.className='pipeline-enc-item';
      var cb=document.createElement('input');cb.type='checkbox';cb.checked=enc[e];
      cb.className='pipeline-enc-cb';cb.setAttribute('data-encoding',e);
      cb.setAttribute('data-original',String(enc[e]));
      item.appendChild(cb);
      var lbl=document.createElement('span');lbl.textContent=e;item.appendChild(lbl);
      encToggles.appendChild(item);
    });
    encWrap.appendChild(encToggles);

    /* Numeric settings row */
    var numRow=document.createElement('div');numRow.className='pipeline-enc-row';
    [['max_depth','Depth',1,5],['min_decoded_length','Min length',1,100],
     ['max_decoded_length','Max length',100,1000000]].forEach(function(s){
      var item=document.createElement('div');item.className='pipeline-enc-num';
      var lbl=document.createElement('span');lbl.className='pipeline-enc-label';
      lbl.textContent=s[1];item.appendChild(lbl);
      var inp=document.createElement('input');inp.type='number';
      inp.className='pipeline-enc-input';inp.value=enc[s[0]];
      inp.min=s[2];inp.max=s[3];
      inp.setAttribute('data-enc-setting',s[0]);
      inp.setAttribute('data-original',String(enc[s[0]]));
      item.appendChild(inp);numRow.appendChild(item);
    });
    encWrap.appendChild(numRow);
    row.appendChild(encWrap);
  }

  return row;
}

function _savePipeline(statusEl){
  var changes={};

  /* Default action */
  var actSel=document.querySelector('.pipeline-select[data-config-key="default_action"]');
  if(actSel&&actSel.value!==actSel.getAttribute('data-original')){
    changes.default_action=actSel.value;
  }

  /* Stage toggles — only include changed */
  var stageCbs=document.querySelectorAll('.pipeline-cb[data-stage]');
  var stageChanges={};
  for(var i=0;i<stageCbs.length;i++){
    var cb=stageCbs[i];
    if(String(cb.checked)!==cb.getAttribute('data-original')){
      stageChanges[cb.getAttribute('data-stage')]={enabled:cb.checked};
    }
  }
  if(Object.keys(stageChanges).length)changes.stages=stageChanges;

  /* Detector toggles + action overrides — only include changed */
  var detCbs=document.querySelectorAll('.pipeline-cb[data-detector]');
  var detChanges={};
  for(var j=0;j<detCbs.length;j++){
    var dcb=detCbs[j];
    if(String(dcb.checked)!==dcb.getAttribute('data-original')){
      if(!detChanges[dcb.getAttribute('data-detector')])detChanges[dcb.getAttribute('data-detector')]={};
      detChanges[dcb.getAttribute('data-detector')].enabled=dcb.checked;
    }
  }
  var detActionSels=document.querySelectorAll('.pipeline-action-select');
  for(var k=0;k<detActionSels.length;k++){
    var sel=detActionSels[k];
    var key=sel.getAttribute('data-config-key');
    if(!key)continue;
    var detName=key.split('.')[1]; /* detectors.secrets.action -> secrets */
    if(sel.value!==sel.getAttribute('data-original')){
      if(!detChanges[detName])detChanges[detName]={};
      detChanges[detName].action=sel.value;
    }
  }
  if(Object.keys(detChanges).length)changes.detectors=detChanges;

  /* Encoding settings — only include changed */
  var encCbs=document.querySelectorAll('.pipeline-enc-cb');
  var encChanges={};
  for(var m=0;m<encCbs.length;m++){
    var ecb=encCbs[m];
    if(String(ecb.checked)!==ecb.getAttribute('data-original')){
      encChanges[ecb.getAttribute('data-encoding')]=ecb.checked;
    }
  }
  var encInputs=document.querySelectorAll('.pipeline-enc-input');
  for(var n=0;n<encInputs.length;n++){
    var ei=encInputs[n];
    if(ei.value!==ei.getAttribute('data-original')){
      encChanges[ei.getAttribute('data-enc-setting')]=Number(ei.value);
    }
  }
  if(Object.keys(encChanges).length)changes.encoding_settings=encChanges;

  /* Parallel batching toggle */
  var parCb=document.querySelector('input[data-config-key="parallel_batching"]');
  if(parCb&&String(parCb.checked)!==parCb.getAttribute('data-original')){
    changes.parallel_batching=parCb.checked;
  }

  if(!changes.default_action&&!changes.stages&&!changes.detectors&&!changes.encoding_settings&&!('parallel_batching' in changes)){
    statusEl.textContent='No changes';statusEl.style.color='var(--text-muted)';return;
  }

  statusEl.textContent='Saving...';statusEl.style.color='var(--text-secondary)';
  fetch('/api/v1/pipeline',{
    method:'PUT',
    headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify(changes)
  }).then(function(r){return r.json().then(function(d){return{status:r.status,data:d}})})
  .then(function(res){
    if(res.data.applied){
      var n=Object.keys(res.data.applied).length;
      statusEl.textContent=n+' setting(s) saved';
      statusEl.style.color='var(--accent)';
      /* Reload page after brief delay to show message and reflect saved state.
         Use the registered loadFn so Pro extensions are preserved. */
      _pipelineStages=null; /* invalidate dashboard health cache */
      setTimeout(function(){
        var reg=_registeredPages['pipeline'];
        if(reg&&reg.loadFn)reg.loadFn();else loadPipeline();
      }, 600);
    }
    if(res.data.errors&&res.data.errors.length){
      statusEl.textContent+=' ('+res.data.errors.length+' error(s))';
      statusEl.style.color='var(--high)';
    }
  }).catch(function(e){
    statusEl.textContent='Failed: '+e.message;
    statusEl.style.color='var(--critical)';
  });
}
