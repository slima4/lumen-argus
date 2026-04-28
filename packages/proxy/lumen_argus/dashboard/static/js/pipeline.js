/* pipeline.js — Pipeline configuration page.
   Displays scanning stages grouped by direction (request, response, protocol).
   Stage toggles, sub-detector toggles, default action selector.
   Plugins extend the action set via registerPipelineAction(name). */

const _BASE_PIPELINE_ACTIONS=['log','alert','redact','block'];
const _extraPipelineActions=[];
let _pipelineActionOpts=_BASE_PIPELINE_ACTIONS.slice();

function registerPipelineAction(name){
  if(_extraPipelineActions.indexOf(name)===-1)_extraPipelineActions.push(name);
}

function loadPipeline(){
  fetch('/api/v1/pipeline').then(function(r){return r.json()}).then(function(data){
    _pipelineActionOpts=_BASE_PIPELINE_ACTIONS.concat(_extraPipelineActions);

    const el=document.getElementById('page-pipeline');el.replaceChildren();

    /* Header bar with title + default action selector */
    const hdr=document.createElement('div');hdr.className='pipeline-header';
    const title=document.createElement('h2');title.textContent='Pipeline';
    title.style.cssText='margin:0;font-size:1.1rem;font-weight:600';
    hdr.appendChild(title);

    const actWrap=document.createElement('div');actWrap.className='pipeline-action-wrap';
    const actLabel=document.createElement('span');actLabel.textContent='Default action';
    actLabel.style.cssText='font-size:.72rem;color:var(--text-secondary);margin-right:8px';
    actWrap.appendChild(actLabel);
    const actSel=document.createElement('select');
    actSel.className='config-input pipeline-select';
    actSel.dataset.configKey='default_action';
    actSel.dataset.original=data.default_action;
    _pipelineActionOpts.forEach(function(a){
      const o=document.createElement('option');o.value=a;o.textContent=a;
      if(a===data.default_action)o.selected=true;actSel.appendChild(o);
    });
    actWrap.appendChild(actSel);
    hdr.appendChild(actWrap);
    el.appendChild(hdr);

    /* Group stages by direction */
    const groups={request:[],response:[],protocol:[]};
    const groupLabels={request:'Request Scanning',response:'Response Scanning',protocol:'Protocol Scanning'};
    (data.stages||[]).forEach(function(s){
      if(groups[s.group])groups[s.group].push(s);
    });

    for(const g in groups){if(!groups.hasOwnProperty(g))continue;
      const stages=groups[g];
      if(!stages.length)continue;
      const card=document.createElement('div');card.className='pipeline-group';
      const glabel=document.createElement('div');glabel.className='pipeline-group-label';
      glabel.textContent=groupLabels[g]||g;
      card.appendChild(glabel);

      stages.forEach(function(stage){
        const row=_pipelineStageRow(stage);
        card.appendChild(row);
      });
      el.appendChild(card);
    }

    /* Advanced settings */
    const advCard=document.createElement('div');advCard.className='pipeline-group';
    const advLabel=document.createElement('div');advLabel.className='pipeline-group-label';
    advLabel.textContent='Advanced';advCard.appendChild(advLabel);

    const parRow=document.createElement('div');parRow.className='pipeline-stage';
    const parTop=document.createElement('div');parTop.className='pipeline-stage-top';
    const parToggle=document.createElement('label');parToggle.className='pipeline-toggle';
    const parCb=document.createElement('input');parCb.type='checkbox';
    parCb.checked=!!data.parallel_batching;
    parCb.dataset.configKey='parallel_batching';
    parCb.dataset.original=String(!!data.parallel_batching);
    const parSlider=document.createElement('span');parSlider.className='pipeline-slider';
    parToggle.appendChild(parCb);parToggle.appendChild(parSlider);
    parTop.appendChild(parToggle);
    const parLabel=document.createElement('div');parLabel.className='pipeline-stage-info';
    const parName=document.createElement('div');parName.className='pipeline-stage-name';
    parName.textContent='Parallel rule evaluation';
    const parDesc=document.createElement('div');parDesc.className='pipeline-stage-desc';
    parDesc.textContent='Evaluate candidate rules in parallel threads (experimental)';
    parLabel.appendChild(parName);parLabel.appendChild(parDesc);
    parTop.appendChild(parLabel);
    parRow.appendChild(parTop);advCard.appendChild(parRow);
    el.appendChild(advCard);

    /* Save button */
    const saveBar=document.createElement('div');saveBar.className='pipeline-save-bar';
    const saveBtn=document.createElement('button');saveBtn.className='btn btn-primary';
    saveBtn.textContent='Save Pipeline Config';
    const saveStatus=document.createElement('span');saveStatus.className='pipeline-save-status';
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
  const row=document.createElement('div');
  row.className='pipeline-stage'+(stage.available?'':' pipeline-stage-unavailable');

  /* Toggle + label line */
  const top=document.createElement('div');top.className='pipeline-stage-top';

  const toggle=document.createElement('label');toggle.className='pipeline-toggle';
  const cb=document.createElement('input');cb.type='checkbox';
  cb.checked=stage.enabled;cb.disabled=!stage.available;
  cb.dataset.stage=stage.name;
  cb.dataset.original=String(stage.enabled);
  cb.className='pipeline-cb';
  const slider=document.createElement('span');slider.className='pipeline-slider';
  toggle.appendChild(cb);toggle.appendChild(slider);
  top.appendChild(toggle);

  const info=document.createElement('div');info.className='pipeline-stage-info';
  const nameEl=document.createElement('span');nameEl.className='pipeline-stage-name';
  nameEl.textContent=stage.label;
  info.appendChild(nameEl);
  const desc=document.createElement('span');desc.className='pipeline-stage-desc';
  desc.textContent=stage.description;
  info.appendChild(desc);
  top.appendChild(info);

  /* Right side: badge */
  const badge=document.createElement('span');
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
    const subs=document.createElement('div');subs.className='pipeline-sub-detectors';
    stage.sub_detectors.forEach(function(det){
      const sub=document.createElement('div');sub.className='pipeline-sub-det';

      const subToggle=document.createElement('label');subToggle.className='pipeline-toggle pipeline-toggle-sm';
      const subCb=document.createElement('input');subCb.type='checkbox';
      subCb.checked=det.enabled;subCb.className='pipeline-cb';
      subCb.dataset.detector=det.name;
      subCb.dataset.original=String(det.enabled);
      const subSlider=document.createElement('span');subSlider.className='pipeline-slider';
      subToggle.appendChild(subCb);subToggle.appendChild(subSlider);
      sub.appendChild(subToggle);

      const subName=document.createElement('span');subName.className='pipeline-sub-name';
      subName.textContent=titlecase(det.name);
      sub.appendChild(subName);

      const subActionSel=document.createElement('select');
      subActionSel.className='pipeline-action-select config-input';
      subActionSel.dataset.configKey='detectors.'+det.name+'.action';
      subActionSel.dataset.original=det.action;
      ['default'].concat(_pipelineActionOpts).forEach(function(a){
        const o=document.createElement('option');o.value=a;o.textContent=a;
        subActionSel.appendChild(o);
      });
      subActionSel.value=det.action;
      sub.appendChild(subActionSel);

      if(det.finding_count>0){
        const subCount=document.createElement('span');subCount.className='pipeline-sub-count';
        subCount.textContent=det.finding_count;sub.appendChild(subCount);
      }
      subs.appendChild(sub);
    });
    row.appendChild(subs);
  }

  /* Encoding settings (only for encoding_decode) */
  if(stage.encoding_settings){
    const enc=stage.encoding_settings;
    const encWrap=document.createElement('div');encWrap.className='pipeline-sub-detectors';

    /* Encoding toggles row */
    const encToggles=document.createElement('div');encToggles.className='pipeline-enc-row';
    const encLabel=document.createElement('span');encLabel.className='pipeline-enc-label';
    encLabel.textContent='Encodings';encToggles.appendChild(encLabel);
    ['base64','hex','url','unicode'].forEach(function(e){
      const item=document.createElement('label');item.className='pipeline-enc-item';
      const cb=document.createElement('input');cb.type='checkbox';cb.checked=enc[e];
      cb.className='pipeline-enc-cb';cb.dataset.encoding=e;
      cb.dataset.original=String(enc[e]);
      item.appendChild(cb);
      const lbl=document.createElement('span');lbl.textContent=e;item.appendChild(lbl);
      encToggles.appendChild(item);
    });
    encWrap.appendChild(encToggles);

    /* Numeric settings row */
    const numRow=document.createElement('div');numRow.className='pipeline-enc-row';
    [['max_depth','Depth',1,5],['min_decoded_length','Min length',1,100],
     ['max_decoded_length','Max length',100,1000000]].forEach(function(s){
      const item=document.createElement('div');item.className='pipeline-enc-num';
      const lbl=document.createElement('span');lbl.className='pipeline-enc-label';
      lbl.textContent=s[1];item.appendChild(lbl);
      const inp=document.createElement('input');inp.type='number';
      inp.className='pipeline-enc-input';inp.value=enc[s[0]];
      inp.min=s[2];inp.max=s[3];
      inp.dataset.encSetting=s[0];
      inp.dataset.original=String(enc[s[0]]);
      item.appendChild(inp);numRow.appendChild(item);
    });
    encWrap.appendChild(numRow);
    row.appendChild(encWrap);
  }

  return row;
}

function _savePipeline(statusEl){
  const changes={};

  /* Default action */
  const actSel=document.querySelector('.pipeline-select[data-config-key="default_action"]');
  if(actSel&&actSel.value!==actSel.dataset.original){
    changes.default_action=actSel.value;
  }

  /* Stage toggles — only include changed */
  const stageCbs=document.querySelectorAll('.pipeline-cb[data-stage]');
  const stageChanges={};
  for(const cb of stageCbs){
    if(String(cb.checked)!==cb.dataset.original){
      stageChanges[cb.dataset.stage]={enabled:cb.checked};
    }
  }
  if(Object.keys(stageChanges).length)changes.stages=stageChanges;

  /* Detector toggles + action overrides — only include changed */
  const detCbs=document.querySelectorAll('.pipeline-cb[data-detector]');
  const detChanges={};
  for(const dcb of detCbs){
    if(String(dcb.checked)!==dcb.dataset.original){
      if(!detChanges[dcb.dataset.detector])detChanges[dcb.dataset.detector]={};
      detChanges[dcb.dataset.detector].enabled=dcb.checked;
    }
  }
  const detActionSels=document.querySelectorAll('.pipeline-action-select');
  for(const sel of detActionSels){
    const key=sel.dataset.configKey;
    if(!key)continue;
    const detName=key.split('.')[1]; /* detectors.secrets.action -> secrets */
    if(sel.value!==sel.dataset.original){
      if(!detChanges[detName])detChanges[detName]={};
      detChanges[detName].action=sel.value;
    }
  }
  if(Object.keys(detChanges).length)changes.detectors=detChanges;

  /* Encoding settings — only include changed */
  const encCbs=document.querySelectorAll('.pipeline-enc-cb');
  const encChanges={};
  for(const ecb of encCbs){
    if(String(ecb.checked)!==ecb.dataset.original){
      encChanges[ecb.dataset.encoding]=ecb.checked;
    }
  }
  const encInputs=document.querySelectorAll('.pipeline-enc-input');
  for(const ei of encInputs){
    if(ei.value!==ei.dataset.original){
      encChanges[ei.dataset.encSetting]=Number(ei.value);
    }
  }
  if(Object.keys(encChanges).length)changes.encoding_settings=encChanges;

  /* Parallel batching toggle */
  const parCb=document.querySelector('input[data-config-key="parallel_batching"]');
  if(parCb&&String(parCb.checked)!==parCb.dataset.original){
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
      const n=Object.keys(res.data.applied).length;
      statusEl.textContent=n+' setting(s) saved';
      statusEl.style.color='var(--accent)';
      /* Reload page after brief delay to show message and reflect saved state.
         Use the registered loadFn so Pro extensions are preserved. */
      _pipelineStages=null; /* invalidate dashboard health cache */
      setTimeout(function(){
        const reg=_registeredPages['pipeline'];
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
