/* Animate only presentation. No evidence values, ordering or collector state change. */
(() => {
 const reduced=matchMedia('(prefers-reduced-motion: reduce)');
 const totals=new Map(),seen=new Set();
 function reveal(){
  if(reduced.matches)return;
  const view=document.querySelector('.view.active');if(!view)return;
  view.animate([{opacity:.55,transform:'translateY(5px)'},{opacity:1,transform:'translateY(0)'}],{duration:230,easing:'ease-out'});
  [...view.querySelectorAll('.panel,.asset-card,.scenario-card')].slice(0,14).forEach((node,i)=>{
   node.animate([{opacity:0,transform:'translateY(13px)'},{opacity:1,transform:'translateY(0)'}],{duration:390,delay:Math.min(i*32,220),easing:'cubic-bezier(.16,.7,.2,1)',fill:'backwards'});
  });
  view.querySelectorAll('.target-track i,.stage-track i').forEach(node=>node.animate([{transform:'scaleX(0)'},{transform:'scaleX(1)'}],{duration:550,easing:'cubic-bezier(.2,.8,.2,1)',transformOrigin:'left'}));
 }
 function metrics(root){
  [...root.querySelectorAll('.metric-value')].forEach((node,index)=>{
   const text=[...node.childNodes].find(n=>n.nodeType===Node.TEXT_NODE);if(!text)return;
   const match=text.data.trim().match(/^(\d+(?:[.,]\d+)?)(.*)$/);if(!match)return;
   const target=Number(match[1].replace(',','.')),key=root.id+':'+index,previous=totals.get(key);
   totals.set(key,target);if(reduced.matches||previous===target)return;
   const initial=previous??0,started=performance.now(),suffix=match[2],decimal=/[.,]/.test(match[1]);
   node.setAttribute('aria-label',text.data.trim());
   node.animate([{filter:'brightness(1.6)'},{filter:'brightness(1)'}],{duration:650,easing:'ease-out'});
   function frame(now){if(!node.isConnected||reduced.matches){if(node.isConnected)text.data=match[1]+suffix;return;}const progress=Math.min(1,(now-started)/560),eased=1-Math.pow(1-progress,3),value=initial+(target-initial)*eased;text.data=(progress===1?match[1]:decimal?value.toFixed(1).replace('.',','):String(Math.round(value)))+suffix;if(progress<1)requestAnimationFrame(frame);}
   requestAnimationFrame(frame);
  });
 }
 function rows(root){
  const nodes=[...root.querySelectorAll('[data-event],[data-evidence]')];let flashed=0;
  for(const node of nodes){const id=node.dataset.event||node.dataset.evidence;if(seen.has(id))continue;seen.add(id);if(reduced.matches||flashed++>=5||!node.closest('.view.active'))continue;node.animate([{backgroundColor:'rgba(235,62,138,.24)'},{backgroundColor:'rgba(235,62,138,0)'}],{duration:1100,easing:'ease-out'});}
  if(seen.size>5000){for(const id of [...seen].slice(0,2000))seen.delete(id);}
 }
 document.addEventListener('click',event=>{if(event.target.closest('[data-view],[data-go],[data-scope]'))requestAnimationFrame(reveal);});
 document.addEventListener('DOMContentLoaded',()=>{
  reveal();
  for(const id of ['metrics','telemetry-metrics','event-feed','indexed-events']){
   const root=document.getElementById(id);if(!root)continue;
   const update=()=>id.includes('metrics')?metrics(root):rows(root);
   new MutationObserver(update).observe(root,{childList:true});update();
  }
 });
})();
