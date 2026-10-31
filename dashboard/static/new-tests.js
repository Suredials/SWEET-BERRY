/* Fixed host operation; the model cannot invoke or parameterize this action. */
let newTestBusy=false,newTestAfter=0;
const testDialog=document.getElementById('new-test-dialog');
const testButton=document.getElementById('new-test-button');
const testStatus=document.getElementById('new-test-status');
function testMessage(message,error=false){testStatus.textContent=message;testStatus.classList.remove('hidden');testStatus.classList.toggle('test-error',error);}
testButton.addEventListener('click',()=>testDialog.showModal());
document.getElementById('cancel-new-test').addEventListener('click',()=>testDialog.close());
document.getElementById('confirm-new-test').addEventListener('click',async()=>{
 if(newTestBusy)return;
 newTestBusy=true;newTestAfter=Date.now()/1000;testButton.disabled=true;testDialog.close();
 testMessage('Guardando evidencia y preparando una nueva captura. Los objetivos siguen funcionando…');
 try{const accepted=await request('/api/test-runs','POST',{});newTestAfter=accepted.accepted_at||newTestAfter;}catch(error){
  // A service restart can cut the initiating connection; status is independent.
  if(!String(error.message).includes('fetch')){testMessage(error.message,true);newTestBusy=false;testButton.disabled=false;}
 }
});
async function checkNewTest(){
 try{
  const response=await fetch('/api/test-runs/status',{signal:AbortSignal.timeout(3000)});
  if(!response.ok)return;
  const status=await response.json();
  if(!status.available){testButton.disabled=true;testButton.title='Disponible en la Raspberry con el servicio de capturas instalado';return;}
  if(status.state==='running'){newTestBusy=true;testButton.disabled=true;testMessage('Guardando la captura y reiniciando colectores. Los contenedores se conservan…');}
  if(newTestBusy&&['done','error'].includes(status.state)&&(status.finished||0)>=newTestAfter){
   newTestBusy=false;testButton.disabled=false;
   if(status.state==='error'){testMessage('No se completó el guardado. Revisa sudo journalctl -u sweetberry-new-test. '+(status.error||''),true);return;}
   testMessage('Nueva prueba lista en '+status.elapsed_seconds+' s. Evidencia guardada en '+status.archive+'. Objetivos y señuelos conservados.');
   selected='all';scope='live';lastRenderStamp='';lastEvidence=[];operatorStamp='';analystStamp='';lastTelemetryStamp='';indexedRows=[];
   document.querySelectorAll('[data-scope]').forEach(b=>b.classList.toggle('selected',b.dataset.scope==='live'));
   await poll(true);
  }
 }catch{}finally{setTimeout(checkNewTest,1000);}
}
checkNewTest();
