const $ = (id) => document.getElementById(id);
let currentAlerts = [];
let toastTimer;
async function api(path, options={}) {
  const response = await fetch(path, options);
  let data = {};
  try { data = await response.json(); } catch (_) {}
  if (!response.ok) throw new Error(data.detail?.message || data.detail || data.message || `Request failed (${response.status})`);
  return data;
}
function toast(message, error=false) {
  const el=$("toast"); el.textContent=message; el.classList.toggle("error",error); el.classList.remove("hidden");
  clearTimeout(toastTimer); toastTimer=setTimeout(()=>el.classList.add("hidden"),3500);
}
function setView(view) {
  document.querySelectorAll(".view").forEach(el=>el.classList.add("hidden"));
  $(`view-${view}`).classList.remove("hidden");
  document.querySelectorAll(".nav-item").forEach(el=>el.classList.toggle("active",el.dataset.view===view));
  const names={dashboard:["Security overview","OVERVIEW"],alerts:["Threat alerts","ALERT MANAGEMENT"],ingestion:["Log ingestion","DATA INGESTION"]};
  $("pageTitle").textContent=names[view][0]; $("pageCrumb").textContent=names[view][1];
  if(view==="alerts") loadAlerts();
}
document.querySelectorAll(".nav-item").forEach(el=>el.addEventListener("click",()=>setView(el.dataset.view)));
document.querySelectorAll("[data-goto]").forEach(el=>el.addEventListener("click",()=>setView(el.dataset.goto)));
function severityClass(s){return `sev-${String(s||"low").toLowerCase()}`}
function renderTable(alerts, target) {
  if(!alerts.length){$(target).innerHTML='<div class="empty-state">No matching alerts. Upload the synthetic sample to generate findings.</div>';return}
  $(target).innerHTML=`<div class="table-wrap"><table><thead><tr><th>Alert</th><th>Severity</th><th>Detection</th><th>Source IP</th><th>Risk</th><th>Status</th></tr></thead><tbody>${alerts.map(a=>`<tr data-alert-id="${a.id}"><td>#CS-${String(a.id).padStart(4,"0")}</td><td><span class="severity ${severityClass(a.severity)}">${esc(a.severity)}</span></td><td>${esc(a.category)}</td><td>${esc(a.source_ip)}</td><td>${a.risk_score}/100</td><td><span class="status-pill ${a.status==="Resolved"?"status-resolved":""}">${esc(a.status)}</span></td></tr>`).join("")}</tbody></table></div>`;
  $(target).querySelectorAll("[data-alert-id]").forEach(row=>row.addEventListener("click",()=>showAlert(row.dataset.alertId)));
}
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
async function loadStats(){
  const s=await api("/api/dashboard/stats");
  $("mEvents").textContent=s.processed_events;$("mAlerts").textContent=s.total_alerts;$("mOpen").textContent=s.open_alerts;$("mHigh").textContent=s.high_critical_alerts;$("sideAlertCount").textContent=s.total_alerts;
  const counts=s.severity_distribution||{}, order=["Critical","High","Medium","Low"], total=Math.max(1,order.reduce((n,k)=>n+(counts[k]||0),0));
  $("severityChart").innerHTML=order.map(k=>`<div class="severity-row"><span>${k}</span><div class="bar-track"><div class="bar-fill bar-${k.toLowerCase()}" style="width:${Math.round((counts[k]||0)/total*100)}%"></div></div><strong>${counts[k]||0}</strong></div>`).join("");
}
async function loadAlerts(){
  const p=new URLSearchParams();p.set("severity",$("severityFilter").value);p.set("status",$("statusFilter").value);p.set("search",$("searchInput").value.trim());
  const data=await api("/api/alerts?"+p.toString());currentAlerts=data.alerts;$("alertTotalTag").textContent=`${data.count} RECORDS`;renderTable(currentAlerts,"alertsTable");
  if(!$("view-alerts").classList.contains("hidden") && !currentAlerts.length)$("alertDetail").innerHTML='<div class="empty-state">Select an alert from the table to inspect details.</div>';
}
async function showAlert(id){
  try{
    const a=await api(`/api/alerts/${id}`);
    $("alertDetail").innerHTML=`<div class="panel-head"><div><h3>Alert #CS-${String(a.id).padStart(4,"0")}</h3><p>${esc(a.category)}</p></div><span class="severity ${severityClass(a.severity)}">${esc(a.severity)}</span></div><div class="detail-grid"><div class="detail-cell"><small>Source IP</small><strong>${esc(a.source_ip)}</strong></div><div class="detail-cell"><small>Risk score</small><strong>${a.risk_score}/100</strong></div><div class="detail-cell"><small>Status</small><strong>${esc(a.status)}</strong></div></div><p class="detail-copy">${esc(a.description)}</p><h4>Supporting evidence</h4><ul class="evidence-list">${(a.evidence||[]).map(x=>`<li>${esc(x)}</li>`).join("")}</ul><h4>Recommended action</h4><p class="detail-copy">${esc(a.recommendation)}</p><p class="muted">Detected at ${esc(a.timestamp)} · Rule-based detection</p>${a.status==="Open"?`<button class="secondary-button resolve-button" id="resolveBtn">Mark as resolved</button>`:""}`;
    if($("resolveBtn"))$("resolveBtn").addEventListener("click",async()=>{try{await api(`/api/alerts/${id}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({status:"Resolved"})});toast("Alert marked as resolved.");await refreshAll();await showAlert(id)}catch(e){toast(e.message,true)}});
  }catch(e){toast(e.message,true)}
}
async function refreshAll(){
  try{
    await loadStats();await loadAlerts();
    $("connectionText").textContent="Connected · API healthy";
    document.querySelector(".status-dot").style.background="var(--green)";
    const recent=await api("/api/alerts");
    renderTable(recent.alerts.slice(0,5),"recentAlerts");
  }catch(e){
    $("connectionText").textContent="Backend unavailable";
    document.querySelector(".status-dot").style.background="var(--red)";
    toast("Cannot reach backend. Start the server and refresh.",true);
  }
}
$("refreshBtn").addEventListener("click",refreshAll);
$("searchInput").addEventListener("input",()=>loadAlerts().catch(e=>toast(e.message,true)));
$("severityFilter").addEventListener("change",()=>loadAlerts().catch(e=>toast(e.message,true)));
$("statusFilter").addEventListener("change",()=>loadAlerts().catch(e=>toast(e.message,true)));
$("uploadForm").addEventListener("submit",async ev=>{
  ev.preventDefault();const file=$("csvFile").files[0];if(!file)return;
  const btn=$("uploadButton");btn.disabled=true;btn.textContent="Analyzing…";
  try{
    const form=new FormData();form.append("file",file);
    const result=await api("/api/logs/upload",{method:"POST",body:form});
    $("uploadResult").className="result-box success";$("uploadResult").innerHTML=`<strong>Processing complete</strong><br>Valid rows: ${result.valid_rows}<br>New events stored: ${result.new_events}<br>Total alerts: ${result.total_alerts}${result.rejected_rows.length?`<br>Rejected rows: ${result.rejected_rows.length}`:""}`;
    await refreshAll();toast("CSV processed successfully.");
  }catch(e){$("uploadResult").className="result-box error";$("uploadResult").textContent=e.message;toast(e.message,true)}
  finally{btn.disabled=false;btn.textContent="Upload and analyze"}
});
$("sampleButton").addEventListener("click",async()=>{
  const btn=$("sampleButton");btn.disabled=true;btn.textContent="Processing sample…";
  try{const r=await api("/api/demo/sample",{method:"POST"});$("uploadResult").className="result-box success";$("uploadResult").textContent=`Synthetic sample processed. Valid rows: ${r.valid_rows}; new events: ${r.new_events}; total alerts: ${r.total_alerts}.`;await refreshAll();toast("Synthetic demo data loaded.");setView("dashboard")}
  catch(e){$("uploadResult").className="result-box error";$("uploadResult").textContent=e.message;toast(e.message,true)}
  finally{btn.disabled=false;btn.textContent="Run synthetic sample"}
});
$("resetButton").addEventListener("click",async()=>{
  if(!confirm("Clear all local demo events and alerts?"))return;
  try{await api("/api/demo/reset",{method:"POST"});await refreshAll();$("uploadResult").className="result-box success";$("uploadResult").textContent="Demo data cleared. Upload the sample CSV to run detections again.";toast("Demo data reset.")}catch(e){toast(e.message,true)}
});
refreshAll();
