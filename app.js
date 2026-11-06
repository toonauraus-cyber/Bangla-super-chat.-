const $ = s => document.querySelector(s);
const money = n => "৳" + Number(n||0).toLocaleString("en-BD",{maximumFractionDigits:2});
async function api(url, options={}) {
  const r=await fetch("/api"+url,{credentials:"same-origin",headers:{"Content-Type":"application/json"},...options});
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data.error||"Request failed");
  return data;
}
function msg(el,text,bad=false){el.textContent=text;el.style.color=bad?"#ff9aad":"#75e4bd";}
function status(s){return `<span class="status ${s}">${s}</span>`}
async function start(){
  const out=$("#message");
  try{
    const {user}=await api("/me");
    $("#auth").classList.add("hidden"); $("#app").classList.remove("hidden");
    $("#welcome").textContent=`Welcome, ${user.name}`;
    $("#balance").textContent=money(user.wallet_balance);
    await loadDashboard();
    const socket=io(); socket.on("user:transaction-updated",loadDashboard); socket.on("user:wallet-updated",loadDashboard);
    socket.on("user:account-status",d=>{if(d.status==="blocked"){alert("Your account has been blocked.");location.reload();}});
  }catch{ $("#auth").classList.remove("hidden"); }
}
async function loadDashboard(){
  const d=await api("/dashboard"); $("#balance").textContent=money(d.user.wallet_balance);
  $("#donations").textContent=money(d.stats.donations_total); $("#donationCount").textContent=d.stats.donations_count;
  $("#history").innerHTML=d.transactions.map(t=>`<tr><td>#${t.id}</td><td>${t.type}</td><td>${money(t.amount)}</td><td>${status(t.status)}</td><td>${t.method||"-"}</td><td>${new Date(t.created_at).toLocaleString()}</td></tr>`).join("")||"<tr><td colspan='6'>No transactions yet.</td></tr>";
}
$("#register").addEventListener("submit",async e=>{e.preventDefault();try{const f=new FormData(e.target);await api("/auth/register",{method:"POST",body:JSON.stringify(Object.fromEntries(f))});location.reload();}catch(x){msg($("#message"),x.message,true);}});
$("#login").addEventListener("submit",async e=>{e.preventDefault();try{const f=new FormData(e.target);await api("/auth/login",{method:"POST",body:JSON.stringify(Object.fromEntries(f))});location.reload();}catch(x){msg($("#message"),x.message,true);}});
$("#logout").onclick=async()=>{await api("/auth/logout",{method:"POST"});location.reload();};
$("#withdraw").addEventListener("submit",async e=>{e.preventDefault();try{const f=new FormData(e.target);await api("/withdrawals",{method:"POST",body:JSON.stringify(Object.fromEntries(f))});msg($("#withdrawMessage"),"Withdrawal request submitted for review.");e.target.reset();await loadDashboard();}catch(x){msg($("#withdrawMessage"),x.message,true);}});
start();
