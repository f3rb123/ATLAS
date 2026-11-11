"use strict";
let nonce = "", busy = false;
const element = id => document.getElementById(id);
function text(id, value) { element(id).textContent = String(value); }
function node(tag, value, className) { const result = document.createElement(tag); if (value !== undefined) result.textContent = String(value); if (className) result.className = className; return result; }
function item(title, subtitle, label, state) { const row = node("div", undefined, "item"); const body = node("div"); body.append(node("p", title)); if (subtitle) body.append(node("small", subtitle)); row.append(body, node("span", label, "badge " + (state || ""))); return row; }
function render(state) {
  nonce = state.control_nonce;
  text("scope", state.scope); text("phase", state.phase);
  text("mode", (state.deep ? "Deep recon + non-destructive validation" : "Reconnaissance") + " · " + state.agents + " concurrent slots");
  text("agent-count", state.agents + " slots");
  text("elapsed", String(Math.floor(state.elapsed / 60)).padStart(2, "0") + ":" + String(state.elapsed % 60).padStart(2, "0"));
  text("coverage", state.targets ? state.targets + " hosts discovered · " + state.remaining + " queued" : "Preparing scope");
  const confirmed = state.findings.filter(f => f.verification === "confirmed");
  text("confirmed", confirmed.length); text("candidates", state.candidates.length); text("responses", state.observations);
  text("finding-count", state.findings.length + " findings / " + state.candidates.length + " candidates");
  const findings = element("findings"); findings.replaceChildren();
  for (const finding of state.findings) findings.append(item(finding.title, finding.severity, finding.verification, finding.verification === "confirmed" ? "" : "candidate"));
  for (const candidate of state.candidates.slice(-30)) findings.append(item(candidate.claim, "Hypothesis · requires independent proof/control", candidate.status, "candidate"));
  if (!findings.children.length) findings.append(node("p", "No evidence-backed findings yet. Activity and coverage are shown below.", "empty"));
  const agents = element("agents"); agents.replaceChildren();
  for (const task of state.tasks) agents.append(item(task.role, task.id.slice(0, 8) + " · attempt " + task.attempts + (task.diagnostic ? " · " + task.diagnostic : ""), task.status, task.status === "dead_letter" ? "error" : task.status === "queued" ? "candidate" : ""));
  if (!agents.children.length) agents.append(node("p", "Preparing specialist responsibilities.", "empty"));
  const feed = element("events"); const atEnd = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 40; feed.replaceChildren();
  for (const event of state.events) { const row = node("div", undefined, "event"); row.append(node("time", event.time.slice(11, 19)), node("span", event.actor, "actor"), node("span", event.type + " · " + event.text, "detail")); feed.append(row); }
  if (atEnd) feed.scrollTop = feed.scrollHeight;
  text("connection", "LIVE · " + new Date().toLocaleTimeString());
  element("pause").disabled = busy || state.finished || state.phase === "paused";
  element("resume").disabled = busy || state.finished || state.phase !== "paused";
  element("cancel").disabled = busy || state.finished;
  if (state.error) text("notice", state.error);
  else if (state.finished) text("notice", "Assessment " + state.phase + ". Reports and incomplete coverage remain recorded locally.");
}
async function refresh() { try { const response = await fetch("/api/state", {cache: "no-store"}); if (!response.ok) throw new Error("Controller unavailable"); render(await response.json()); } catch (_) { text("connection", "RECONNECTING"); } }
for (const button of document.querySelectorAll("[data-action]")) button.addEventListener("click", async () => { if (busy) return; busy = true; try { const response = await fetch("/api/control", {method: "POST", headers: {"Content-Type": "application/json", "X-SKUNK-Control": nonce}, body: JSON.stringify({action: button.dataset.action})}); const result = await response.json(); if (!response.ok) throw new Error(result.error || "Control failed"); text("notice", "Control saved. In-flight requests may finish; new dispatches follow the selected state."); } catch (error) { text("notice", error.message); } finally { busy = false; refresh(); } });
refresh(); setInterval(refresh, 1200);
