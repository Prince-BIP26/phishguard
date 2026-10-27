/* main.js — PhishGuard frontend logic */

// ── Helpers ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function classColor(c) {
  return c === "Legitimate" ? "var(--safe)" : c === "Suspicious" ? "var(--warning)" : "var(--danger)";
}
function classBarClass(score) {
  return score <= 20 ? "bar-safe" : score <= 50 ? "bar-warning" : "bar-danger";
}
function classIcon(c) {
  return c === "Legitimate" ? "✅" : c === "Suspicious" ? "⚠️" : "❌";
}
function classGlow(c) {
  return c === "Legitimate" ? "glow-green" : c === "Suspicious" ? "glow-amber" : "glow-red";
}

// ── Debounce live preview ─────────────────────────────────────────────────────
let debounceTimer = null;
$("mainInput").addEventListener("input", () => {
  clearTimeout(debounceTimer);
  const val = $("mainInput").value.trim();
  if (val.length < 3) {
    $("livePreview").style.display = "none";
    $("detectedType").style.display = "none";
    return;
  }
  debounceTimer = setTimeout(() => doLivePreview(val), 300);
});

$("mainInput").addEventListener("keydown", e => {
  if (e.key === "Enter") runAnalysis();
});

async function doLivePreview(val) {
  // Detect type label
  const dtRes = await fetch("/api/detect-type", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({input: val})
  });
  const dt = await dtRes.json();
  $("detectedLabel").textContent = dt.label;
  $("detectedType").style.display = "block";

  // Quick analysis
  const res = await fetch("/api/analyze", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({input: val})
  });
  const data = await res.json();
  renderLivePreview(data);
}

function renderLivePreview(data) {
  const color = classColor(data.classification);
  $("liveIcon").textContent = classIcon(data.classification);
  $("liveClass").textContent = data.classification;
  $("liveClass").style.color = color;
  $("liveTypeLabel").textContent = "— " + threatLabel(data.threatType);
  $("liveScore").textContent = data.riskScore + "%";
  $("liveScore").style.color = color;

  const bar = $("liveBar");
  bar.style.width = data.riskScore + "%";
  bar.className = "risk-bar " + classBarClass(data.riskScore);

  const triggered = data.rules.filter(r => r.triggered);
  $("liveTriggered").innerHTML = triggered.map(r =>
    `<span class="tag-danger">✕ ${r.name}</span>`
  ).join("");

  $("livePreview").style.display = "block";
}

// ── Main analysis ─────────────────────────────────────────────────────────────
async function runAnalysis() {
  const val = $("mainInput").value.trim();
  if (!val) return;

  $("results").style.display = "none";
  $("livePreview").style.display = "none";
  $("detectedType").style.display = "none";
  $("scanningAnim").style.display = "block";
  $("scanningText").textContent = "⟫ Analyzing input...";

  const res = await fetch("/api/analyze", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({input: val})
  });
  const data = await res.json();

  setTimeout(() => {
    $("scanningAnim").style.display = "none";
    renderResults(data);
  }, 900);
}

function renderResults(data) {
  const color = classColor(data.classification);
  const glow  = classGlow(data.classification);

  // Card glow
  const card = $("results");
  card.className = "card result-card " + glow;

  $("resultTypeBadge").textContent = threatLabel(data.threatType);
  $("resultIcon").textContent = classIcon(data.classification);

  $("resultClass").textContent = data.classification;
  $("resultClass").style.color = color;

  $("resultTime").textContent = "Scanned at " + data.timestamp;

  $("resultScore").textContent = data.riskScore + "%";
  $("resultScore").style.color = color;

  const bar = $("resultBar");
  bar.style.width = "0%";
  bar.className = "risk-bar " + classBarClass(data.riskScore);
  setTimeout(() => bar.style.width = data.riskScore + "%", 50);

  $("resultUrl").textContent = data.url;

  const triggered = data.rules.filter(r => r.triggered).length;
  $("rulesLabel").textContent = `Security Rules (${triggered}/${data.rules.length} triggered)`;

  $("rulesList").innerHTML = data.rules.map(rule => `
    <div class="rule-item ${rule.triggered ? "rule-triggered" : "rule-passed"}">
      <span class="rule-icon">${rule.triggered ? "❌" : "✅"}</span>
      <div>
        <div class="rule-name ${rule.triggered ? "color-danger" : "color-safe"}">
          ${rule.name}
          <span class="rule-weight">(weight: ${rule.weight})</span>
        </div>
        <div class="rule-desc">${rule.description}</div>
      </div>
    </div>
  `).join("");

  card.style.display = "block";
  card.scrollIntoView({behavior:"smooth", block:"nearest"});
}

// ── Bar chart ─────────────────────────────────────────────────────────────────
let barChartInstance = null;

async function toggleBarChart() {
  const sec = $("barChartSection");
  if (sec.style.display === "none") {
    sec.style.display = "block";
    $("barChartBtn").textContent = "📊 Hide Threat Stats";
    if (!barChartInstance) await renderBarChart();
  } else {
    sec.style.display = "none";
    $("barChartBtn").textContent = "📊 View Threat Stats (2022–2024)";
  }
}

async function renderBarChart() {
  const res = await fetch("/api/stats/bar");
  const data = await res.json();
  const ctx = $("barChart").getContext("2d");
  barChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: data.map(d => d.year),
      datasets: [
        {label:"URL Phishing",    data:data.map(d=>d.urlPhishing),    backgroundColor:"hsl(0,85%,55%)",   borderRadius:3},
        {label:"Email Phishing",  data:data.map(d=>d.emailPhishing),  backgroundColor:"hsl(30,90%,50%)",  borderRadius:3},
        {label:"Domain Spoofing", data:data.map(d=>d.domainSpoofing), backgroundColor:"hsl(45,85%,50%)",  borderRadius:3},
        {label:"Clone Website",   data:data.map(d=>d.cloneWebsite),   backgroundColor:"hsl(200,70%,45%)", borderRadius:3},
        {label:"SMS Phishing",    data:data.map(d=>d.smsPhishing),    backgroundColor:"hsl(260,60%,50%)", borderRadius:3},
      ]
    },
    options: {
      responsive:true,
      plugins:{legend:{labels:{color:"#8899a6",font:{family:"JetBrains Mono",size:11}}}},
      scales:{
        x:{ticks:{color:"#8899a6",font:{family:"JetBrains Mono",size:11}},grid:{color:"hsl(160,30%,18%)"}},
        y:{ticks:{color:"#8899a6",font:{family:"JetBrains Mono",size:11}},grid:{color:"hsl(160,30%,18%)"}},
      }
    }
  });
}

// ── Per-type analysis ─────────────────────────────────────────────────────────
async function analyzeByType(id, threatType) {
  const input = $(`typeInput-${id}`).value.trim();
  if (!input) return;

  const resultEl = $(`typeResult-${id}`);
  resultEl.style.display = "flex";
  resultEl.innerHTML = `<span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--primary);animation:pulseGlow 2s infinite">Scanning...</span>`;

  await new Promise(r => setTimeout(r, 700));

  const res = await fetch("/api/analyze", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({input, threatType})
  });
  const data = await res.json();
  const color = classColor(data.classification);

  resultEl.innerHTML = `
    <span>${classIcon(data.classification)}</span>
    <span style="font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;color:${color}">${data.classification}</span>
    <span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:${color}">(${data.riskScore}% risk)</span>
  `;
}

// ── Pie charts ────────────────────────────────────────────────────────────────
const pieInstances = {};

async function togglePie(id, threatType) {
  const sec   = $(`pie-section-${id}`);
  const label = $(`pie-label-${id}`);
  if (sec.style.display === "none") {
    sec.style.display = "block";
    label.textContent = "Hide Stats";
    if (!pieInstances[id]) await renderPie(id, threatType);
  } else {
    sec.style.display = "none";
    label.textContent = "View Stats";
  }
}

async function renderPie(id, threatType) {
  const res  = await fetch(`/api/stats/pie/${threatType}`);
  const data = await res.json();
  const ctx  = $(`pieChart-${id}`).getContext("2d");
  pieInstances[id] = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: data.map(d => d.name),
      datasets:[{
        data: data.map(d => d.value),
        backgroundColor: data.map(d => d.fill),
        borderColor: "hsl(220,18%,10%)",
        borderWidth: 2,
        hoverOffset: 6,
      }]
    },
    options: {
      responsive:true,
      plugins:{
        legend:{labels:{color:"#8899a6",font:{family:"JetBrains Mono",size:10}}},
        tooltip:{callbacks:{label: ctx => ` ${ctx.label}: ${ctx.parsed}%`}}
      }
    }
  });
}

// ── Threat label helper ───────────────────────────────────────────────────────
function threatLabel(type) {
  const map = {
    url:    "URL Phishing",
    email:  "Email Phishing",
    domain: "Domain Spoofing",
    clone:  "Clone Website Phishing",
    sms:    "SMS Phishing",
  };
  return map[type] || type;
}
