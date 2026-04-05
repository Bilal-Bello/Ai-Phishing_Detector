/* ═══════════════════════════════════════════
   PhishGuard — app.js
   Handles API calls, chart rendering, UI updates
═══════════════════════════════════════════ */

const API_URL = "http://127.0.0.1:5000/predict";

// ── Chart instances (kept for destroy/redraw) ──
let gaugeChartInst  = null;
let entropyChartInst = null;
let radarChartInst  = null;

// ── Chart.js global defaults ──
Chart.defaults.color = "#5a7490";
Chart.defaults.font.family = "'Space Mono', monospace";

// ═══════════════════════════════════════════
// ENTRY POINTS
// ═══════════════════════════════════════════

document.getElementById("scanBtn").addEventListener("click", runScan);
document.getElementById("urlInput").addEventListener("keydown", e => {
  if (e.key === "Enter") runScan();
});

function fillExample(url) {
  const input = document.getElementById("urlInput");
  // Strip leading https:// since input-prefix shows it
  input.value = url.replace(/^https?:\/\//, "");
  input.focus();
}

// ═══════════════════════════════════════════
// MAIN SCAN FUNCTION
// ═══════════════════════════════════════════

async function runScan() {
  const rawVal = document.getElementById("urlInput").value.trim();
  if (!rawVal) { shakeInput(); return; }

  // Reconstruct full URL
  const url = rawVal.startsWith("http") ? rawVal : "https://" + rawVal;

  setLoading(true);
  hideResults();

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!res.ok) throw new Error(`Server error: ${res.status}`);

    const data = await res.json();
    renderResults(data);
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

// ═══════════════════════════════════════════
// RENDER ALL RESULTS
// ═══════════════════════════════════════════

function renderResults(data) {
  const { prediction, risk_score, alerts, details } = data;
  const isPhishing = prediction === "Phishing";

  document.getElementById("results").style.display = "block";

  // Staggered card animations
  document.querySelectorAll(".card").forEach((c, i) => {
    c.style.animationDelay = `${i * 0.07}s`;
  });

  renderVerdict(prediction, data.url, risk_score, isPhishing);
  renderGauge(risk_score, isPhishing);
  renderStats(details, alerts.length);
  renderEntropy(details.domain_entropy, details.domain);
  renderAlerts(alerts);
  renderRadar(details, alerts);
  renderBrands(details.similar_brands || []);
  renderDetails(details);
}

// ═══════════════════════════════════════════
// VERDICT
// ═══════════════════════════════════════════

function renderVerdict(prediction, url, riskScore, isPhishing) {
  const card    = document.getElementById("verdictCard");
  const icon    = document.getElementById("verdictIcon");
  const text    = document.getElementById("verdictText");
  const urlEl   = document.getElementById("verdictUrl");
  const badge   = document.getElementById("verdictBadge");

  card.classList.remove("verdict-phishing", "verdict-legitimate");
  card.classList.add(isPhishing ? "verdict-phishing" : "verdict-legitimate");

  icon.textContent  = isPhishing ? "⚠" : "✓";
  text.textContent  = prediction.toUpperCase();
  urlEl.textContent = truncate(url, 38);
  badge.textContent = isPhishing ? "THREAT DETECTED" : "SAFE";
}

// ═══════════════════════════════════════════
// GAUGE CHART (donut arc)
// ═══════════════════════════════════════════

function renderGauge(score, isPhishing) {
  const gaugeVal = document.getElementById("gaugeValue");
  const color    = scoreColor(score);

  animateNumber(gaugeVal, 0, score, 800);
  gaugeVal.style.color = color;

  if (gaugeChartInst) gaugeChartInst.destroy();

  const ctx = document.getElementById("gaugeChart").getContext("2d");
  gaugeChartInst = new Chart(ctx, {
    type: "doughnut",
    data: {
      datasets: [{
        data: [score, 100 - score],
        backgroundColor: [color, "rgba(255,255,255,0.05)"],
        borderWidth: 0,
        borderRadius: 4,
        hoverOffset: 0,
      }]
    },
    options: {
      rotation: -90,
      circumference: 180,
      cutout: "72%",
      animation: { duration: 900, easing: "easeInOutQuart" },
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      events: []
    }
  });
}

// ═══════════════════════════════════════════
// QUICK STATS
// ═══════════════════════════════════════════

function renderStats(details, alertCount) {
  const s = (id, val, cls) => {
    const el = document.getElementById(id);
    el.textContent = val;
    el.className = `stat-val ${cls || ""}`;
  };

  s("statHttps",     details.uses_https ? "YES" : "NO",
    details.uses_https ? "val-good" : "val-bad");
  s("statDomain",    details.domain || "—", "val-neutral");
  s("statAlerts",    alertCount,
    alertCount === 0 ? "val-good" : alertCount < 3 ? "val-warn" : "val-bad");
  s("statLength",    details.url_length, "val-neutral");
  s("statSubdomains",details.subdomain_count, details.subdomain_count > 2 ? "val-bad" : "val-neutral");
  s("statIp",        details.has_ip_address ? "YES" : "NO",
    details.has_ip_address ? "val-bad" : "val-good");
}

// ═══════════════════════════════════════════
// ENTROPY SECTION (bar + sparkline)
// ═══════════════════════════════════════════

function renderEntropy(entropy, domain) {
  document.getElementById("entropyValue").textContent = entropy ?? "—";

  // Animated progress bar (0–6 scale)
  const pct = Math.min(100, ((entropy || 0) / 6) * 100);
  document.getElementById("entropyFill").style.width = pct + "%";

  // Verdict label
  const vEl = document.getElementById("entropyVerdict");
  if (entropy < 2.5) {
    vEl.textContent = "LOW — Regular domain";
    vEl.style.cssText = "background:rgba(0,224,150,0.15);color:#00e096;border:1px solid #00e096;";
  } else if (entropy < 3.5) {
    vEl.textContent = "MODERATE — Acceptable";
    vEl.style.cssText = "background:rgba(255,170,0,0.15);color:#ffaa00;border:1px solid #ffaa00;";
  } else {
    vEl.textContent = "HIGH — Suspicious randomness";
    vEl.style.cssText = "background:rgba(255,59,92,0.15);color:#ff3b5c;border:1px solid #ff3b5c;";
  }

  // Per-character entropy sparkline
  if (entropyChartInst) entropyChartInst.destroy();
  if (!domain) return;

  const chars  = domain.split("");
  const counts = {};
  chars.forEach(c => counts[c] = (counts[c] || 0) + 1);
  const total  = chars.length;
  const charEntropies = chars.map(c => {
    const p = counts[c] / total;
    return +(- p * Math.log2(p)).toFixed(3);
  });

  const ctx = document.getElementById("entropyChart").getContext("2d");
  entropyChartInst = new Chart(ctx, {
    type: "bar",
    data: {
      labels: chars,
      datasets: [{
        label: "Char entropy",
        data: charEntropies,
        backgroundColor: charEntropies.map(v =>
          v < 0.5 ? "rgba(0,224,150,0.7)"
          : v < 1  ? "rgba(255,170,0,0.7)"
                   : "rgba(255,59,92,0.7)"
        ),
        borderRadius: 3,
        borderWidth: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 700 },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: items => `Character: "${items[0].label}"`,
            label: item  => `Entropy: ${item.raw}`
          }
        }
      },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: {
          grid: { color: "rgba(0,229,255,0.05)" },
          ticks: { font: { size: 10 } },
          title: { display: true, text: "entropy", font: { size: 10 } }
        }
      }
    }
  });
}

// ═══════════════════════════════════════════
// ALERTS LIST
// ═══════════════════════════════════════════

function renderAlerts(alerts) {
  const list  = document.getElementById("alertsList");
  const badge = document.getElementById("alertCountBadge");
  badge.textContent = alerts.length;

  if (!alerts.length) {
    list.innerHTML = '<div class="no-alerts">✓ No threat alerts triggered</div>';
    return;
  }

  const iconMap = {
    "typosquat": "🔁",
    "homograph":  "🔤",
    "subdomain":  "🌐",
    "entropy":    "📊",
    "keyword":    "🔑",
    "ip":         "📡",
    "https":      "🔓",
    "default":    "⚠️"
  };

  list.innerHTML = alerts.map((alert, i) => {
    const lower  = alert.toLowerCase();
    let   icon   = iconMap.default;
    let   critical = "";
    if (lower.includes("typosquat"))  { icon = iconMap.typosquat; }
    if (lower.includes("homograph"))  { icon = iconMap.homograph; critical = "critical"; }
    if (lower.includes("subdomain"))  { icon = iconMap.subdomain; }
    if (lower.includes("entropy"))    { icon = iconMap.entropy; }
    if (lower.includes("keyword"))    { icon = iconMap.keyword; }
    if (lower.includes("ip address")) { icon = iconMap.ip; critical = "critical"; }
    if (lower.includes("https"))      { icon = iconMap.https; }

    return `
      <div class="alert-item ${critical}" style="animation-delay:${i*0.08}s">
        <span class="alert-icon">${icon}</span>
        <span class="alert-text">${alert}</span>
      </div>`;
  }).join("");
}

// ═══════════════════════════════════════════
// RADAR CHART (threat vectors)
// ═══════════════════════════════════════════

function renderRadar(details, alerts) {
  // Build 6 axis scores 0–10
  const httpsScore    = details.uses_https ? 0 : 8;
  const ipScore       = details.has_ip_address ? 10 : 0;
  const subdomScore   = Math.min(10, details.subdomain_count * 3);
  const entropyScore  = Math.min(10, ((details.domain_entropy || 0) / 6) * 10);
  const keywordScore  = details.has_suspicious_keywords ? 7 : 0;
  const typosqScore   = (details.similar_brands && details.similar_brands.length > 0)
                        ? Math.min(10, details.similar_brands[0].similarity / 10)
                        : (details.is_typosquat ? 7 : 0);

  if (radarChartInst) radarChartInst.destroy();

  const ctx = document.getElementById("radarChart").getContext("2d");
  radarChartInst = new Chart(ctx, {
    type: "radar",
    data: {
      labels: ["No HTTPS", "IP in URL", "Subdomains", "Entropy", "Keywords", "Typosquat"],
      datasets: [{
        label: "Threat Score",
        data: [httpsScore, ipScore, subdomScore, entropyScore, keywordScore, typosqScore],
        backgroundColor: "rgba(255,59,92,0.15)",
        borderColor:     "#ff3b5c",
        borderWidth:     2,
        pointBackgroundColor: "#ff3b5c",
        pointBorderColor:    "#ff3b5c",
        pointRadius:          4,
        pointHoverRadius:     6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      animation: { duration: 900, easing: "easeInOutQuart" },
      plugins: { legend: { display: false } },
      scales: {
        r: {
          min: 0, max: 10,
          ticks: {
            stepSize: 2,
            font: { size: 9 },
            backdropColor: "transparent",
          },
          grid:        { color: "rgba(0,229,255,0.1)" },
          angleLines:  { color: "rgba(0,229,255,0.1)" },
          pointLabels: { font: { size: 11, family: "'Space Mono'" }, color: "#8fa9bf" }
        }
      }
    }
  });
}

// ═══════════════════════════════════════════
// BRAND SIMILARITY TABLE
// ═══════════════════════════════════════════

function renderBrands(brands) {
  const el = document.getElementById("brandsContent");
  if (!brands || brands.length === 0) {
    el.innerHTML = '<div class="no-alerts">No brand matches detected</div>';
    return;
  }

  const rows = brands.map(b => `
    <tr>
      <td class="brand-name">${b.brand}</td>
      <td class="brand-bar-wrap">
        <div class="brand-bar">
          <div class="brand-bar-fill" style="width:${b.similarity}%"></div>
        </div>
      </td>
      <td class="brand-score" style="color:${b.similarity >= 90 ? "var(--red)" : b.similarity >= 80 ? "var(--amber)" : "var(--cyan)"}">
        ${b.similarity}%
      </td>
    </tr>`).join("");

  el.innerHTML = `
    <table class="brands-table">
      <thead>
        <tr>
          <th>BRAND</th>
          <th>SIMILARITY</th>
          <th>SCORE</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ═══════════════════════════════════════════
// DETAILS PANEL
// ═══════════════════════════════════════════

function renderDetails(details) {
  const rows = [
    { key: "Full Domain",   val: details.full_domain,      cls: "val-neutral" },
    { key: "HTTPS",         val: details.uses_https ? "Yes" : "No",
      cls: details.uses_https ? "val-good" : "val-bad" },
    { key: "IP Address",    val: details.has_ip_address ? "Detected" : "None",
      cls: details.has_ip_address ? "val-bad" : "val-good" },
    { key: "Subdomains",    val: details.subdomain_count,
      cls: details.subdomain_count > 2 ? "val-bad" : "val-neutral" },
    { key: "URL Length",    val: `${details.url_length} chars`,
      cls: details.url_length > 75 ? "val-warn" : "val-neutral" },
    { key: "Entropy",       val: details.domain_entropy,
      cls: details.domain_entropy > 3.5 ? "val-bad" : "val-neutral" },
    { key: "Keywords",      val: details.has_suspicious_keywords ? "Found" : "None",
      cls: details.has_suspicious_keywords ? "val-warn" : "val-good" },
    { key: "Typosquat",     val: details.is_typosquat ? "Yes" : "No",
      cls: details.is_typosquat ? "val-bad" : "val-good" },
    { key: "Homograph",     val: details.is_homograph ? "Detected" : "None",
      cls: details.is_homograph ? "val-bad" : "val-good" },
  ];

  document.getElementById("detailsList").innerHTML = rows.map(r => `
    <div class="detail-row">
      <span class="detail-key">${r.key}</span>
      <span class="detail-val ${r.cls}">${r.val}</span>
    </div>`).join("");
}

// ═══════════════════════════════════════════
// UI HELPERS
// ═══════════════════════════════════════════

function setLoading(on) {
  const btn    = document.getElementById("scanBtn");
  const loader = document.getElementById("loader");
  btn.classList.toggle("loading", on);
  btn.querySelector(".btn-text").textContent = on ? "SCANNING" : "SCAN";
  loader.style.display = on ? "block" : "none";
}

function hideResults() {
  document.getElementById("results").style.display = "none";
}

function showError(msg) {
  const results = document.getElementById("results");
  results.style.display = "block";
  results.innerHTML = `
    <div class="card" style="text-align:center;padding:40px;border-color:var(--red);">
      <div style="font-size:36px;margin-bottom:16px;">⚠</div>
      <div style="font-family:var(--font-mono);color:var(--red);letter-spacing:2px;margin-bottom:8px;">CONNECTION ERROR</div>
      <div style="color:var(--text-muted);font-size:13px;">${msg}</div>
      <div style="margin-top:16px;font-size:12px;color:var(--text-muted);">Make sure the Flask backend is running on port 5000</div>
    </div>`;
}

function shakeInput() {
  const wrapper = document.querySelector(".input-wrapper");
  wrapper.style.animation = "none";
  wrapper.offsetHeight; // reflow
  wrapper.style.animation = "shake 0.4s ease";
  wrapper.style.borderColor = "var(--red)";
  setTimeout(() => { wrapper.style.borderColor = ""; wrapper.style.animation = ""; }, 600);
}

function animateNumber(el, from, to, duration) {
  const start = performance.now();
  const update = now => {
    const t = Math.min((now - start) / duration, 1);
    el.textContent = Math.round(from + (to - from) * easeOut(t));
    if (t < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

function scoreColor(score) {
  if (score < 33)  return "#00e096";
  if (score < 66)  return "#ffaa00";
  return "#ff3b5c";
}

function truncate(str, max) {
  return str && str.length > max ? str.slice(0, max) + "…" : str;
}

// ── Add shake keyframe dynamically ──
const style = document.createElement("style");
style.textContent = `
  @keyframes shake {
    0%,100% { transform: translateX(0); }
    20%      { transform: translateX(-6px); }
    40%      { transform: translateX(6px); }
    60%      { transform: translateX(-4px); }
    80%      { transform: translateX(4px); }
  }`;
document.head.appendChild(style);
