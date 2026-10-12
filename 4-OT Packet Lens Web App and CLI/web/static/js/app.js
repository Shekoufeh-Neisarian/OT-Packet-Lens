function escapeCaptureText(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

/**
 * Single Page Application (SPA) Controller for ICS/OT Network Traffic Analyzer.
 */

let currentReport = null;
let currentJobId = null;
let pollInterval = null;
let networkTopology = null;
let chartProtoDoughnutInstance = null;
let chartProtoBarInstance = null;
let chartRolePieInstance = null;
let chartTopTalkersInstance = null;

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  loadSampleList();
  setupEventListeners();
  setupDropzone();
  setupProductTour();
});

function initTheme() {
  let saved = "dark";
  try { saved = localStorage.getItem("ics_theme") || "dark"; } catch (_) {}
  document.documentElement.setAttribute("data-theme", saved);
  const btn = document.getElementById("themeToggle");
  if (btn) btn.textContent = saved === "light" ? "🌙" : "☀️";
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("ics_theme", next); } catch (_) {}
  const btn = document.getElementById("themeToggle");
  if (btn) btn.textContent = next === "light" ? "🌙" : "☀️";
  if (currentReport) renderCharts(currentReport);
}

function setupEventListeners() {
  document.addEventListener('click', (event) => {
    const b = event.target.closest('[data-target-tab]');
    if (b) document.querySelector(`[data-tab="${b.dataset.targetTab}"]`)?.click();
  });
  document.getElementById("themeToggle")?.addEventListener("click", toggleTheme);
  
  // Tab Navigation
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const tabId = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      
      btn.classList.add("active");
      document.getElementById(tabId)?.classList.add("active");

      if (tabId === "tabTopology" && networkTopology) {
        networkTopology.initCanvasSize();
      }
    });
  });

  // Sample Selector Dropdown
  document.getElementById("sampleSelect")?.addEventListener("change", (e) => {
    const path = e.target.value;
    if (path) analyzePath(path);
  });

  // Device Search & Role Filter
  document.getElementById("deviceSearch")?.addEventListener("input", filterDeviceTable);
  document.getElementById("roleFilter")?.addEventListener("change", filterDeviceTable);
  document.getElementById("flowSearch")?.addEventListener("input", filterFlowTable);

  // Modal Close
  document.getElementById("modalClose")?.addEventListener("click", closeModal);
  document.getElementById("assetModal")?.addEventListener("click", (e) => {
    if (e.target.id === "assetModal") closeModal();
  });
}

/* A short, self-contained guide. No capture is loaded or processed by the tour. */
function setupProductTour() {
  const overlay = document.getElementById("tourOverlay");
  const dialog = document.getElementById("tourDialog");
  if (!overlay || !dialog) return;
  const steps = [
    { glyph: "⇪", kicker: "01 / Input", title: "Load a capture",
      text: "Choose a bundled sample from the top-right menu, or drag a .pcap / .pcapng file into the upload area.",
      tip: "Nothing is analyzed automatically when you open the website." },
    { glyph: "◫", kicker: "02 / Overview", title: "Understand the capture",
      text: "Start with the packet count, capture time, discovered endpoints, and protocol charts. Explore Device Inventory for IPs, ports and role evidence.",
      tip: "Counts describe captured traffic. Device roles are estimates, not authenticated identities." },
    { glyph: "⌁", kicker: "03 / Investigation", title: "Follow the communication",
      text: "Open Protocol Insights, Topology & Comms, and Capture Investigation to inspect operations, flows and alerts.",
      tip: "An alert is a lead for investigation; confirm important findings with packet evidence." },
    { glyph: "⇩", kicker: "04 / Results", title: "Export your findings",
      text: "Open Export Center to download a standalone HTML or Markdown report, JSON data, or CSV tables for assets and flows.",
      tip: "Exports describe the currently analyzed PCAP. Existing Mystery reports do not need to regenerate at startup." }
  ];
  let index = 0;
  let previousFocus = null;
  const get = id => document.getElementById(id);
  const track = get("tourStepTrack");
  steps.forEach(() => { const dot = document.createElement("span"); track.appendChild(dot); });
  function render() {
    const step = steps[index];
    get("tourGlyph").textContent = step.glyph;
    get("tourStepTag").textContent = `STEP ${String(index+1).padStart(2,"0")} / 04`;
    get("tourKicker").textContent = step.kicker;
    get("tourTitle").textContent = step.title;
    get("tourDescription").textContent = step.text;
    get("tourTip").textContent = step.tip;
    get("tourCount").textContent = `${index+1} of ${steps.length}`;
    get("tourPrev").disabled = index === 0;
    get("tourNext").textContent = index === steps.length - 1 ? "Finish tour ✓" : "Next step →";
    Array.from(track.children).forEach((el,i) => el.classList.toggle("is-done",i<=index));
  }
  function open() {
    previousFocus = document.activeElement;
    index = 0;
    render();
    overlay.hidden = false;
    document.body.style.overflow = "hidden";
    get("tourClose").focus();
  }
  function close() {
    overlay.hidden = true;
    document.body.style.overflow = "";
    if (previousFocus && typeof previousFocus.focus === "function") previousFocus.focus();
  }
  ["tourOpen", "tourWelcomeOpen"].forEach(id => get(id)?.addEventListener("click",open));
  get("tourChooseSample")?.addEventListener("click", () => {
    const selector = get("sampleSelect");
    selector?.focus();
    selector?.scrollIntoView({behavior:"smooth",block:"nearest"});
  });
  get("tourClose")?.addEventListener("click",close);
  overlay.addEventListener("click", e => { if (e.target === overlay) close(); });
  get("tourPrev")?.addEventListener("click", () => { if (index > 0) { index--; render(); } });
  get("tourNext")?.addEventListener("click", () => { if (index >= steps.length-1) close(); else { index++; render(); } });
  document.addEventListener("keydown",e => {
    if (overlay.hidden) return;
    if (e.key === "Escape") {e.preventDefault();close();}
    if (e.key === "Tab") {
      const focusable = [get("tourClose"),get("tourPrev"),get("tourNext")].filter(b=>b && !b.disabled);
      const first = focusable[0], last = focusable[focusable.length-1];
      if (e.shiftKey && document.activeElement === first) {e.preventDefault();last.focus();}
      else if (!e.shiftKey && document.activeElement === last) {e.preventDefault();first.focus();}
    }
  });
}

function setupDropzone() {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");

  if (!dropzone || !fileInput) return;

  // Prevent the browser from navigating to a dropped capture.
  ["dragover", "drop"].forEach(type => document.addEventListener(type, e => {
    if (Array.from(e.dataTransfer?.types || []).includes("Files")) e.preventDefault();
  }));
  dropzone.addEventListener("click", e => {
    if (e.target !== fileInput) fileInput.click();
  });
  dropzone.addEventListener("keydown", e => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });
  let dragDepth = 0;
  dropzone.addEventListener("dragenter", e => {
    e.preventDefault(); dragDepth++; dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragover", e => {
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
  });
  dropzone.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) dropzone.classList.remove("dragover");
  });
  dropzone.addEventListener("drop", e => {
    e.preventDefault(); e.stopPropagation();
    dragDepth = 0; dropzone.classList.remove("dragover");
    const files = e.dataTransfer?.files;
    if (files?.length === 1) uploadFile(files[0]);
    else alert("Drop one PCAP or PCAPNG file at a time.");
  });
  fileInput.addEventListener("change", e => {
    const file = e.target.files?.[0];
    if (file) uploadFile(file);
    fileInput.value = "";
  });
}

async function loadSampleList() {
  try {
    const res = await fetch("/api/samples");
    const data = await res.json();
    const select = document.getElementById("sampleSelect");
    if (!select) return;

    select.innerHTML = '<option value="">-- Quick Load Sample Capture --</option>';
    
    // Group by category
    const groups = {};
    data.samples.forEach(s => {
      if (!groups[s.category]) groups[s.category] = [];
      groups[s.category].push(s);
    });

    for (const [cat, items] of Object.entries(groups)) {
      const optgroup = document.createElement("optgroup");
      optgroup.label = cat;
      items.forEach(item => {
        const opt = document.createElement("option");
        opt.value = item.path;
        opt.textContent = `${item.name} (${item.size_mb} MB)`;
        optgroup.appendChild(opt);
      });
      select.appendChild(optgroup);
    }
  } catch (err) {
    console.error("Failed to load sample PCAP list:", err);
  }
}

async function uploadFile(file) {
  if (!/\.(pcap|pcapng|cap)$/i.test(file.name) || !file.size) {
    alert("Choose a non-empty .pcap, .pcapng or .cap file."); return;
  }
  showProgress(`Uploading '${file.name}'...`);
  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/api/upload", { method: "POST", body: formData });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || err.detail || "Upload failed");
    }
    const data = await res.json();
    currentJobId = data.job_id;
    startPolling(currentJobId);
  } catch (err) {
    alert("Upload failed: " + err.message);
    hideProgress();
  }
}

async function analyzePath(filePath) {
  showProgress(`Initializing analysis for ${filePath}...`);
  try {
    const res = await fetch("/api/analyze-path", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: filePath })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || err.detail || "Analysis request failed");
    }
    const data = await res.json();
    currentJobId = data.job_id;
    startPolling(currentJobId);
  } catch (err) {
    alert("Analysis failed: " + err.message);
    hideProgress();
  }
}

function startPolling(jobId) {
  if (pollInterval) clearInterval(pollInterval);
  
  pollInterval = setInterval(async () => {
    try {
      const res = await fetch(`/api/status/${jobId}`);
      if (!res.ok) return;
      const status = await res.json();

      updateProgress(status);

      if (status.status === "completed") {
        clearInterval(pollInterval);
        loadFullReport(jobId);
      } else if (status.status === "failed") {
        clearInterval(pollInterval);
        alert(`Analysis failed: ${status.error || status.message}`);
        hideProgress();
      }
    } catch (e) {
      console.error("Polling error:", e);
    }
  }, 1000);
}

function showProgress(msg) {
  const box = document.getElementById("progressBox");
  const msgEl = document.getElementById("progressMsg");
  const fill = document.getElementById("progressFill");
  if (box) box.style.display = "block";
  if (msgEl) msgEl.textContent = msg;
  if (fill) fill.style.width = "10%";
}

function updateProgress(status) {
  const msgEl = document.getElementById("progressMsg");
  const fill = document.getElementById("progressFill");
  const countEl = document.getElementById("progressCount");

  if (msgEl) msgEl.textContent = status.message || "Processing packets...";
  if (countEl && status.progress_packets) {
    countEl.textContent = `${status.progress_packets.toLocaleString()} packets processed`;
    if (fill) fill.style.width = "65%";
  }
}

function hideProgress() {
  const box = document.getElementById("progressBox");
  if (box) box.style.display = "none";
}

async function loadFullReport(jobId) {
  try {
    const res = await fetch(`/api/report/${jobId}`);
    if (!res.ok) throw new Error("Could not retrieve report");
    const data = await res.json();
    currentReport = data;
    hideProgress();
    renderReport(data);
  } catch (err) {
    alert("Error fetching report: " + err.message);
    hideProgress();
  }
}

function renderReport(report) {
  document.getElementById("reportDashboard").style.display = "block";
  document.body.classList.add("has-report");
  
  renderInvestigation(report);
  document.getElementById("captureStart").textContent = report.summary.start_time;
  document.getElementById("captureEnd").textContent = report.summary.end_time;
  // Render KPI Metrics
  const sum = report.summary;
  document.getElementById("kpiFilename").textContent = sum.filename;
  document.getElementById("kpiPackets").textContent = sum.packet_count.toLocaleString();
  document.getElementById("kpiVolume").textContent = `${sum.total_transferred_mb} MiB`;
  document.getElementById("kpiDevices").textContent = sum.device_count;
  document.getElementById("kpiOtAssets").textContent = sum.ot_asset_count;
  document.getElementById("kpiDuration").textContent = sum.duration_human;
  document.getElementById("kpiThroughput").textContent = `Capture avg ${Number(sum.capture_average_pkts_sec || 0).toLocaleString()} pkt/s · Analysis ${Number(sum.processing_rate_pkts_sec || 0).toLocaleString()} pkt/s`;

  // Distinguish TShark-dissected facts from per-segment heuristics.
  const quality = report.analysis_quality || {};
  const qEl = document.getElementById("dissectionQualityMessage");
  const refPanel = document.getElementById("wiresharkFilterCounts");
  const refCountEl = document.getElementById("wiresharkCountsTable");
  if (qEl) {
    qEl.textContent = `${quality.mode === "wireshark_dissected" ? "Wireshark/TShark-derived" : "Estimated / no Wireshark dissection"}. ${quality.message || ""}`;
    qEl.style.color = quality.mode === "wireshark_dissected" ? "var(--teal, #39aa99)" : "var(--amber, #d8a349)";
  }
  const wsRef = report.wireshark_reference;
  if (refPanel) refPanel.style.display = wsRef ? "block" : "none";
  if (refCountEl) {
    refCountEl.replaceChildren();
    if (wsRef) {
      const version = document.createElement("p");
      version.textContent = `Source: ${wsRef.version || "TShark"}. Exactly ${wsRef.packet_count.toLocaleString()} frames processed.`;
      version.style.width = "100%";
      refCountEl.appendChild(version);
      for (const [key, n] of Object.entries(wsRef.display_filter_packet_counts || {})) {
        const chip = document.createElement("span");
        chip.style.cssText = "padding:5px 10px;border:1px solid var(--border-color,#7775);border-radius:9px;font-size:13px";
        chip.textContent = `${key}: ${Number(n).toLocaleString()} frames`;
        refCountEl.appendChild(chip);
      }
    }
  }

  // Compact review indicator; detailed evidence lives in the Investigation tab.
  const anomBox = document.getElementById("anomaliesBox");
  const findings = report.anomalies || [];
  if (findings.length) {
    anomBox.style.display = "block";
    anomBox.replaceChildren();
    const ribbon=document.createElement('div');ribbon.className='findings-ribbon';
    const heading=document.createElement('strong');heading.textContent=`${findings.length} item(s) for investigation`;
    const expl=document.createElement('span');expl.textContent='Heuristic signals — not confirmed attacks';
    const open=document.createElement('button');open.type='button';open.textContent='Review evidence →';
    open.setAttribute('data-target-tab','tabMystery');
    ribbon.append(heading,expl,open);anomBox.appendChild(ribbon);
  } else {anomBox.style.display='none';anomBox.replaceChildren();}

  // Render Visual Analytics Charts
  renderCharts(report);
  renderAssetActivity(report.devices);

  // Render Detected Protocols
  renderProtocols(report.detected_protocols, sum.packet_count);

  // Render FIRST decoded outermost transport per frame (not an overlapping display filter)
  renderTransportChips(report.transport_summary, sum.packet_count);

  // Render Device Inventory Table
  renderDeviceTable(report.devices);

  // Render Protocol-Specific Insights (Bonus)
  renderProtocolInsights(report.protocol_insights);

  // Render Communications Table
  renderFlowTable(report.conversations);

  // Render Topology Graph
  if (!networkTopology) {
    networkTopology = new NetworkTopology("topologyCanvas", (ip) => openAssetModal(ip));
  }
  networkTopology.setData(report.topology_graph);

  // Setup Export Links
  setupExportLinks(currentJobId);
}

function renderCharts(report) {
  if (typeof Chart === "undefined") {
    console.warn("Chart.js not loaded, skipping charts");
    return;
  }

  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  const textColor = isLight ? "#475569" : "#94a3b8";
  const gridColor = isLight ? "rgba(0, 0, 0, 0.06)" : "rgba(255, 255, 255, 0.06)";

  Chart.defaults.color = textColor;
  Chart.defaults.font.family = "'Inter', sans-serif";

  const cyberColors = [
    "#06b6d4", // Cyan
    "#3b82f6", // Blue
    "#10b981", // Emerald
    "#f59e0b", // Amber
    "#8b5cf6", // Purple
    "#f43f5e", // Rose
    "#14b8a6", // Teal
    "#ec4899", // Pink
    "#eab308", // Yellow
    "#64748b"  // Slate
  ];

  // 1. Protocol Distribution Doughnut
  const protoCanvas = document.getElementById("chartProtoDoughnut");
  if (protoCanvas) {
    if (chartProtoDoughnutInstance) chartProtoDoughnutInstance.destroy();
    const protoEntries = Object.entries(report.detected_protocols || {});
    const protoLabels = protoEntries.map(([k]) => k);
    const protoData = protoEntries.map(([, v]) => v);

    chartProtoDoughnutInstance = new Chart(protoCanvas, {
      type: "doughnut",
      data: {
        labels: protoLabels,
        datasets: [{
          data: protoData,
          backgroundColor: cyberColors.slice(0, protoLabels.length),
          borderColor: isLight ? "#ffffff" : "#101830",
          borderWidth: 2,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "right",
            labels: { boxWidth: 12, font: { size: 11 } }
          },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                const val = ctx.parsed;
                const pct = ((val / Math.max(1, total)) * 100).toFixed(1);
                return ` ${ctx.label}: ${val.toLocaleString()} pkts (${pct}%)`;
              }
            }
          }
        },
        cutout: "65%"
      }
    });
  }

  // 2. Top Protocols Bar Chart
  const protoBarCanvas = document.getElementById("chartProtoBar");
  if (protoBarCanvas) {
    if (chartProtoBarInstance) chartProtoBarInstance.destroy();
    const sortedProtos = Object.entries(report.detected_protocols || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);

    chartProtoBarInstance = new Chart(protoBarCanvas, {
      type: "bar",
      data: {
        labels: sortedProtos.map(([k]) => k),
        datasets: [{
          label: "Packets",
          data: sortedProtos.map(([, v]) => v),
          backgroundColor: "rgba(6, 182, 212, 0.75)",
          borderColor: "#06b6d4",
          borderWidth: 1,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => ` ${ctx.parsed.x.toLocaleString()} packets`
            }
          }
        },
        scales: {
          x: {
            grid: { color: gridColor },
            ticks: {
              callback: (val) => val >= 1000 ? (val / 1000).toFixed(0) + 'k' : val
            }
          },
          y: { grid: { display: false } }
        }
      }
    });
  }

  // 3. Asset Role Distribution (Pie)
  const roleCanvas = document.getElementById("chartRolePie");
  if (roleCanvas) {
    if (chartRolePieInstance) chartRolePieInstance.destroy();
    const roleCounts = {};
    Object.values(report.devices || {}).forEach(d => {
      const r = d.suspected_role || "Unknown";
      roleCounts[r] = (roleCounts[r] || 0) + 1;
    });

    const roleEntries = Object.entries(roleCounts).sort((a, b) => b[1] - a[1]);
    const roleLabels = roleEntries.map(([k]) => k);
    const roleData = roleEntries.map(([, v]) => v);

    const roleColors = roleLabels.map(r => {
      switch (r) {
        case "PLC": return "#06b6d4";
        case "HMI": return "#3b82f6";
        case "Engineering Workstation": return "#f59e0b";
        case "SCADA Server": return "#8b5cf6";
        case "Historian": return "#14b8a6";
        case "Network Device": return "#10b981";
        case "Server": return "#6366f1";
        case "Workstation": return "#64748b";
        default: return "#94a3b8";
      }
    });

    chartRolePieInstance = new Chart(roleCanvas, {
      type: "pie",
      data: {
        labels: roleLabels,
        datasets: [{
          data: roleData,
          backgroundColor: roleColors,
          borderColor: isLight ? "#ffffff" : "#101830",
          borderWidth: 2,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "right",
            labels: { boxWidth: 12, font: { size: 11 } }
          },
          tooltip: {
            callbacks: {
              label: (ctx) => ` ${ctx.label}: ${ctx.parsed} device(s)`
            }
          }
        }
      }
    });
  }

  // 4. Top Talkers by Traffic Volume (Bar)
  const talkersCanvas = document.getElementById("chartTopTalkers");
  if (talkersCanvas) {
    if (chartTopTalkersInstance) chartTopTalkersInstance.destroy();
    const topDevices = Object.entries(report.devices || {})
      .sort((a, b) => (b[1].total_bytes || 0) - (a[1].total_bytes || 0))
      .slice(0, 6);

    const talkerLabels = topDevices.map(([ip, d]) => `${ip} (${d.suspected_role || '?'})`);
    const talkerMiB = topDevices.map(([, d]) => +((d.total_bytes || 0) / (1024 * 1024)).toFixed(2));

    chartTopTalkersInstance = new Chart(talkersCanvas, {
      type: "bar",
      data: {
        labels: talkerLabels,
        datasets: [{
          label: "Endpoint Traffic (MiB)",
          data: talkerMiB,
          backgroundColor: "rgba(16, 185, 129, 0.75)",
          borderColor: "#10b981",
          borderWidth: 1,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => ` ${ctx.parsed.x.toLocaleString()} MiB endpoint traffic`
            }
          }
        },
        scales: {
          x: {
            grid: { color: gridColor },
            ticks: {
              callback: (val) => val >= 1000 ? (val / 1000).toFixed(0) + 'k' : val
            }
          },
          y: { grid: { display: false } }
        }
      }
    });
  }
}

function renderProtocols(protoDict, totalPkts) {
  const container = document.getElementById("protocolChips");
  if (!container) return;

  container.innerHTML = Object.entries(protoDict).map(([proto, count]) => {
    const pct = ((count / Math.max(1, totalPkts)) * 100).toFixed(1);
    return `
      <div class="proto-chip">
        <span class="proto-chip-name">${escapeCaptureText(proto)}</span>
        <span class="proto-chip-count">${Number(count).toLocaleString()} (${pct}%)</span>
      </div>
    `;
  }).join("");
}

function renderTransportChips(transportDict, totalPkts) {
  const wrap = document.getElementById("transportChipsWrap");
  const container = document.getElementById("transportChips");
  if (!wrap || !container) return;

  if (!transportDict || Object.keys(transportDict).length === 0) {
    wrap.style.display = "none";
    return;
  }
  wrap.style.display = "block";
  container.innerHTML = Object.entries(transportDict).map(([proto, count]) => {
    const pct = ((count / Math.max(1, totalPkts)) * 100).toFixed(1);
    return `
      <div class="proto-chip">
        <span class="proto-chip-name">${escapeCaptureText(proto)}</span>
        <span class="proto-chip-count">${Number(count).toLocaleString()} (${pct}%)</span>
      </div>
    `;
  }).join("");
}

function renderDeviceTable(devices) {
  const tbody = document.getElementById("deviceTableBody");
  if (!tbody) return;

  tbody.innerHTML = Object.entries(devices).map(([ip, dev]) => {
    const role = dev.suspected_role || "Unknown";
    const conf = dev.confidence || "Low";
    const roleCls = getRoleBadgeClass(role);
    const confCls = `conf-${conf.toLowerCase()}`;
    const mb = (dev.total_bytes / (1024 * 1024)).toFixed(2);
    const ports = (dev.observed_ports_tcp_server || []).join(", ") || "-";

    return `
      <tr data-ip="${escapeCaptureText(ip)}" data-role="${escapeCaptureText(role)}" style="cursor: pointer;">
        <td><strong><code>${escapeCaptureText(ip)}</code></strong></td>
        <td><code>${escapeCaptureText(dev.mac_address)}</code></td>
        <td>${escapeCaptureText(dev.mac_vendor)}</td>
        <td><span class="badge ${roleCls}">${escapeCaptureText(role)}</span></td>
        <td><span class="conf-pill ${confCls}">${escapeCaptureText(conf)}</span></td>
        <td>${dev.total_packets.toLocaleString()}</td>
        <td>${mb} MB</td>
        <td><code>${escapeCaptureText(ports)}</code></td>
        <td><button class="btn btn-outline" style="padding: 3px 8px; font-size: 11px;">View Evidence</button></td>
      </tr>
    `;
  }).join("");
  // Delegate clicks after rendering, rather than constructing inline JS from
  // capture-derived IP strings. Evidence buttons and table rows both work.
  tbody.onclick = (event) => {
    const row = event.target.closest("tr[data-ip]");
    if (row && tbody.contains(row)) openAssetModal(row.dataset.ip);
  };
}

function getRoleBadgeClass(role) {
  const map = {
    "PLC": "badge-plc",
    "HMI": "badge-hmi",
    "Engineering Workstation": "badge-ews",
    "SCADA Server": "badge-scada",
    "Network Device": "badge-net",
    "Server": "badge-server",
    "Workstation": "badge-client",
    "Unknown": "badge-unknown"
  };
  return map[role] || "badge-unknown";
}

function filterDeviceTable() {
  const query = document.getElementById("deviceSearch")?.value.toLowerCase() || "";
  const roleFilter = document.getElementById("roleFilter")?.value || "";

  document.querySelectorAll("#deviceTableBody tr").forEach(tr => {
    const text = tr.textContent.toLowerCase();
    const role = tr.getAttribute("data-role") || "";
    const matchesSearch = text.includes(query);
    const matchesRole = !roleFilter || role === roleFilter;

    tr.style.display = (matchesSearch && matchesRole) ? "" : "none";
  });
}

function filterFlowTable() {
  const query = document.getElementById("flowSearch")?.value.toLowerCase() || "";
  document.querySelectorAll("#flowTableBody tr").forEach(tr => {
    const text = tr.textContent.toLowerCase();
    tr.style.display = text.includes(query) ? "" : "none";
  });
}

function openAssetModal(ip) {
  if (!currentReport || !currentReport.devices || !currentReport.devices[ip]) return;
  const dev = currentReport.devices[ip];

  document.getElementById("modalIp").textContent = ip;
  document.getElementById("modalMac").textContent = dev.mac_address;
  document.getElementById("modalVendor").textContent = dev.mac_vendor;
  document.getElementById("modalHostname").textContent = dev.hostname || "None discovered";
  document.getElementById("modalRole").textContent = dev.suspected_role;
  document.getElementById("modalConfidence").textContent = dev.confidence;
  document.getElementById("modalPacketsSent").textContent = dev.packets_sent.toLocaleString();
  document.getElementById("modalPacketsRecv").textContent = dev.packets_received.toLocaleString();
  document.getElementById("modalBytesSent").textContent = `${(dev.bytes_sent / 1024).toFixed(1)} KB`;
  document.getElementById("modalBytesRecv").textContent = `${(dev.bytes_received / 1024).toFixed(1)} KB`;
  document.getElementById("modalServerPorts").textContent = dev.observed_ports_tcp_server.join(", ") || "None";
  document.getElementById("modalClientPorts").textContent = dev.observed_ports_tcp_client.join(", ") || "None";
  document.getElementById("modalPartners").textContent = dev.communication_partners.join(", ") || "None";

  document.getElementById("modalUdpPorts").textContent = dev.observed_ports_udp.join(", ") || "None";
  document.getElementById("modalProtocols").textContent = dev.protocols_used.join(", ") || "None";

  // Observation window (first/last seen)
  const fmtTs = (ts) => {
    if (ts === null || ts === undefined) return "N/A";
    const d = new Date(typeof ts === "number" ? ts * 1000 : ts);
    return isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
  };
  document.getElementById("modalFirstSeen").textContent = fmtTs(dev.first_seen);
  document.getElementById("modalLastSeen").textContent = fmtTs(dev.last_seen);

  // Evidence list
  const evUl = document.getElementById("modalEvidence");
  evUl.innerHTML = dev.evidence.map(e => `<li>${escapeCaptureText(e)}</li>`).join("");

  document.getElementById("assetModal").style.display = "flex";
}

function closeModal() {
  document.getElementById("assetModal").style.display = "none";
}

function renderProtocolInsights(insights) {
  const container = document.getElementById("insightsGrid");
  if (!container) return;
  container.replaceChildren();
  let rendered = 0;
  for (const [proto, data] of Object.entries(insights || {})) {
    const combined = [
      ["Decoded functions", data.function_codes || {}],
      ["Operations and commands", {...(data.operations || {}), ...(data.opcua_messages || {}), ...(data.asdu_types || {})}],
      ["Service codes", data.service_codes || {}],
      ["Exceptions / indications", data.exception_codes || {}]
    ].filter(([_, vals]) => Object.keys(vals).length);
    if (!combined.length && !(data.unit_ids || []).length && !(data.device_identifiers || []).length) continue;
    rendered += 1;
    const card = document.createElement('article');
    card.className = 'panel-card operation-card';
    const title = document.createElement('h3'); title.textContent = proto;
    card.appendChild(title);
    const note = document.createElement('p'); note.className = 'visual-subtitle';
    note.textContent = `Functions: ${data.function_source || 'unverified'} · Operations: ${data.operation_source || 'unverified'}`;
    card.appendChild(note);
    for (const [groupName, obj] of combined) {
      const section = document.createElement('section');
      section.className = 'operation-section';
      const head = document.createElement('div');head.className = 'operation-section-head';head.textContent=groupName;
      section.appendChild(head);
      const entries = Object.entries(obj).filter(([_,v]) => Number.isFinite(Number(v)) && Number(v)>=0).sort((a,b)=>Number(b[1])-Number(a[1]));
      const top = entries.slice(0,6);const max = Math.max(1,...top.map(x=>Number(x[1])));
      function drawRows(rows, parent) {
        rows.forEach(([key,val])=>{
          const wrap=document.createElement('div');wrap.className='operation-row';
          const label=document.createElement('span');label.className='operation-label';label.textContent=key;label.title=key;
          const num=document.createElement('span');num.className='operation-count';num.textContent=Number(val).toLocaleString();
          const track=document.createElement('div');track.className='operation-track';
          const fill=document.createElement('div');fill.className='operation-fill';fill.style.width=`${100*Number(val)/max}%`;
          track.appendChild(fill);wrap.append(label,num,track);parent.appendChild(wrap);
        });
      }
      drawRows(top,section);
      if (entries.length>6) {
        const more=document.createElement('details');more.className='operation-more';
        const toggle=document.createElement('summary');toggle.textContent=`Show ${entries.length-6} additional values`;
        more.appendChild(toggle);drawRows(entries.slice(6),more);section.appendChild(more);
      }
      card.appendChild(section);
    }
    const ids=[...(data.unit_ids || []).map(x=>`Unit ID ${x}`),...(data.device_identifiers || []).slice(0,6)];
    if (ids.length) {const foot=document.createElement('p');foot.className='operation-ids';foot.textContent=ids.join(' · ');card.appendChild(foot);}
    container.appendChild(card);
  }
  if (!rendered) {const blank=document.createElement('div');blank.className='panel-card';blank.textContent='No supported decoded operation fields were found in this capture.';container.appendChild(blank);}
}

function renderAssetActivity(devices) {
  const box=document.getElementById('assetActivityVisual');if(!box)return;
  box.replaceChildren();
  const items=Object.entries(devices||{}).sort((a,b)=>(b[1].total_bytes||0)-(a[1].total_bytes||0)).slice(0,5);
  if(!items.length) {box.textContent='No IP endpoints observed.';return;}
  const max=Math.max(1,...items.map(([_,d])=>d.total_bytes||0));
  for(const [ip,d] of items){
    const entry=document.createElement('div');entry.className='activity-item';
    const label=document.createElement('div');label.className='activity-heading';
    const left=document.createElement('strong');left.textContent=ip;
    const role=document.createElement('span');role.className='role-muted';role.textContent=d.suspected_role||'Unknown';
    const val=document.createElement('span');val.textContent=`${((d.total_bytes||0)/1048576).toFixed(2)} MiB`;
    label.append(left,role,val);
    const track=document.createElement('div');track.className='activity-track';
    const fill=document.createElement('div');fill.className='activity-fill';fill.style.width=`${100*(d.total_bytes||0)/max}%`;
    track.appendChild(fill);entry.append(label,track);box.appendChild(entry);
  }
}

function renderFlowTable(flows) {
  const tbody = document.getElementById("flowTableBody");
  if (!tbody) return;

  tbody.innerHTML = (flows || []).map(f => {
    const fmtF = (ts) => {
      if (ts === null || ts === undefined) return "-";
      const d = new Date(typeof ts === "number" ? ts * 1000 : ts);
      return isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
    };
    return `
      <tr>
        <td><code>${escapeCaptureText(f.client_ip)}:${escapeCaptureText(f.source_port)}</code></td>
        <td><code>${escapeCaptureText(f.server_ip)}:${escapeCaptureText(f.destination_port)}</code></td>
        <td><span class="badge badge-plc">${escapeCaptureText(f.protocol)}</span></td>
        <td>${f.packet_count.toLocaleString()}</td>
        <td>${(f.total_bytes / 1024).toFixed(1)} KB</td>
        <td><code>${escapeCaptureText(fmtF(f.first_seen))}</code></td>
        <td><code>${escapeCaptureText(fmtF(f.last_seen))}</code></td>
        <td><code>${escapeCaptureText(f.likely_requester)}</code></td>
        <td><code>${escapeCaptureText(f.likely_responder)}</code></td>
      </tr>
    `;
  }).join("");
}

function setupExportLinks(jobId) {
  document.getElementById("btnExportJson")?.setAttribute("href", `/api/export/${jobId}/json`);
  document.getElementById("btnExportCsvDevices")?.setAttribute("href", `/api/export/${jobId}/csv-devices`);
  document.getElementById("btnExportCsvFlows")?.setAttribute("href", `/api/export/${jobId}/csv-flows`);
  document.getElementById("btnExportHtml")?.setAttribute("href", `/api/export/${jobId}/html`);
  document.getElementById("btnExportMd")?.setAttribute("href", `/api/export/${jobId}/md`);
}

function renderInvestigation(report) {
  const box = document.getElementById('captureInvestigation');
  if (!box) return;
  box.replaceChildren();
  const devices = Object.entries(report.devices || {});
  const ot = devices.filter(([_,d]) => d.is_ot_asset);
  const findings = report.anomalies || [];
  const flows = [...(report.conversations || [])].sort((a,b)=>(b.total_bytes||0)-(a.total_bytes||0)).slice(0,6);
  const sum=report.summary||{};
  const make = (tag,cls,txt) => {const el=document.createElement(tag);if(cls)el.className=cls;if(txt!==undefined)el.textContent=txt;return el;};
  const hero=make('section','panel-card investigation-summary');
  hero.append(make('h3','', 'Capture evidence at a glance'));
  const stats=make('div','investigation-stat-grid');
  const known=[['Captured frames', Number(sum.packet_count||0).toLocaleString(),'OBSERVED'],['IP endpoints',String(sum.device_count||0),'OBSERVED'],['Suspected OT roles',String(ot.length),'INFERRED'],['Items to review',String(findings.length),'HEURISTIC']];
  known.forEach(([label,num,evidence])=>{
    const cell=make('div','investigation-stat');cell.append(make('small','',label),make('strong','',num),make('span','evidence-flag',evidence));stats.append(cell);
  });
  hero.append(stats);box.append(hero);
  const flowPanel=make('section','panel-card investigation-flows');
  flowPanel.append(make('h3','', 'Largest observed endpoint flows'),make('p','visual-subtitle','These are capture-level relationships, not authenticated commands or confirmed device identities.'));
  if(flows.length){
    const max=Math.max(1,...flows.map(f=>Number(f.total_bytes||0)));
    flows.forEach(f=>{
      const entry=make('div','investigation-flow');
      const endpoints=make('div','investigation-flow-label');
      const lhs=make('code','',String(f.client_ip||'?'));const rhs=make('code','',String(f.server_ip||'?'));
      const arrow=make('span','', '→');const port=make('small','',String(f.protocol||'TCP')+' / '+String(f.destination_port||'?'));
      endpoints.append(lhs,arrow,rhs,port);
      const track=make('div','investigation-flow-track');const fill=make('div','investigation-flow-fill');fill.style.width=`${100*Number(f.total_bytes||0)/max}%`;track.append(fill);
      const value=make('span','flow-amount',`${(Number(f.total_bytes||0)/1048576).toFixed(2)} MiB`);
      entry.append(endpoints,track,value);flowPanel.append(entry);
    });
  } else {flowPanel.append(make('p','', 'No communication groups retained.'))}
  box.append(flowPanel);
  const rolePanel=make('section','panel-card investigation-roles');rolePanel.append(make('h3','', 'Device role hypotheses'));
  if(ot.length){
    ot.sort((a,b)=>(b[1].total_packets||0)-(a[1].total_packets||0)).slice(0,9).forEach(([ip,d])=>{
      const row=make('div','hypothesis-row');
      const meta=make('div','');meta.append(make('strong','',ip),make('small','',String(d.confidence||'Unrated')+' confidence'));
      const badge=make('span','hypothesis-role',d.suspected_role||'Unknown');row.append(meta,badge);rolePanel.append(row);
    });
  } else rolePanel.append(make('p','visual-subtitle','No OT role inferred.'));
  const note=make('p','visual-subtitle','Role assignments are statistical hypotheses; confirm against asset inventories and engineering documentation.');rolePanel.append(note);
  box.append(rolePanel);
  const findingPanel=make('section','panel-card investigation-findings');findingPanel.append(make('h3','',`Investigation queue · ${findings.length} item(s)`));
  if(findings.length){
    findings.slice(0,15).forEach(a=>{
      const item=make('details','finding-review');const head=make('summary','');
      head.append(make('span','finding-severity',a.severity||'REVIEW'),make('strong','',a.type||'Potential anomaly'),make('code','',a.source_ip||''));
      item.append(head,make('p','',a.evidence||'No evidence text supplied.'));findingPanel.append(item);
    });
  }else findingPanel.append(make('p','visual-subtitle','No configured heuristic triggered. This does not establish an incident-free capture.'));
  box.append(findingPanel);
  const lim=make('details','panel-card investigation-method');lim.append(make('summary','', 'How to interpret this investigation'));
  lim.append(make('p','', 'Observed: recorded packets, addresses, ports and timestamps. Derived: dissections, statistics and vendor lookups. Inferred: identities, authorization, attack intent and successful writes. TCP retransmissions are not independent operations. Review evidence in Wireshark before making security claims.'));
  box.append(lim);
}
