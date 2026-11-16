/**
 * EmberVault Core Client App Logic
 * - Dark/Light Theme Switching
 * - Browser Timezone Normalization
 * - Live Status Polling (/api/ui/status) every 10 seconds
 * - Toast Notification Helper
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  normalizeAllDatetimes();
  initRealtimeSystem();
  initThroughputControls();
  initRunDetailRealtime();
  initEmberXPTaskbar();
});

// Timezone Normalization Utilities
function parseUtcDate(val) {
  if (!val) return null;
  if (val instanceof Date) return isNaN(val.getTime()) ? null : val;
  if (typeof val === 'number') {
    const d = new Date(val);
    return isNaN(d.getTime()) ? null : d;
  }
  if (typeof val === 'string') {
    let s = val.trim();
    if (!s || s === 'N/A' || s === 'Mai' || s === '—' || s === 'In attesa' || s === 'In coda') return null;
    if (!s.endsWith('Z') && !/[+-]\d{2}(?::?\d{2})?$/.test(s)) {
      s = s.replace(' ', 'T') + 'Z';
    }
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }
  return null;
}

function formatUserDateTime(val, formatType = 'full') {
  const d = parseUtcDate(val);
  if (!d) return val ? String(val) : '—';

  const pad = (n) => String(n).padStart(2, '0');
  const day = pad(d.getDate());
  const month = pad(d.getMonth() + 1);
  const year = d.getFullYear();
  const shortYear = String(year).slice(-2);
  const hours = pad(d.getHours());
  const minutes = pad(d.getMinutes());
  const seconds = pad(d.getSeconds());

  if (formatType === 'short') {
    return `${day}/${month}/${year} ${hours}:${minutes}`;
  } else if (formatType === 'time-date') {
    return `${hours}:${minutes}:${seconds} (${day}/${month}/${shortYear})`;
  } else if (formatType === 'time') {
    return `${hours}:${minutes}:${seconds}`;
  } else if (formatType === 'time-ms') {
    const ms = String(d.getMilliseconds()).padStart(3, '0');
    return `${hours}:${minutes}:${seconds}.${ms}`;
  } else if (formatType === 'date') {
    return `${day}/${month}/${year}`;
  } else if (formatType === 'iso-date') {
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  }
  return `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;
}

function normalizeAllDatetimes(container = document) {
  const elements = container.querySelectorAll('.user-datetime');
  const tzName = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Locale';
  elements.forEach((el) => {
    const utcVal = el.getAttribute('data-utc') || el.getAttribute('datetime') || el.textContent.trim();
    const fmt = el.getAttribute('data-format') || 'full';
    const parsed = parseUtcDate(utcVal);
    if (parsed) {
      el.textContent = formatUserDateTime(parsed, fmt);
      el.title = `${formatUserDateTime(parsed, 'full')} (${tzName})`;
    }
  });
}

window.parseUtcDate = parseUtcDate;
window.formatUserDateTime = formatUserDateTime;
window.normalizeAllDatetimes = normalizeAllDatetimes;

// 1. Theme Management
function initTheme() {
  const themeToggle = document.getElementById('theme-toggle');
  const savedMode = localStorage.getItem('embervault-theme') || 'dark';
  
  if (savedMode === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
  }

  // Restore client color theme if saved in localStorage and not already set by server
  const savedColorTheme = localStorage.getItem('embervault-user-theme');
  const serverColorTheme = document.documentElement.getAttribute('data-color-theme');
  if (serverColorTheme) {
    localStorage.setItem('embervault-user-theme', serverColorTheme);
  } else if (savedColorTheme) {
    document.documentElement.setAttribute('data-color-theme', savedColorTheme);
  }

  function updateThemeColor() {
    try {
      const metaTheme = document.querySelector('meta[name="theme-color"]');
      if (metaTheme) {
        let bg = getComputedStyle(document.documentElement).getPropertyValue('--bg-primary').trim();
        if (!bg) {
          bg = getComputedStyle(document.body).backgroundColor;
        }
        if (bg) {
          metaTheme.setAttribute('content', bg);
        }
      }
    } catch (e) {}
  }

  updateThemeColor();

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      const nextTheme = current === 'light' ? 'dark' : 'light';
      if (nextTheme === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
      } else {
        document.documentElement.removeAttribute('data-theme');
      }
      localStorage.setItem('embervault-theme', nextTheme);
      document.cookie = "embervault_mode=" + nextTheme + ";path=/;max-age=31536000;SameSite=Lax";
      updateThemeColor();
    });
  }
}

// 2. Realtime SSE & Dashboard Charts
let currentThroughputRange = '24h';
let activeThroughputSamples = [];
let isCustomRangeActive = false;

function formatSpeed(bytesPerSec) {
  if (!bytesPerSec || bytesPerSec <= 0) return '0 B/s';
  if (bytesPerSec >= 1073741824) return (bytesPerSec / 1073741824).toFixed(2) + ' GiB/s';
  if (bytesPerSec >= 1048576) return (bytesPerSec / 1048576).toFixed(2) + ' MiB/s';
  if (bytesPerSec >= 1024) return (bytesPerSec / 1024).toFixed(2) + ' KiB/s';
  return Math.round(bytesPerSec) + ' B/s';
}

function updateElementText(id, val) {
  if (val !== null && val !== undefined) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }
}

function initRealtimeSystem() {
  const indicator = document.getElementById('system-status');
  const indicatorText = document.getElementById('system-status-text');

  if (!('EventSource' in window)) {
    fallbackPolling();
    return;
  }

  let eventSource = null;
  let fallbackInterval = null;
  let sseReconnectTimeout = null;
  let isPageVisible = !document.hidden;

  function stopAllConnections() {
    if (eventSource) {
      try { eventSource.close(); } catch (_) {}
      eventSource = null;
    }
    if (fallbackInterval) {
      clearInterval(fallbackInterval);
      fallbackInterval = null;
    }
    if (sseReconnectTimeout) {
      clearTimeout(sseReconnectTimeout);
      sseReconnectTimeout = null;
    }
  }

  function connectSSE() {
    stopAllConnections();
    if (!isPageVisible) return;

    try {
      eventSource = new EventSource('/api/ui/events');
    } catch (e) {
      fallbackInterval = setInterval(checkStatusFallback, 10000);
      return;
    }

    eventSource.addEventListener('connected', (e) => {
      try {
        const data = JSON.parse(e.data);
        handleRealtimePayload(data);
        if (indicator) {
          indicator.classList.remove('offline');
          indicator.classList.add('realtime');
          if (indicatorText) indicatorText.textContent = indicator.dataset.connectedText || window._t('status_live', 'In diretta');
        }
      } catch (err) {
        console.warn('SSE connected parse error:', err);
      }
    });

    eventSource.addEventListener('status', (e) => {
      try {
        const data = JSON.parse(e.data);
        handleRealtimePayload(data);
        if (indicator) {
          indicator.classList.remove('offline');
          indicator.classList.add('realtime');
          if (indicatorText) indicatorText.textContent = indicator.dataset.connectedText || window._t('status_live', 'In diretta');
        }
      } catch (err) {
        console.warn('SSE status parse error:', err);
      }
    });

    eventSource.addEventListener('reconnect', () => {
      stopAllConnections();
      sseReconnectTimeout = setTimeout(connectSSE, 1000);
    });

    eventSource.onerror = () => {
      if (indicator) {
        indicator.classList.remove('realtime');
        indicator.classList.add('offline');
        if (indicatorText) indicatorText.textContent = indicator.dataset.offlineText || window._t('status_offline', 'Offline');
      }
      stopAllConnections();
      if (isPageVisible) {
        fallbackInterval = setInterval(checkStatusFallback, 10000);
        sseReconnectTimeout = setTimeout(connectSSE, 5000);
      }
    };
  }

  document.addEventListener('visibilitychange', () => {
    isPageVisible = !document.hidden;
    if (isPageVisible) {
      connectSSE();
    } else {
      stopAllConnections();
    }
  });

  window.addEventListener('pagehide', () => {
    stopAllConnections();
  });

  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      connectSSE();
    }
  });

  async function checkStatusFallback() {
    try {
      const res = await fetch('/api/ui/status', { headers: { 'Accept': 'application/json' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (indicator) {
        indicator.classList.remove('offline');
        if (indicatorText) indicatorText.textContent = indicator.dataset.connectedText || 'In diretta';
      }
      updateElementText('stat-proxies-online', data.proxies ? data.proxies.online : null);
      updateElementText('stat-proxies-total', data.proxies ? data.proxies.total : null);
      updateElementText('stat-active-runs', data.runs ? data.runs.active : null);
    } catch (err) {
      if (indicator) {
        indicator.classList.add('offline');
        if (indicatorText) indicatorText.textContent = indicator.dataset.offlineText || window._t('status_disconnected', 'Disconnesso');
      }
    }
  }

  function fallbackPolling() {
    checkStatusFallback();
    setInterval(checkStatusFallback, 10000);
  }

  connectSSE();
}

function handleRealtimePayload(data) {
  if (!data) return;

  // 1. Stat cards numbers
  if (data.proxies_count) {
    updateElementText('stat-proxies-online', data.proxies_count.online);
    updateElementText('stat-proxies-total', data.proxies_count.total);
  }
  if (data.runs_count) {
    updateElementText('stat-active-runs', data.runs_count.active);
  }
  if (data.recent_errors !== undefined) {
    updateElementText('stat-recent-errors', data.recent_errors);
  }

  // 2. Charts updates
  if (data.throughput) {
    updateThroughputChart(data.throughput);
  }
  if (data.runs_count) {
    updateRunsDonutChart(data.runs_count);
  }
  if (data.fleet_capacity && data.proxies) {
    updateFleetCapacity(data.fleet_capacity, data.proxies);
  }

  // 3. Tables updates
  if (data.proxies) {
    updateProxiesTable(data.proxies);
  }
  if (data.recent_runs) {
    updateRecentRunsTable(data.recent_runs);
  }

  // 4. Dispatch event for page-specific observers (e.g. proxies page live update)
  window.dispatchEvent(new CustomEvent('embervault:realtime_status', { detail: data }));
}

// Throughput SVG Line & Area Chart with Historical Ranges
function initThroughputControls() {
  const rangeGroup = document.getElementById('throughput-range-group');
  if (!rangeGroup) return;

  const chartSvg = document.getElementById('chart-throughput-svg');
  if (chartSvg) {
    let resizeTimer = null;
    const handleResize = () => {
      if (resizeTimer) cancelAnimationFrame(resizeTimer);
      resizeTimer = requestAnimationFrame(() => {
        renderThroughputChart();
      });
    };

    if (window.ResizeObserver) {
      const ro = new ResizeObserver(handleResize);
      ro.observe(chartSvg);
    } else {
      window.addEventListener('resize', handleResize);
    }
  }

  const rangeButtons = rangeGroup.querySelectorAll('.btn-range');
  const customBar = document.getElementById('throughput-custom-range-bar');
  const customStartInput = document.getElementById('throughput-custom-start');
  const customEndInput = document.getElementById('throughput-custom-end');
  const btnApplyCustom = document.getElementById('btn-apply-custom-range');
  const customError = document.getElementById('custom-range-error');

  rangeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const selectedRange = btn.getAttribute('data-range');
      rangeButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      if (selectedRange === 'custom') {
        isCustomRangeActive = true;
        currentThroughputRange = 'custom';
        if (customBar) customBar.style.display = 'flex';

        if (customStartInput && !customStartInput.value) {
          const past = new Date(Date.now() - 24 * 3600 * 1000);
          customStartInput.value = formatDatetimeLocal(past);
        }
        if (customEndInput && !customEndInput.value) {
          customEndInput.value = formatDatetimeLocal(new Date());
        }
        if (customStartInput && customEndInput) {
          loadThroughputHistory('custom', customStartInput.value, customEndInput.value);
        }
      } else {
        isCustomRangeActive = false;
        currentThroughputRange = selectedRange;
        if (customBar) customBar.style.display = 'none';
        if (customError) customError.style.display = 'none';
        loadThroughputHistory(selectedRange);
      }
    });
  });

  if (btnApplyCustom) {
    btnApplyCustom.addEventListener('click', () => {
      const startVal = customStartInput ? customStartInput.value : '';
      const endVal = customEndInput ? customEndInput.value : '';
      if (!startVal || !endVal) {
        if (customError) {
          customError.textContent = window._t('err_specify_start_and_end_date', 'Specificare sia data di inizio che data di fine.');
          customError.style.display = 'inline';
        }
        return;
      }
      const startDate = new Date(startVal);
      const endDate = new Date(endVal);
      if (startDate >= endDate) {
        if (customError) {
          customError.textContent = window._t('err_start_before_end_date', 'La data di inizio deve essere precedente alla data di fine.');
          customError.style.display = 'inline';
        }
        return;
      }
      if (customError) customError.style.display = 'none';
      loadThroughputHistory('custom', startVal, endVal);
    });
  }

  // Initial render with current dimensions
  renderThroughputChart();

  // Load default 24h view
  loadThroughputHistory('24h');
}

function formatDatetimeLocal(d) {
  const pad = (n) => String(n).padStart(2, '0');
  const year = d.getFullYear();
  const month = pad(d.getMonth() + 1);
  const day = pad(d.getDate());
  const hours = pad(d.getHours());
  const minutes = pad(d.getMinutes());
  return `${year}-${month}-${day}T${hours}:${minutes}`;
}

async function loadThroughputHistory(range, customStart, customEnd) {
  try {
    let url = `/api/ui/metrics/throughput?range=${encodeURIComponent(range)}`;
    if (range === 'custom' && customStart && customEnd) {
      url += `&start=${encodeURIComponent(new Date(customStart).toISOString())}&end=${encodeURIComponent(new Date(customEnd).toISOString())}`;
    }
    const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.samples && Array.isArray(data.samples)) {
      activeThroughputSamples = data.samples.map(s => ({
        timestamp: new Date(s.timestamp).getTime(),
        bytes_per_sec: s.bytes_per_sec || 0
      }));
    }
    if (data.current_speed_display) {
      updateElementText('chart-throughput-speed', data.current_speed_display);
    }
    renderThroughputChart();
  } catch (err) {
    console.warn('Failed to load throughput history:', err);
  }
}

function renderThroughputChart() {
  const chartSvg = document.getElementById('chart-throughput-svg');
  if (!chartSvg) return;

  const svgWidth = Math.max(300, Math.round(chartSvg.clientWidth || chartSvg.getBoundingClientRect().width || 600));
  const svgHeight = 180;
  chartSvg.setAttribute('viewBox', `0 0 ${svgWidth} ${svgHeight}`);

  const chartXStart = 85;
  const chartXEnd = svgWidth - 15;
  const chartWidth = Math.max(50, chartXEnd - chartXStart);
  const chartYBottom = 160;
  const chartHeight = 140; // from y=20 to y=160

  // Update horizontal grid lines x2 to match dynamic width
  const gridLines = chartSvg.querySelectorAll('.throughput-grid-line, line[y1="160"]');
  gridLines.forEach(line => line.setAttribute('x2', String(chartXEnd)));

  // Update X-axis label positions
  const xMidEl = document.getElementById('chart-x-mid');
  const xEndEl = document.getElementById('chart-x-end');
  if (xMidEl) xMidEl.setAttribute('x', String(Math.round(chartXStart + chartWidth / 2)));
  if (xEndEl) xEndEl.setAttribute('x', String(chartXEnd));

  const now = Date.now();
  let timeStart, timeEnd;

  if (currentThroughputRange === '5m') {
    timeStart = now - (5 * 60 * 1000);
    timeEnd = now;
    updateElementText('chart-x-start', '-5m');
    updateElementText('chart-x-mid', '-2.5m');
    updateElementText('chart-x-end', window._t('chart_now', 'Ora'));
  } else if (currentThroughputRange === '1h') {
    timeStart = now - (60 * 60 * 1000);
    timeEnd = now;
    updateElementText('chart-x-start', '-1h');
    updateElementText('chart-x-mid', '-30m');
    updateElementText('chart-x-end', window._t('chart_now', 'Ora'));
  } else if (currentThroughputRange === '6h') {
    timeStart = now - (6 * 3600 * 1000);
    timeEnd = now;
    updateElementText('chart-x-start', '-6h');
    updateElementText('chart-x-mid', '-3h');
    updateElementText('chart-x-end', window._t('chart_now', 'Ora'));
  } else if (currentThroughputRange === '24h') {
    timeStart = now - (24 * 3600 * 1000);
    timeEnd = now;
    updateElementText('chart-x-start', '-24h');
    updateElementText('chart-x-mid', '-12h');
    updateElementText('chart-x-end', window._t('chart_now', 'Ora'));
  } else {
    // Custom range
    const startInput = document.getElementById('throughput-custom-start');
    const endInput = document.getElementById('throughput-custom-end');
    timeStart = startInput && startInput.value ? new Date(startInput.value).getTime() : now - (24 * 3600 * 1000);
    timeEnd = endInput && endInput.value ? new Date(endInput.value).getTime() : now;
    const formatTimeLabel = (ts) => {
      const d = new Date(ts);
      return `${d.getDate()}/${d.getMonth()+1} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
    };
    updateElementText('chart-x-start', formatTimeLabel(timeStart));
    updateElementText('chart-x-mid', formatTimeLabel(timeStart + (timeEnd - timeStart) / 2));
    updateElementText('chart-x-end', formatTimeLabel(timeEnd));
  }

  const duration = Math.max(1000, timeEnd - timeStart);

  let visibleSamples = activeThroughputSamples.filter(
    s => s.timestamp >= (timeStart - 60000) && s.timestamp <= (timeEnd + 60000)
  );

  if (visibleSamples.length === 0) {
    visibleSamples = [
      { timestamp: timeStart, bytes_per_sec: 0 },
      { timestamp: timeEnd, bytes_per_sec: 0 }
    ];
  }

  // Auto-scale Y axis
  const maxObserved = Math.max(...visibleSamples.map(s => s.bytes_per_sec), 1048576); // min 1 MiB/s
  const maxY = Math.ceil(maxObserved * 1.25);

  updateElementText('chart-y-max', formatSpeed(maxY));
  updateElementText('chart-y-mid', formatSpeed(maxY / 2));
  updateElementText('chart-y-low', formatSpeed(maxY / 4));

  const points = [];
  if (visibleSamples.length === 1) {
    points.push({ x: chartXStart, y: chartYBottom });
    const norm = Math.min(1.0, (visibleSamples[0].bytes_per_sec || 0) / maxY);
    points.push({ x: chartXEnd, y: chartYBottom - (norm * chartHeight) });
  } else {
    for (const sample of visibleSamples) {
      const ratio = Math.max(0.0, Math.min(1.0, (sample.timestamp - timeStart) / duration));
      const x = chartXStart + (ratio * chartWidth);
      const norm = Math.min(1.0, (sample.bytes_per_sec || 0) / maxY);
      const y = chartYBottom - (norm * chartHeight);
      points.push({ x, y });
    }
  }

  // Construct SVG Path
  let linePathD = `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
  for (let i = 1; i < points.length; i++) {
    linePathD += ` L ${points[i].x.toFixed(1)} ${points[i].y.toFixed(1)}`;
  }

  const areaPathD = `${linePathD} L ${points[points.length - 1].x.toFixed(1)} ${chartYBottom} L ${points[0].x.toFixed(1)} ${chartYBottom} Z`;

  const lineEl = document.getElementById('chart-throughput-line');
  const areaEl = document.getElementById('chart-throughput-area');
  if (lineEl) lineEl.setAttribute('d', linePathD);
  if (areaEl) areaEl.setAttribute('d', areaPathD);
}

function updateThroughputChart(throughput) {
  const chartSvg = document.getElementById('chart-throughput-svg');
  if (!chartSvg) return;

  const currentSpeedBytes = throughput.speed_bytes_per_sec || 0;
  updateElementText('chart-throughput-speed', throughput.speed_display || formatSpeed(currentSpeedBytes));

  const now = Date.now();
  activeThroughputSamples.push({ timestamp: now, bytes_per_sec: currentSpeedBytes });

  if (!isCustomRangeActive) {
    const cutoff = now - (25 * 3600 * 1000);
    activeThroughputSamples = activeThroughputSamples.filter(s => s.timestamp >= cutoff);
  }

  renderThroughputChart();
}

// Runs Outcome SVG Donut Chart
function updateRunsDonutChart(runsCount) {
  const donutContainer = document.querySelector('.donut-chart-container');
  if (!donutContainer) return;

  const completed = runsCount.completed || 0;
  const failed = runsCount.failed || 0;
  const active = runsCount.active || 0;
  const queued = runsCount.queued || 0;
  const total = completed + failed + active + queued;

  const rate = runsCount.success_rate !== undefined ? runsCount.success_rate : (total > 0 ? Math.round((completed / total) * 100) : 100);
  updateElementText('donut-center-rate', rate + '%');
  updateElementText('chart-runs-rate-badge', rate + '% ' + window._t('status_success', 'Successo'));

  updateElementText('donut-val-completed', completed);
  updateElementText('donut-val-failed', failed);
  updateElementText('donut-val-active', active);
  updateElementText('donut-val-queued', queued);

  // Circumference: 2 * PI * 38 = 238.76
  const C = 238.76;
  const segments = [
    { id: 'donut-slice-completed', count: completed },
    { id: 'donut-slice-failed', count: failed },
    { id: 'donut-slice-active', count: active },
    { id: 'donut-slice-queued', count: queued },
  ];

  let currentOffset = 0;
  segments.forEach((seg) => {
    const el = document.getElementById(seg.id);
    if (!el) return;
    const fraction = total > 0 ? seg.count / total : 0;
    const length = fraction * C;
    el.setAttribute('stroke-dasharray', `${length.toFixed(2)} ${(C - length).toFixed(2)}`);
    el.setAttribute('stroke-dashoffset', (-currentOffset).toFixed(2));
    currentOffset += length;
  });
}

// Proxy Fleet Capacity Gauge & Live List
function updateFleetCapacity(capacity, proxies) {
  const gaugeFill = document.getElementById('chart-fleet-gauge-fill');
  if (!gaugeFill) return;

  const totalSlots = capacity.total_slots || 0;
  const usedSlots = capacity.used_slots || 0;
  const pct = capacity.utilization_pct || 0;

  gaugeFill.style.width = pct + '%';
  updateElementText('chart-fleet-pct-label', pct + '%');
  updateElementText('chart-fleet-slots-badge', `${usedSlots}/${totalSlots} ${window._t('dashboard_slots_unit', 'Slot')} (${pct}%)`);

  const listContainer = document.getElementById('dashboard-fleet-proxies-list');
  if (!listContainer || !proxies) return;

  let html = '';
  proxies.forEach((p) => {
    const running = p.running_tasks || 0;
    const maxTasks = p.max_concurrent || 4;
    const pPct = maxTasks > 0 ? Math.round((running / maxTasks) * 100) : 0;
    const dotClass = p.state === 'online' ? 'var(--status-online)' : (p.state === 'busy' ? 'var(--status-warning, #ff7a00)' : 'var(--status-offline)');

    const proxyHref = p.id ? `/proxies?edit=${encodeURIComponent(p.id)}` : '/proxies';
    html += `
      <div class="fleet-proxy-row clickable-row" data-href="${proxyHref}" title="${window._t('btn_edit_proxy_title', 'Modifica proxy')} ${escapeHtml(p.name)}" style="cursor: pointer;">
        <div class="fleet-proxy-name-col">
          <span style="width: 8px; height: 8px; border-radius: 50%; background: ${dotClass}; flex-shrink: 0;"></span>
          <a href="${proxyHref}" style="color: inherit; text-decoration: none; font-weight: 500;">${escapeHtml(p.name)}</a>
        </div>
        <div class="fleet-proxy-tasks-col">
          <div class="fleet-proxy-slot-meter">
            <div class="fleet-proxy-slot-fill" style="width: ${pPct}%;"></div>
          </div>
          <span style="font-size: 0.75rem; color: var(--text-secondary); min-width: 45px; text-align: right;">${running}/${maxTasks}</span>
        </div>
      </div>
    `;
  });
  listContainer.innerHTML = html;
}

// Live Proxy Table update
function updateProxiesTable(proxies) {
  const table = document.getElementById('table-dashboard-proxies');
  if (!table || !table.querySelector('tbody')) return;
  const tbody = table.querySelector('tbody');

  let html = '';
  proxies.forEach((p) => {
    const state = p.state || 'offline';
    const proxyHref = p.id ? `/proxies?edit=${encodeURIComponent(p.id)}` : '/proxies';
    html += `
      <tr data-href="${proxyHref}" class="clickable-row" title="${window._t('btn_edit_proxy_title', 'Modifica proxy')} ${escapeHtml(p.name)}">
        <td><a href="${proxyHref}" style="color: var(--ember-primary); font-weight: 600;">${escapeHtml(p.name)}</a></td>
        <td class="col-hide-sm">${escapeHtml(p.host)}:${p.port}</td>
        <td>
          <span class="badge badge-${state}">
            <span class="badge-dot"></span>
            ${escapeHtml(state.toUpperCase())}
          </span>
        </td>
        <td class="col-hide-md">${p.running_tasks || 0} / ${p.max_concurrent || 4}</td>
        <td class="col-hide-lg">${p.latency_ms || 0} ms</td>
      </tr>
    `;
  });
  tbody.innerHTML = html;
}

// Live Recent Runs Table update
function updateRecentRunsTable(recentRuns) {
  const table = document.getElementById('table-dashboard-recent-runs');
  if (!table) return;
  const container = table.querySelector('tbody');
  if (!container || !recentRuns || recentRuns.length === 0) return;

  let html = '';
  recentRuns.forEach((r) => {
    html += `
      <tr data-href="/runs/${r.id}" class="clickable-row" title="${window._t('dashboard_view_run_detail_title', 'Visualizza dettaglio esecuzione')}">
        <td><a href="/runs/${r.id}" style="color: var(--ember-primary); font-weight: 600;">${escapeHtml(r.short_id)}</a></td>
        <td>${escapeHtml(r.job_name || r.job_id || 'Job')}</td>
        <td>
          <span class="badge badge-${r.status}">
            <span class="badge-dot"></span>
            ${escapeHtml(r.status)}
          </span>
        </td>
        <td class="col-hide-md"><span style="font-size: 0.85rem; font-weight: 500; text-transform: uppercase;">${escapeHtml(r.trigger || r.planning_mode || 'manual')}</span></td>
        <td class="col-hide-sm">${r.tasks_completed || 0} / ${r.task_count_actual || 0}</td>
        <td class="col-hide-lg"><span class="user-datetime" data-utc="${escapeHtml(r.created_at || '')}">${formatUserDateTime(r.created_at, 'full')}</span></td>
      </tr>
    `;
  });
  container.innerHTML = html;
}

// 3. Realtime Run Detail & Live Logs Streaming
function initRunDetailRealtime() {
  const match = window.location.pathname.match(/^\/runs\/([0-9a-fA-F-]+)$/);
  if (!match) return;

  const runId = match[1];
  const terminalViewport = document.querySelector('.log-terminal-viewport');
  let eventSource = null;
  let sseReconnectTimeout = null;

  function stopRunSSE() {
    if (eventSource) {
      try { eventSource.close(); } catch (_) {}
      eventSource = null;
    }
    if (sseReconnectTimeout) {
      clearTimeout(sseReconnectTimeout);
      sseReconnectTimeout = null;
    }
  }

  function connectRunSSE() {
    stopRunSSE();
    if (document.hidden) return;

    try {
      eventSource = new EventSource(`/api/ui/runs/${runId}/events`);
    } catch (_) {
      return;
    }

    eventSource.addEventListener('run_snapshot', (e) => {
      try {
        const data = JSON.parse(e.data);
        updateRunDetailDOM(data);
      } catch (err) {
        console.warn('Run snapshot parse error:', err);
      }
    });

    eventSource.addEventListener('run_progress', (e) => {
      try {
        const data = JSON.parse(e.data);
        updateRunDetailDOM(data);
      } catch (err) {
        console.warn('Run progress parse error:', err);
      }
    });

    eventSource.addEventListener('run_logs', (e) => {
      try {
        const logs = JSON.parse(e.data);
        appendTerminalLogs(logs, terminalViewport);
      } catch (err) {
        console.warn('Run logs parse error:', err);
      }
    });

    eventSource.addEventListener('run_completed', (e) => {
      try {
        const data = JSON.parse(e.data);
        showToast(window._t('run_completed_toast_prefix', 'Esecuzione terminata: ') + (data.status || window._t('status_completed', 'Completata')), 'info');
        stopRunSSE();
      } catch (err) {
        console.warn('Run completed parse error:', err);
      }
    });

    eventSource.onerror = () => {
      stopRunSSE();
      if (!document.hidden) {
        sseReconnectTimeout = setTimeout(connectRunSSE, 5000);
      }
    };
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stopRunSSE();
    } else {
      connectRunSSE();
    }
  });

  window.addEventListener('pagehide', stopRunSSE);
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      connectRunSSE();
    }
  });

  connectRunSSE();
}

function updateRunDetailDOM(data) {
  if (!data) return;
  if (data.throughput_display) {
    updateElementText('metric-throughput-val', data.throughput_display);
  }
  if (data.tasks_completed !== undefined && data.task_count_actual !== undefined) {
    updateElementText('metric-tasks-succeeded', `${data.tasks_completed} / ${data.task_count_actual}`);
  }
}

function appendTerminalLogs(logs, viewport) {
  if (!viewport || !logs || logs.length === 0) return;

  const isScrolledToBottom = (viewport.scrollHeight - viewport.clientHeight <= viewport.scrollTop + 30);

  logs.forEach((log) => {
    const row = document.createElement('div');
    row.className = `log-row ${log.level === 'error' ? 'is-error' : (log.level === 'warn' ? 'is-warn' : '')}`;
    const timeDisplay = formatUserDateTime(log.ts || log.created_at, 'time');
    row.innerHTML = `
      <span class="log-row-seq">#${log.seq}</span>
      <span class="log-row-time">${escapeHtml(timeDisplay)}</span>
      <span class="log-badge log-badge-${escapeHtml(log.level || 'info')}">${escapeHtml((log.level || 'info').toUpperCase())}</span>
      <span class="log-row-message">${escapeHtml(log.message || '')}</span>
    `;
    viewport.appendChild(row);
  });

  if (isScrolledToBottom) {
    viewport.scrollTop = viewport.scrollHeight;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// 3. Toast Notifications (Bottom-Right, 5s Auto-Close, Click-to-Dismiss)
function showToast(message, type = 'success') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const normalizedType = (type === 'danger' || type === 'error' || type === 'fail') ? 'error' : (type === 'warning' ? 'warning' : 'success');
  const toast = document.createElement('div');
  toast.className = `toast ${normalizedType}`;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'assertive');
  toast.setAttribute('title', window._t('toast_click_to_close', 'Premi col tasto sinistro per chiudere'));

  // SVG Icons: Checkmark for success, Alert for error/failure, Triangle for warning
  let iconHtml = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><polyline points="20 6 9 17 4 12"></polyline></svg>';
  if (normalizedType === 'error') {
    iconHtml = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
  } else if (normalizedType === 'warning') {
    iconHtml = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
  }

  const textDiv = document.createElement('div');
  textDiv.style.flex = '1';
  textDiv.style.lineHeight = '1.45';
  textDiv.style.wordBreak = 'break-word';
  textDiv.textContent = message;

  const closeBtn = document.createElement('span');
  closeBtn.style.fontSize = '1.25rem';
  closeBtn.style.lineHeight = '1';
  closeBtn.style.opacity = '0.55';
  closeBtn.style.marginLeft = '8px';
  closeBtn.style.flexShrink = '0';
  closeBtn.style.cursor = 'pointer';
  closeBtn.innerHTML = '&times;';

  toast.innerHTML = iconHtml;
  toast.appendChild(textDiv);
  toast.appendChild(closeBtn);

  container.appendChild(toast);

  let dismissed = false;
  function dismiss() {
    if (dismissed) return;
    dismissed = true;
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(40px)';
    toast.style.transition = 'all 0.28s cubic-bezier(0.16, 1, 0.3, 1)';
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 280);
  }

  // Left mouse button click manually closes the notification
  toast.addEventListener('click', (e) => {
    if (e.button === 0) {
      dismiss();
    }
  });

  // Automatically closes after 5 seconds (5000ms)
  setTimeout(dismiss, 5000);
}
window.showToast = showToast;

// Global modal helpers with mobile/Android back-button support
window.openModal = function(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('active');
    try {
      window.history.pushState({ modalOpen: modalId }, '', window.location.href);
    } catch (_) {}
  }
};

window.closeModal = function(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('active');
  }
};

window.closeAllModals = function() {
  document.querySelectorAll('.modal-backdrop.active').forEach((m) => {
    m.classList.remove('active');
  });
};

// Global confirmation modal helper (replaces browser confirm())
window.confirmAction = function({
  title = window._t("confirm_operation_title", "Conferma Operazione"),
  message = window._t("confirm_operation_default_msg", "Sei sicuro di voler procedere?"),
  subtext = "",
  confirmText = window._t("btn_confirm", "Conferma"),
  confirmClass = "btn-danger",
  onConfirm = null,
} = {}) {
  const modal = document.getElementById("app-confirm-modal");
  if (!modal) {
    if (window.confirm(message)) {
      if (typeof onConfirm === "function") onConfirm();
    }
    return;
  }
  const titleEl = document.getElementById("app-confirm-title");
  const msgEl = document.getElementById("app-confirm-message");
  const subEl = document.getElementById("app-confirm-subtext");
  const btnProceed = document.getElementById("app-confirm-btn-proceed");

  if (titleEl) titleEl.textContent = title;
  if (msgEl) msgEl.textContent = message;
  if (subEl) {
    subEl.textContent = subtext;
    subEl.style.display = subtext ? "block" : "none";
  }
  if (btnProceed) {
    btnProceed.textContent = confirmText;
    btnProceed.disabled = false;
    btnProceed.className = `btn ${confirmClass}`;
    if (confirmClass === "btn-danger") {
      btnProceed.style.background = "var(--color-danger, #ef4444)";
      btnProceed.style.color = "white";
    } else {
      btnProceed.style.background = "";
      btnProceed.style.color = "";
    }
    // Clone button to strip previous event listeners
    const newBtn = btnProceed.cloneNode(true);
    btnProceed.parentNode.replaceChild(newBtn, btnProceed);
    newBtn.addEventListener("click", async () => {
      newBtn.disabled = true;
      try {
        if (typeof onConfirm === "function") {
          await onConfirm();
        }
      } finally {
        window.closeModal("app-confirm-modal");
      }
    });
  }

  window.openModal("app-confirm-modal");
};

// Mobile Bottom Navigation Submenu Drawer helpers
window.toggleBottomNavSheet = function() {
  const sheet = document.getElementById('bottom-nav-sheet');
  const backdrop = document.getElementById('bottom-nav-sheet-backdrop');
  const btn = document.getElementById('bottom-nav-more');
  if (!sheet || !backdrop) return;
  const isOpen = sheet.classList.toggle('active');
  backdrop.classList.toggle('active', isOpen);
  if (btn) {
    btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    btn.classList.toggle('sheet-open', isOpen);
  }
};

window.closeBottomNavSheet = function() {
  const sheet = document.getElementById('bottom-nav-sheet');
  const backdrop = document.getElementById('bottom-nav-sheet-backdrop');
  const btn = document.getElementById('bottom-nav-more');
  if (sheet) sheet.classList.remove('active');
  if (backdrop) backdrop.classList.remove('active');
  if (btn) {
    btn.setAttribute('aria-expanded', 'false');
    btn.classList.remove('sheet-open');
  }
};

// Declarative modal trigger delegation (CSP-safe, no inline onclick needed)
document.addEventListener('click', (e) => {
  const openTrigger = e.target.closest('[data-open-modal]');
  if (openTrigger) {
    e.preventDefault();
    const modalId = openTrigger.getAttribute('data-open-modal');
    window.openModal(modalId);
    return;
  }

  const closeTrigger = e.target.closest('[data-close-modal]');
  if (closeTrigger) {
    e.preventDefault();
    const modalId = closeTrigger.getAttribute('data-close-modal');
    window.closeModal(modalId);
    return;
  }

  const reloadTrigger = e.target.closest('[data-action="reload"]');
  if (reloadTrigger) {
    e.preventDefault();
    window.location.reload();
    return;
  }

  // Clickable table rows navigation (CSP-safe delegation)
  const clickableRow = e.target.closest('.clickable-row');
  if (clickableRow && !e.target.closest('a, button, input, select, textarea')) {
    const href = clickableRow.getAttribute('data-href');
    if (href) {
      window.location.href = href;
    }
  }

  // Mobile Bottom Nav Submenu Toggle & Close
  const moreNavBtn = e.target.closest('#bottom-nav-more');
  if (moreNavBtn) {
    e.preventDefault();
    e.stopPropagation();
    window.toggleBottomNavSheet();
    return;
  }

  if (e.target.closest('#btn-close-bottom-sheet') || e.target.closest('#bottom-nav-sheet-backdrop')) {
    e.preventDefault();
    e.stopPropagation();
    window.closeBottomNavSheet();
    return;
  }

  // Backdrop click to close
  if (e.target.classList && e.target.classList.contains('modal-backdrop')) {
    e.target.classList.remove('active');
  }

  // User Profile Dropdown Toggle
  const toggleBtn = e.target.closest('#btn-user-menu-toggle');
  const dropdownWrapper = document.getElementById('user-dropdown-wrapper');
  if (toggleBtn && dropdownWrapper) {
    e.preventDefault();
    e.stopPropagation();
    const isOpen = dropdownWrapper.classList.toggle('active');
    toggleBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    // Close lang dropdown if open
    const langWrapper = document.getElementById('lang-dropdown-wrapper');
    if (langWrapper) langWrapper.classList.remove('active');
    return;
  }

  // Language Dropdown Toggle
  const langToggleBtn = e.target.closest('#btn-lang-dropdown-toggle');
  const langDropdownWrapper = document.getElementById('lang-dropdown-wrapper');
  if (langToggleBtn && langDropdownWrapper) {
    e.preventDefault();
    e.stopPropagation();
    const isOpen = langDropdownWrapper.classList.toggle('active');
    langToggleBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    // Close user dropdown if open
    if (dropdownWrapper) dropdownWrapper.classList.remove('active');
    return;
  }

  // Close Dropdowns when clicking outside
  if (dropdownWrapper && dropdownWrapper.classList.contains('active')) {
    if (!e.target.closest('#user-dropdown-wrapper')) {
      dropdownWrapper.classList.remove('active');
      const btn = document.getElementById('btn-user-menu-toggle');
      if (btn) btn.setAttribute('aria-expanded', 'false');
    }
  }

  if (langDropdownWrapper && langDropdownWrapper.classList.contains('active')) {
    if (!e.target.closest('#lang-dropdown-wrapper')) {
      langDropdownWrapper.classList.remove('active');
      const btn = document.getElementById('btn-lang-dropdown-toggle');
      if (btn) btn.setAttribute('aria-expanded', 'false');
    }
  }
});

// Escape key to close active modal or dropdown
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    window.closeAllModals();
    window.closeBottomNavSheet();

    const activeDropdown = document.querySelector('#user-dropdown-wrapper.active');
    if (activeDropdown) {
      activeDropdown.classList.remove('active');
      const btn = document.getElementById('btn-user-menu-toggle');
      if (btn) btn.setAttribute('aria-expanded', 'false');
    }

    const activeLangDropdown = document.querySelector('#lang-dropdown-wrapper.active');
    if (activeLangDropdown) {
      activeLangDropdown.classList.remove('active');
      const btn = document.getElementById('btn-lang-dropdown-toggle');
      if (btn) btn.setAttribute('aria-expanded', 'false');
    }
  }
});

// Mobile/Android hardware & browser Back Button (popstate):
// If a modal or dropdown is open when the user presses Back, close it smoothly
window.addEventListener('popstate', (e) => {
  window.closeBottomNavSheet();

  const openModal = document.querySelector('.modal-backdrop.active');
  if (openModal) {
    openModal.classList.remove('active');
  }

  const activeDropdown = document.querySelector('#user-dropdown-wrapper.active');
  if (activeDropdown) {
    activeDropdown.classList.remove('active');
  }

  const activeLangDropdown = document.querySelector('#lang-dropdown-wrapper.active');
  if (activeLangDropdown) {
    activeLangDropdown.classList.remove('active');
  }
});

// Chrome Android Back-Forward Cache (bfcache) restore handler:
// Cleans up any stuck modal backdrops, dropdowns, and re-enables buttons left in pending state
window.addEventListener('pageshow', (event) => {
  window.closeAllModals();
  window.closeBottomNavSheet();

  document.querySelectorAll('#user-dropdown-wrapper.active, #lang-dropdown-wrapper.active').forEach((el) => {
    el.classList.remove('active');
  });

  // Re-enable any form submit/action buttons that might have been disabled before navigation/reload
  document.querySelectorAll('button[type="submit"]:disabled, .btn:disabled').forEach((btn) => {
    // Only re-enable if it does not have a permanently disabled rule (like disabled-by-role)
    if (!btn.hasAttribute('data-permanently-disabled')) {
      btn.disabled = false;
    }
  });
});



// EmberXP Theme Windows XP Taskbar & Start Menu
function initEmberXPTaskbar() {
  const startBtn = document.getElementById('xp-start-btn');
  const startMenu = document.getElementById('xp-start-menu');
  const clockEl = document.getElementById('xp-tray-clock');

  function updateClock() {
    if (!clockEl) return;
    const now = new Date();
    let hours = now.getHours();
    let minutes = now.getMinutes();
    const ampm = hours >= 12 ? 'PM' : 'AM';
    const h12 = hours % 12 || 12;
    const mStr = minutes < 10 ? '0' + minutes : String(minutes);
    clockEl.textContent = `${h12}:${mStr} ${ampm}`;
  }

  if (clockEl) {
    updateClock();
    setInterval(updateClock, 15000);
  }

  if (startBtn && startMenu) {
    startBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isActive = startMenu.classList.toggle('active');
      startBtn.setAttribute('aria-expanded', String(isActive));
      startBtn.classList.toggle('active', isActive);
    });

    document.addEventListener('click', (e) => {
      if (!startMenu.contains(e.target) && !startBtn.contains(e.target)) {
        if (startMenu.classList.contains('active')) {
          startMenu.classList.remove('active');
          startBtn.setAttribute('aria-expanded', 'false');
          startBtn.classList.remove('active');
        }
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && startMenu.classList.contains('active')) {
        startMenu.classList.remove('active');
        startBtn.setAttribute('aria-expanded', 'false');
        startBtn.classList.remove('active');
      }
    });

    window.addEventListener('resize', () => {
      if (window.innerWidth <= 1024 && startMenu.classList.contains('active')) {
        startMenu.classList.remove('active');
        startBtn.setAttribute('aria-expanded', 'false');
        startBtn.classList.remove('active');
      }
    });
  }
}
