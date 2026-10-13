/**
 * ZERO//TRUST Security Dashboard Visualizations
 * Chart.js Integration for Real-time Trust Timeline, Decisions, and Factors
 */

let timelineChart = null;
let decisionChart = null;
let resourceChart = null;
let factorChart = null;

document.addEventListener('DOMContentLoaded', () => {
  initDashboardCharts();
  
  const refreshBtn = document.getElementById('btn-refresh-dashboard');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      refreshBtn.disabled = true;
      refreshBtn.innerText = 'Refreshing...';
      refreshDashboardData().finally(() => {
        refreshBtn.disabled = false;
        refreshBtn.innerText = 'Refresh Feed';
      });
    });
  }
});

function initDashboardCharts() {
  const chartTextColor = '#98A7BE';
  const chartGridColor = 'rgba(40, 54, 77, 0.5)';
  
  // 1. Trust Timeline Line Chart
  const ctxTimeline = document.getElementById('trustTimelineCanvas');
  if (ctxTimeline && window.timelineData) {
    timelineChart = new Chart(ctxTimeline, {
      type: 'line',
      data: {
        labels: window.timelineData.labels || [],
        datasets: [{
          label: 'Continuous Trust Score',
          data: window.timelineData.scores || [],
          borderColor: '#14B8A6',
          backgroundColor: 'rgba(20, 184, 166, 0.1)',
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointBackgroundColor: '#6EE7C8',
          pointBorderColor: '#0B1020',
          pointRadius: 4,
          pointHoverRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            min: 0,
            max: 100,
            grid: { color: chartGridColor },
            ticks: { color: chartTextColor }
          },
          x: {
            grid: { color: chartGridColor },
            ticks: { color: chartTextColor }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#172238',
            titleColor: '#E8EEF8',
            bodyColor: '#6EE7C8',
            borderColor: '#28364D',
            borderWidth: 1
          }
        }
      }
    });
  }

  // 2. Decision Distribution Doughnut Chart
  const ctxDecision = document.getElementById('decisionDistCanvas');
  if (ctxDecision && window.distributionData) {
    decisionChart = new Chart(ctxDecision, {
      type: 'doughnut',
      data: {
        labels: window.distributionData.labels || ['Allowed', 'Verification', 'Restricted', 'Blocked'],
        datasets: [{
          data: window.distributionData.counts || [0, 0, 0, 0],
          backgroundColor: window.distributionData.colors || ['#14B8A6', '#F5B942', '#73BFFF', '#FB7185'],
          borderColor: '#111A2E',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: chartTextColor, boxWidth: 12, padding: 12 }
          }
        },
        cutout: '68%'
      }
    });
  }

  // 3. Resource Activity Bar Chart
  const ctxResource = document.getElementById('resourceTrafficCanvas');
  if (ctxResource && window.resourceData) {
    resourceChart = new Chart(ctxResource, {
      type: 'bar',
      data: {
        labels: window.resourceData.labels || [],
        datasets: [{
          label: 'Requests',
          data: window.resourceData.counts || [],
          backgroundColor: '#73BFFF',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            grid: { color: chartGridColor },
            ticks: { color: chartTextColor, precision: 0 }
          },
          x: {
            grid: { display: false },
            ticks: { color: chartTextColor }
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  // 4. IACTE Factor Radar Chart
  const ctxFactor = document.getElementById('factorRadarCanvas');
  if (ctxFactor && window.factorData) {
    factorChart = new Chart(ctxFactor, {
      type: 'radar',
      data: {
        labels: window.factorData.labels || [],
        datasets: [{
          label: 'Average Score',
          data: window.factorData.scores || [],
          borderColor: '#14B8A6',
          backgroundColor: 'rgba(20, 184, 166, 0.25)',
          pointBackgroundColor: '#6EE7C8',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            min: 0,
            max: 100,
            angleLines: { color: chartGridColor },
            grid: { color: chartGridColor },
            pointLabels: { color: chartTextColor, font: { size: 10 } },
            ticks: { display: false, maxTicksLimit: 5 }
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  }
}

async function refreshDashboardData() {
  try {
    const [summaryRes, distRes, timeRes, facRes] = await Promise.all([
      fetch('/api/dashboard/summary').then(r => r.json()),
      fetch('/api/dashboard/distribution').then(r => r.json()),
      fetch('/api/dashboard/timeline').then(r => r.json()),
      fetch('/api/dashboard/factors').then(r => r.json())
    ]);

    if (summaryRes.success) {
      const d = summaryRes.data;
      if (document.getElementById('metric-total-requests')) document.getElementById('metric-total-requests').innerText = d.total_requests;
      if (document.getElementById('metric-allowed-count')) document.getElementById('metric-allowed-count').innerText = d.allowed_count;
      if (document.getElementById('metric-blocked-count')) document.getElementById('metric-blocked-count').innerText = d.blocked_count;
      if (document.getElementById('metric-avg-score')) document.getElementById('metric-avg-score').innerText = d.avg_trust_score.toFixed(2);
    }

    if (distRes.success && decisionChart) {
      decisionChart.data.datasets[0].data = distRes.data.counts;
      decisionChart.update();
    }

    if (timeRes.success && timelineChart) {
      timelineChart.data.labels = timeRes.data.labels;
      timelineChart.data.datasets[0].data = timeRes.data.scores;
      timelineChart.update();
    }

    if (facRes.success && factorChart) {
      factorChart.data.datasets[0].data = facRes.data.scores;
      factorChart.update();
    }

    showToast("Dashboard metrics refreshed successfully", "success");
  } catch (err) {
    console.error("Dashboard refresh error:", err);
    showToast("Failed to refresh dashboard data", "danger");
  }
}
