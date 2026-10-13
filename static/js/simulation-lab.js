/**
 * ZERO//TRUST Attack and Threat Simulation Lab JavaScript
 */

document.addEventListener('DOMContentLoaded', () => {
  // Bind single scenario run buttons
  document.querySelectorAll('.btn-run-scenario').forEach(btn => {
    btn.addEventListener('click', () => {
      const scenarioId = btn.getAttribute('data-scenario-id');
      runSingleScenario(scenarioId, btn);
    });
  });

  // Bind Run Suite button
  const btnRunSuite = document.getElementById('btn-run-suite');
  if (btnRunSuite) {
    btnRunSuite.addEventListener('click', runScenarioSuite);
  }

  // Bind Reset button
  const btnReset = document.getElementById('btn-reset-simulations');
  if (btnReset) {
    btnReset.addEventListener('click', resetSimulationRuns);
  }
});

async function runSingleScenario(scenarioId, btnEl) {
  if (btnEl) {
    btnEl.disabled = true;
    btnEl.innerText = 'Simulating...';
  }

  try {
    const res = await fetch('/api/simulations/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario_id: scenarioId })
    });

    const data = await res.json();
    if (data.success) {
      updateScenarioCard(scenarioId, data);
      showToast(`Scenario ${data.scenario.code} completed: ${data.actual_decision}`, 'info');
    } else {
      showToast(data.error || "Scenario execution failed", "danger");
    }
  } catch (err) {
    console.error("Scenario execution error:", err);
    showToast("Network error executing scenario", "danger");
  } finally {
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.innerText = 'Run Test';
    }
  }
}

async function runScenarioSuite() {
  const btn = document.getElementById('btn-run-suite');
  if (btn) {
    btn.disabled = true;
    btn.innerText = 'Executing 10-Scenario Suite...';
  }

  try {
    const res = await fetch('/api/simulations/run-suite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    const data = await res.json();
    if (data.success) {
      // Update aggregate stat counters
      const passRateEl = document.getElementById('suite-pass-rate');
      const passedCountEl = document.getElementById('suite-passed-count');
      const totalCountEl = document.getElementById('suite-total-count');
      const totalTimeEl = document.getElementById('suite-total-time');

      if (passRateEl) passRateEl.innerText = `${data.pass_rate}%`;
      if (passedCountEl) passedCountEl.innerText = `${data.passed_count}/${data.total_scenarios}`;
      if (totalCountEl) totalCountEl.innerText = data.total_scenarios;
      if (totalTimeEl) totalTimeEl.innerText = `${data.total_execution_time_ms} ms`;

      // Update each scenario card
      if (data.results) {
        data.results.forEach(resItem => {
          updateScenarioCard(resItem.scenario.id, resItem);
        });
      }

      showToast(`Scenario Suite Complete! ${data.passed_count} of ${data.total_scenarios} passed security expectations.`, "success");
    } else {
      showToast("Suite execution encountered an error", "danger");
    }
  } catch (err) {
    console.error("Suite error:", err);
    showToast("Network error executing suite", "danger");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = 'Run Full Scenario Suite';
    }
  }
}

function updateScenarioCard(scenarioId, result) {
  const card = document.getElementById(`scenario-card-${scenarioId}`);
  if (!card) return;

  const resultStatus = card.querySelector('.scenario-result-status');
  const resultDetails = card.querySelector('.scenario-result-details');

  if (resultStatus) {
    if (result.passed_expectation) {
      resultStatus.className = 'scenario-result-status badge-zt badge-allow';
      resultStatus.innerHTML = `&#10003; PASS (Observed: ${result.actual_decision})`;
    } else {
      resultStatus.className = 'scenario-result-status badge-zt badge-block';
      resultStatus.innerHTML = `&#10007; FAIL (Observed: ${result.actual_decision})`;
    }
  }

  if (resultDetails) {
    resultDetails.style.display = 'block';
    resultDetails.innerHTML = `
      <div style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 0.5rem; border-top: 1px solid var(--border-subtle); padding-top: 0.5rem;">
        <div><strong>Trust Score:</strong> <span style="font-family: var(--font-mono); color: var(--primary-teal);">${result.trust_score.toFixed(2)}</span> &bull; <strong>Latency:</strong> ${result.execution_time_ms.toFixed(1)}ms</div>
        <div style="margin-top: 2px;"><strong>Outcome:</strong> ${result.eval_details ? result.eval_details.decision_reason : result.actual_decision}</div>
      </div>
    `;
  }
}

async function resetSimulationRuns() {
  if (!confirm("Are you sure you want to reset simulation test runs? Baseline audit logs and policies will not be deleted.")) {
    return;
  }

  try {
    const res = await fetch('/api/simulations/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    const data = await res.json();
    if (data.success) {
      document.querySelectorAll('.scenario-result-status').forEach(el => {
        el.className = 'scenario-result-status badge-zt badge-info';
        el.innerText = 'UNTESTED';
      });
      document.querySelectorAll('.scenario-result-details').forEach(el => {
        el.style.display = 'none';
        el.innerHTML = '';
      });

      const passRateEl = document.getElementById('suite-pass-rate');
      if (passRateEl) passRateEl.innerText = '--%';

      showToast("Simulation run history cleared", "info");
    }
  } catch (err) {
    console.error("Reset error:", err);
    showToast("Failed to reset simulations", "danger");
  }
}
