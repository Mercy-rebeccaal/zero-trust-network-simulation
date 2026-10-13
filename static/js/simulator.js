/**
 * ZERO//TRUST Access Request Simulator
 * Dynamic trust evaluation, SVG circular gauge animation, and Step-2 MFA challenge
 */

let activeRequestUuid = null;

document.addEventListener('DOMContentLoaded', () => {
  const simForm = document.getElementById('accessSimulatorForm');
  if (simForm) {
    simForm.addEventListener('submit', handleSimulatorSubmit);
  }

  const mfaForm = document.getElementById('mfaVerificationForm');
  if (mfaForm) {
    mfaForm.addEventListener('submit', handleMfaSubmit);
  }

  const btnOpenMfa = document.getElementById('btn-open-mfa-modal');
  if (btnOpenMfa) {
    btnOpenMfa.addEventListener('click', () => {
      const modal = document.getElementById('mfaModal');
      if (modal) modal.classList.add('active');
    });
  }
});

async function handleSimulatorSubmit(e) {
  e.preventDefault();
  const form = e.target;
  const submitBtn = form.querySelector('button[type="submit"]');
  
  submitBtn.disabled = true;
  submitBtn.innerText = 'Evaluating Continuous Trust...';

  const formData = new FormData(form);
  const payload = Object.fromEntries(formData.entries());

  try {
    const res = await fetch('/api/access/evaluate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': payload.csrf_token || ''
      },
      body: JSON.stringify(payload)
    });

    const result = await res.json();
    if (result.success) {
      renderEvaluationResult(result);
      showToast("Access evaluated successfully", "success");
    } else {
      showToast(result.error || "Evaluation failed", "danger");
    }
  } catch (err) {
    console.error("Evaluation error:", err);
    showToast("Network error during evaluation", "danger");
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerText = 'Run Access Evaluation';
  }
}

function renderEvaluationResult(data) {
  activeRequestUuid = data.request_uuid;

  // 1. Animate SVG Radial Gauge
  const score = data.trust_score;
  const gaugeProgress = document.getElementById('gaugeCircleProgress');
  const scoreValueEl = document.getElementById('gaugeScoreValue');
  
  if (gaugeProgress && scoreValueEl) {
    const circumference = 565.48; // 2 * PI * 90
    const offset = circumference - (score / 100 * circumference);
    gaugeProgress.style.strokeDashoffset = offset;

    // Set Gauge color
    if (score > 80.0) {
      gaugeProgress.style.stroke = 'var(--primary-teal)';
    } else if (score >= 60.0) {
      gaugeProgress.style.stroke = 'var(--warning-amber)';
    } else {
      gaugeProgress.style.stroke = 'var(--critical-coral)';
    }

    // Number counter animation
    animateScoreCounter(scoreValueEl, score);
  }

  // 2. Decision Outcome Box
  const decisionBox = document.getElementById('decisionOutcomeBox');
  const decisionTitle = document.getElementById('decisionHeadline');
  const decisionReason = document.getElementById('decisionReasonText');
  const requestIdText = document.getElementById('decisionRequestId');
  const mfaPromptBtn = document.getElementById('btn-open-mfa-modal');

  if (decisionBox && decisionTitle && decisionReason) {
    decisionBox.className = `decision-outcome-box ${data.decision}`;
    decisionTitle.innerText = `DECISION: ${data.decision.replace('_', ' ')}`;
    decisionReason.innerText = data.decision_reason;
    if (requestIdText) requestIdText.innerText = `ID: ${data.request_uuid}`;

    // Show/hide MFA action button
    if (mfaPromptBtn) {
      if (data.decision === 'ADDITIONAL_VERIFICATION') {
        mfaPromptBtn.style.display = 'inline-flex';
      } else {
        mfaPromptBtn.style.display = 'none';
      }
    }
  }

  // 3. Factor Breakdown Progress Bars
  if (data.factor_scores) {
    for (const [factor, val] of Object.entries(data.factor_scores)) {
      const fillEl = document.getElementById(`factor-fill-${factor}`);
      const valEl = document.getElementById(`factor-val-${factor}`);
      if (fillEl) fillEl.style.width = `${val}%`;
      if (valEl) valEl.innerText = `${val.toFixed(1)}/100`;
    }
  }
}

function animateScoreCounter(element, targetScore) {
  let current = 0;
  const duration = 800; // ms
  const stepTime = 16;
  const steps = duration / stepTime;
  const increment = targetScore / steps;

  const timer = setInterval(() => {
    current += increment;
    if (current >= targetScore) {
      element.innerText = targetScore.toFixed(2);
      clearInterval(timer);
    } else {
      element.innerText = current.toFixed(2);
    }
  }, stepTime);
}

async function handleMfaSubmit(e) {
  e.preventDefault();
  if (!activeRequestUuid) {
    showToast("No active request awaiting verification", "danger");
    return;
  }

  const otpInput = document.getElementById('mfaOtpCode');
  const otpCode = otpInput ? otpInput.value.trim() : '';

  try {
    const res = await fetch('/api/access/verify-mfa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        request_uuid: activeRequestUuid,
        otp_code: otpCode
      })
    });

    const result = await res.json();
    if (result.success) {
      // Close modal
      const modal = document.getElementById('mfaModal');
      if (modal) modal.classList.remove('active');

      // Update decision box to ALLOW
      const decisionBox = document.getElementById('decisionOutcomeBox');
      const decisionTitle = document.getElementById('decisionHeadline');
      const decisionReason = document.getElementById('decisionReasonText');
      const mfaPromptBtn = document.getElementById('btn-open-mfa-modal');

      if (decisionBox) {
        decisionBox.className = 'decision-outcome-box ALLOW';
        decisionTitle.innerText = 'DECISION: ALLOW';
        decisionReason.innerText = result.message;
        if (mfaPromptBtn) mfaPromptBtn.style.display = 'none';
      }

      showToast("Secondary Step-Up MFA verified. Access Granted!", "success");
    } else {
      showToast(result.error || "Invalid OTP code", "danger");
    }
  } catch (err) {
    console.error("MFA error:", err);
    showToast("Error processing verification", "danger");
  }
}
