/**
 * ZERO//TRUST Network Topology & Micro-Segmentation Simulation
 * Interactive SVG node flows, packet traversal animations, and lateral movement blocks
 */

document.addEventListener('DOMContentLoaded', () => {
  const btnSimPacket = document.getElementById('btn-simulate-packet');
  if (btnSimPacket) {
    btnSimPacket.addEventListener('click', runPacketSimulation);
  }

  initNodeTooltips();
});

function initNodeTooltips() {
  const tooltip = document.getElementById('topoTooltip');
  if (!tooltip) return;

  document.querySelectorAll('.topo-node').forEach(node => {
    node.addEventListener('mouseenter', (e) => {
      const title = node.getAttribute('data-title') || 'Security Component';
      const detail = node.getAttribute('data-detail') || 'Zero Trust Node';
      const subnet = node.getAttribute('data-subnet') || '';

      tooltip.innerHTML = `
        <strong>${title}</strong>
        ${subnet ? `<div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--primary-teal); margin-top:2px;">${subnet}</div>` : ''}
        <div style="margin-top: 4px; color: var(--text-secondary);">${detail}</div>
      `;
      tooltip.style.display = 'block';
    });

    node.addEventListener('mousemove', (e) => {
      const containerRect = document.querySelector('.topology-container').getBoundingClientRect();
      tooltip.style.left = `${e.clientX - containerRect.left + 15}px`;
      tooltip.style.top = `${e.clientY - containerRect.top + 15}px`;
    });

    node.addEventListener('mouseleave', () => {
      tooltip.style.display = 'none';
    });
  });
}

function runPacketSimulation() {
  const roleSelect = document.getElementById('sim-topo-role');
  const targetSelect = document.getElementById('sim-topo-target');
  const statusEl = document.getElementById('topo-sim-status');

  const role = roleSelect ? roleSelect.value : 'Employee';
  const target = targetSelect ? targetSelect.value : 'SERVER';

  // Reset all links & node states
  document.querySelectorAll('.topo-link').forEach(link => {
    link.classList.remove('active-flow', 'blocked-flow');
  });
  document.querySelectorAll('.topo-node').forEach(n => {
    n.classList.remove('active', 'blocked');
  });

  if (statusEl) {
    statusEl.innerText = `Transmitting verification packet: [Role: ${role}] -> [Resource: ${target}]...`;
    statusEl.style.color = 'var(--ice-blue)';
  }

  // Step 1: User Identity to Auth Gateway
  highlightStep('link-user-auth', 'node-auth', 300);

  // Step 2: Auth Gateway to RBAC Gate
  setTimeout(() => {
    highlightStep('link-auth-rbac', 'node-rbac', 400);

    // Evaluate RBAC for this packet
    setTimeout(() => {
      if (role === 'Employee' && (target === 'SERVER' || target === 'FINANCE')) {
        // RBAC Block!
        blockAtNode('node-rbac', 'link-rbac-iacte');
        if (statusEl) {
          statusEl.innerText = `BLOCKED AT RBAC GATE: Role '${role}' has no permission for '${target}'. Lateral movement prevented!`;
          statusEl.style.color = 'var(--critical-coral)';
        }
        showToast(`Access Denied: Lateral movement to ${target} blocked by RBAC`, 'danger');
      } else {
        // RBAC Passes -> Proceed to IACTE
        highlightStep('link-rbac-iacte', 'node-iacte', 400);

        setTimeout(() => {
          // IACTE to Decision Matrix
          highlightStep('link-iacte-decision', 'node-decision', 400);

          setTimeout(() => {
            // Decision Matrix to Target Segment Link
            const targetLinkId = `link-decision-${target.toLowerCase()}`;
            const targetNodeId = `node-res-${target.toLowerCase()}`;
            
            highlightStep(targetLinkId, targetNodeId, 500);

            if (statusEl) {
              statusEl.innerText = `ACCESS GRANTED: Continuous trust verified. Least-privilege session connected to ${target} subnet.`;
              statusEl.style.color = 'var(--electric-mint)';
            }
            showToast(`Continuous Trust verified. Access established to ${target}`, 'success');
          }, 500);
        }, 500);
      }
    }, 400);
  }, 400);
}

function highlightStep(linkId, nodeId, duration) {
  const link = document.getElementById(linkId);
  const node = document.getElementById(nodeId);

  if (link) link.classList.add('active-flow');
  if (node) node.classList.add('active');
}

function blockAtNode(nodeId, nextLinkId) {
  const node = document.getElementById(nodeId);
  if (node) node.classList.add('blocked');
}
