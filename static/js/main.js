/**
 * ZERO//TRUST Core Frontend JavaScript
 * Theme management, mobile navigation, modals, and notifications
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initMobileNav();
  initModals();
});

function initTheme() {
  const themeToggle = document.getElementById('theme-toggle-btn');
  const savedTheme = localStorage.getItem('zt-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('zt-theme', next);
    });
  }
}

function initMobileNav() {
  const toggleBtn = document.getElementById('mobile-menu-toggle');
  const sidebar = document.querySelector('.app-sidebar');
  
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('mobile-open');
    });

    // Close sidebar on outside click on mobile
    document.addEventListener('click', (e) => {
      if (sidebar.classList.contains('mobile-open') && 
          !sidebar.contains(e.target) && 
          !toggleBtn.contains(e.target)) {
        sidebar.classList.remove('mobile-open');
      }
    });
  }
}

function initModals() {
  // Close buttons
  document.querySelectorAll('.zt-modal-close, [data-modal-close]').forEach(btn => {
    btn.addEventListener('click', () => {
      const modal = btn.closest('.zt-modal-backdrop');
      if (modal) modal.classList.remove('active');
    });
  });

  // Light dismiss on backdrop click
  document.querySelectorAll('.zt-modal-backdrop').forEach(backdrop => {
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) {
        backdrop.classList.remove('active');
      }
    });
  });
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container') || document.body;
  const toast = document.createElement('div');
  toast.className = `flash-alert flash-${type}`;
  toast.style.position = 'fixed';
  toast.style.bottom = '20px';
  toast.style.right = '20px';
  toast.style.zIndex = '9999';
  toast.style.minWidth = '280px';
  toast.style.boxShadow = 'var(--shadow-lg)';
  toast.innerHTML = `<span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}
