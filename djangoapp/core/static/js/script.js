
(() => {
  const sidebar  = document.getElementById('sidebar');
  const toggleBtn = document.querySelector('.toggle-btn');

  function closeAllCollapses() {
    document.querySelectorAll('#sidebar .collapse.show').forEach(el => {
      const inst = bootstrap.Collapse.getOrCreateInstance(el, { toggle: false });
      inst.hide();
    });
  }

  toggleBtn?.addEventListener('click', () => {
    sidebar.classList.toggle('expand');
    if (!sidebar.classList.contains('expand')) {
      closeAllCollapses();
    }
  });

  function setupHoverCollapsed(link) {
    const targetId = link.getAttribute('data-bs-target');
    if (!targetId) return;
    const target = document.querySelector(targetId);
    if (!target) return;

    let hideTimer;

    const open = () => {
      if (sidebar.classList.contains('expand')) return; 
      clearTimeout(hideTimer);
      const inst = bootstrap.Collapse.getOrCreateInstance(target, { toggle: false });
      inst.show();
    };

    const closeIfOutside = () => {
      if (sidebar.classList.contains('expand')) return;
      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => {
        const hovering = link.matches(':hover') || target.matches(':hover');
        if (!hovering) {
          const inst = bootstrap.Collapse.getOrCreateInstance(target, { toggle: false });
          inst.hide();
        }
      }, 120);
    };

    link.addEventListener('mouseenter', open);
    link.addEventListener('mouseleave', closeIfOutside);
    target.addEventListener('mouseenter', open);
    target.addEventListener('mouseleave', closeIfOutside);
  }

  function enableClickWhenExpanded(link) {
    const targetId = link.getAttribute('data-bs-target');
    const isHashOnly = (link.getAttribute('href') || '#') === '#';

    link.addEventListener('click', (e) => {
      const isExpandedSidebar = sidebar.classList.contains('expand');
      const isDropdown = link.classList.contains('has-dropdown');

      if (isExpandedSidebar && (isDropdown || isHashOnly)) {
        e.preventDefault();
        e.stopPropagation();
        if (typeof e.stopImmediatePropagation === 'function') e.stopImmediatePropagation();

        if (targetId) {
          const target = document.querySelector(targetId);
          if (target) {
            const inst = bootstrap.Collapse.getOrCreateInstance(target, { toggle: false });
            inst.toggle();
          }
        }
      }
    });
  }

  // ----- BLOQUEIA CLICK quando a barra está COLAPSADA (hover já resolve o flyout) -----
  function blockClickWhenCollapsed(link) {
    link.addEventListener('click', (e) => {
      const isCollapsed = !sidebar.classList.contains('expand');
      const isHashOnly = (link.getAttribute('href') || '#') === '#';
      if (isCollapsed && (isHashOnly || link.classList.contains('has-dropdown'))) {
        e.preventDefault();
        e.stopPropagation();
      }
    });
  }

  // Ativa para todos os links com submenu
  document.querySelectorAll('#sidebar a.sidebar-link.has-dropdown').forEach(link => {
    setupHoverCollapsed(link);      // hover SÓ quando colapsada
    enableClickWhenExpanded(link);  // click quando expandida
    blockClickWhenCollapsed(link);  // sem click quando colapsada
  });

  // Clicar fora fecha submenus (quando expandida)
  document.addEventListener('click', (e) => {
    const inside = e.target.closest('#sidebar');
    if (!inside && sidebar.classList.contains('expand')) {
      closeAllCollapses();
    }
  });

  // ESC fecha submenus (quando expandida)
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && sidebar.classList.contains('expand')) {
      closeAllCollapses();
    }
  });
})();
