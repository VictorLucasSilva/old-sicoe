// Botão Confirmar (spinner lock) – PDE
(function (window, document) {
    function setLoading(btn, isLoading) {
        const spinner = btn.querySelector('[data-spinner]');
        const label = btn.querySelector('[data-label]');
        if (isLoading) {
            btn.setAttribute('aria-busy', 'true');
            btn.disabled = true;
            if (spinner) spinner.classList.remove('d-none');
            if (label) label.classList.add('visually-hidden');
        } else {
            btn.removeAttribute('aria-busy');
            btn.disabled = false;
            if (spinner) spinner.classList.add('d-none');
            if (label) label.classList.remove('visually-hidden');
        }
    }

    function handleClick(ev) {
        const btn = ev.currentTarget;
        const formSelector = btn.getAttribute('data-target-form') || 'form';
        const form = document.querySelector(formSelector) || btn.closest('form');
        if (!form) {
            console.warn('[confirm-button] Formulário não encontrado para', formSelector);
            return;
        }

        // Caso o template use validação nativa do browser:
        if (typeof form.reportValidity === 'function' && !form.reportValidity()) {
            return; // não envia se inválido
        }

        setLoading(btn, true);

        // Envio padrão (síncrono). A navegação interrompe a necessidade de reverter o estado.
        form.submit();
    }

    function init(scope) {
        (scope || document).querySelectorAll('[data-confirm-submit]').forEach(btn => {
            if (btn.__confirmBound) return; // evita bind duplicado
            btn.__confirmBound = true;
            btn.addEventListener('click', handleClick);
        });
    }

    // API pública: útil para cenários AJAX, onde você decide quando destravar
    window.ConfirmButton = { init, setLoading };
    document.addEventListener('DOMContentLoaded', () => init());
})(window, document);