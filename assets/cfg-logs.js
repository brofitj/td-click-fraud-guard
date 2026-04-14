(function () {
    function onCopyClick(e) {
        var btn = e.target.closest('.cfg-copy-ip');
        if (!btn) return;
        e.preventDefault();
        var ip = btn.getAttribute('data-ip') || '';
        if (!ip) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(ip).then(function () {
                var icon = btn.querySelector('.dashicons');
                if (!icon) return;
                icon.classList.remove('dashicons-admin-page');
                icon.classList.add('dashicons-yes');
                setTimeout(function () {
                    icon.classList.remove('dashicons-yes');
                    icon.classList.add('dashicons-admin-page');
                }, 1200);
            });
        }
    }
    document.addEventListener('click', onCopyClick);
})();
