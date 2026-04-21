(function () {
    function getGclid() {
        var params = new URLSearchParams(window.location.search);
        return params.get('gclid') || '';
    }

    function sendLog() {
        if (typeof CFG_LOG === 'undefined' || !CFG_LOG.ajaxUrl) {
            return;
        }
        var gclid = getGclid();
        if (!gclid) {
            return;
        }

        var data = new URLSearchParams();
        data.append('action', 'cfg_log_click');
        data.append('gclid', gclid);
        data.append('url', window.location.href);
        data.append('referrer', document.referrer || '');
        if (CFG_LOG.nonce) {
            data.append('nonce', CFG_LOG.nonce);
        }

        var payload = data.toString();

        if (navigator.sendBeacon) {
            var blob = new Blob([payload], { type: 'application/x-www-form-urlencoded; charset=UTF-8' });
            navigator.sendBeacon(CFG_LOG.ajaxUrl, blob);
            return;
        }

        fetch(CFG_LOG.ajaxUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
            body: payload,
            keepalive: true,
        }).catch(function () {});
    }

    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        sendLog();
    } else {
        document.addEventListener('DOMContentLoaded', sendLog);
    }
})();
