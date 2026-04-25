// Live tail page client. EventSource attached to /live/stream with
// filter query params. The server emits two event types:
//
//   - default ("event"): one OCSF envelope, JSON payload.
//   - "drops": current per-connection drop count.
//
// Filter changes close the existing connection and reopen with new
// query params. Pause closes; Resume reopens.

(function () {
    const status = document.getElementById('status');
    const out = document.getElementById('events');
    const dropsEl = document.getElementById('drops');
    const filterHost = document.getElementById('filter-host');
    const filterClass = document.getElementById('filter-class');
    const filterText = document.getElementById('filter-text');
    const apply = document.getElementById('apply');
    const pause = document.getElementById('pause');

    let es = null;
    let paused = false;
    const MAX_LINES = 500;

    function setStatus(s) {
        status.textContent = s;
    }

    function buildURL() {
        const u = new URL('/live/stream', window.location.origin);
        if (filterHost.value.trim()) u.searchParams.set('host_id', filterHost.value.trim());
        if (filterClass.value.trim()) u.searchParams.set('class_uid', filterClass.value.trim());
        if (filterText.value.trim()) u.searchParams.set('contains', filterText.value.trim());
        return u.toString();
    }

    function appendLine(line) {
        const lines = out.textContent.split('\n');
        lines.push(line);
        if (lines.length > MAX_LINES) lines.splice(0, lines.length - MAX_LINES);
        out.textContent = lines.join('\n');
        out.scrollTop = out.scrollHeight;
    }

    function open() {
        close();
        setStatus('connecting…');
        es = new EventSource(buildURL());
        es.onopen = () => setStatus('connected');
        es.onerror = () => setStatus('disconnected');
        es.onmessage = (evt) => {
            try {
                const env = JSON.parse(evt.data);
                appendLine(JSON.stringify(env));
            } catch (e) {
                appendLine(evt.data);
            }
        };
        es.addEventListener('drops', (evt) => {
            dropsEl.textContent = evt.data;
        });
    }

    function close() {
        if (es) {
            es.close();
            es = null;
        }
    }

    apply.addEventListener('click', () => {
        if (paused) return;
        open();
    });

    pause.addEventListener('click', () => {
        paused = !paused;
        pause.textContent = paused ? 'Resume' : 'Pause';
        if (paused) {
            close();
            setStatus('paused');
        } else {
            open();
        }
    });

    open();
})();
