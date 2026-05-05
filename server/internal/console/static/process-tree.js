// Phase 6 #114 — live process-tree explorer.
//
// Vanilla JS, no framework — same shape as respond.js + livetail.js.
// Reads alert id + host-policy flags from data-* attributes on the
// container, fetches the JSON tree, renders SVG nodes laid out in a
// simple top-down BFS grid, lazy-loads expansions on click, and
// surfaces right-click response actions gated on host-policy bits.
//
// The rendering goal is "good enough for a forensics walk-through":
// pan/zoom via SVG transform, no edge routing tricks, no virtualised
// scrolling. Within MaxNodes (256) the layout fits comfortably in a
// 1200×600 viewport.

(function () {
    "use strict";

    const root = document.getElementById("process-tree-explorer");
    if (!root) return;

    const alertID = root.dataset.alertId;
    const isAnalyst = root.dataset.isAnalyst === "1";
    const allow = {
        killProcess: root.dataset.allowKillProcess === "1",
        killTree: root.dataset.allowKillTree === "1",
        collect: root.dataset.allowCollect === "1",
    };

    // Pan/zoom state. Updated by mouse events; written through to the
    // SVG transform on every animation frame.
    const view = { x: 0, y: 0, scale: 1 };
    let svg = null;
    let viewport = null;

    function url(rootPID, depth) {
        const params = new URLSearchParams();
        if (rootPID) params.set("root_pid", String(rootPID));
        if (depth) params.set("depth", String(depth));
        const q = params.toString();
        return "/alerts/" + alertID + "/process-tree.json" + (q ? "?" + q : "");
    }

    async function fetchTree(rootPID, depth) {
        const r = await fetch(url(rootPID, depth), { credentials: "same-origin" });
        if (!r.ok) {
            const txt = await r.text();
            throw new Error(r.status + ": " + (txt || r.statusText));
        }
        return r.json();
    }

    function layout(tree) {
        // BFS layers — nodes sharing a parent_pid land on the same
        // x-row; siblings spread along y. Node positions are
        // deterministic given the JSON's edge order which the server
        // already stable-sorts.
        const adj = new Map();
        for (const e of tree.edges || []) {
            if (!adj.has(e.from)) adj.set(e.from, []);
            adj.get(e.from).push(e.to);
        }
        const rootNode = (tree.nodes || []).find((n) => n.is_root);
        if (!rootNode) return [];
        const positions = new Map();
        const cellW = 220;
        const cellH = 80;
        let yCounter = { 0: 0 };
        function place(id, depth) {
            if (positions.has(id)) return;
            const slot = yCounter[depth] || 0;
            positions.set(id, { x: depth * cellW + 20, y: slot * cellH + 20 });
            yCounter[depth] = slot + 1;
            const kids = adj.get(id) || [];
            for (const k of kids) place(k, depth + 1);
        }
        place(rootNode.event_id, 0);
        return positions;
    }

    function render(tree) {
        root.innerHTML = "";
        if (tree.not_found) {
            const p = document.createElement("p");
            p.className = "muted";
            p.textContent = "No process events for this alert in CH retention.";
            root.appendChild(p);
            return;
        }
        const positions = layout(tree);
        if (positions.size === 0) {
            const p = document.createElement("p");
            p.className = "muted";
            p.textContent = "Empty process tree.";
            root.appendChild(p);
            return;
        }

        svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("class", "process-tree-svg");
        svg.setAttribute("viewBox", "0 0 1200 600");
        svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
        svg.style.width = "100%";
        svg.style.height = "600px";
        svg.style.background = "#1a1f2a";
        viewport = document.createElementNS("http://www.w3.org/2000/svg", "g");
        svg.appendChild(viewport);

        const nodeByID = new Map();
        for (const n of tree.nodes || []) nodeByID.set(n.event_id, n);

        for (const e of tree.edges || []) {
            const a = positions.get(e.from);
            const b = positions.get(e.to);
            if (!a || !b) continue;
            const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", a.x + 180);
            line.setAttribute("y1", a.y + 28);
            line.setAttribute("x2", b.x);
            line.setAttribute("y2", b.y + 28);
            line.setAttribute("stroke", "#3a4a5e");
            line.setAttribute("stroke-width", "1.5");
            viewport.appendChild(line);
        }

        for (const [id, p] of positions.entries()) {
            const n = nodeByID.get(id);
            if (!n) continue;
            const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
            g.setAttribute("transform", "translate(" + p.x + "," + p.y + ")");
            g.style.cursor = "pointer";

            const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            rect.setAttribute("width", "180");
            rect.setAttribute("height", "56");
            rect.setAttribute("rx", "4");
            rect.setAttribute("fill", n.is_root ? "#1f3a5e" : "#2c3a4a");
            rect.setAttribute("stroke", n.is_root ? "#82aaff" : "#3a4a5e");
            g.appendChild(rect);

            const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
            label.setAttribute("x", "8");
            label.setAttribute("y", "20");
            label.setAttribute("fill", "#d3d8e0");
            label.setAttribute("font-family", "monospace");
            label.setAttribute("font-size", "12");
            label.textContent = "pid " + n.pid + (n.process_name ? " " + n.process_name : "");
            g.appendChild(label);

            const sub = document.createElementNS("http://www.w3.org/2000/svg", "text");
            sub.setAttribute("x", "8");
            sub.setAttribute("y", "40");
            sub.setAttribute("fill", "#8a99b3");
            sub.setAttribute("font-family", "monospace");
            sub.setAttribute("font-size", "10");
            sub.textContent = (n.exec_path || n.cmdline || "").substring(0, 24);
            g.appendChild(sub);

            if (n.has_more_children) {
                const more = document.createElementNS("http://www.w3.org/2000/svg", "text");
                more.setAttribute("x", "164");
                more.setAttribute("y", "16");
                more.setAttribute("fill", "#f0c674");
                more.setAttribute("font-family", "monospace");
                more.setAttribute("font-size", "10");
                more.setAttribute("text-anchor", "end");
                more.textContent = "+";
                g.appendChild(more);
            }

            g.addEventListener("click", (ev) => {
                ev.preventDefault();
                expand(n.pid);
            });
            g.addEventListener("contextmenu", (ev) => {
                ev.preventDefault();
                showActionMenu(ev.clientX, ev.clientY, n);
            });

            viewport.appendChild(g);
        }
        root.appendChild(svg);

        // Pan via drag.
        let dragging = false;
        let dragStart = null;
        svg.addEventListener("mousedown", (ev) => {
            dragging = true;
            dragStart = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y };
        });
        svg.addEventListener("mousemove", (ev) => {
            if (!dragging) return;
            view.x = dragStart.vx + (ev.clientX - dragStart.x);
            view.y = dragStart.vy + (ev.clientY - dragStart.y);
            applyTransform();
        });
        svg.addEventListener("mouseup", () => { dragging = false; });
        svg.addEventListener("mouseleave", () => { dragging = false; });

        // Zoom via wheel.
        svg.addEventListener("wheel", (ev) => {
            ev.preventDefault();
            const factor = ev.deltaY > 0 ? 0.9 : 1.1;
            view.scale = Math.max(0.25, Math.min(4, view.scale * factor));
            applyTransform();
        }, { passive: false });
    }

    function applyTransform() {
        if (!viewport) return;
        viewport.setAttribute(
            "transform",
            "translate(" + view.x + "," + view.y + ") scale(" + view.scale + ")",
        );
    }

    async function expand(pid) {
        try {
            const tree = await fetchTree(pid, 4);
            render(tree);
        } catch (err) {
            console.warn("process-tree expand failed:", err);
        }
    }

    function showActionMenu(x, y, node) {
        // No menu for viewers — they don't have any allowed actions.
        if (!isAnalyst) return;
        const items = [];
        if (allow.killProcess) items.push({ label: "Kill process", action: "kill_process" });
        if (allow.killTree) items.push({ label: "Kill process tree", action: "kill_process_tree" });
        if (allow.collect) items.push({ label: "Collect artefacts", action: "collect_artifacts" });
        if (items.length === 0) return;

        document.querySelectorAll(".process-tree-menu").forEach((m) => m.remove());
        const menu = document.createElement("div");
        menu.className = "process-tree-menu";
        menu.style.position = "fixed";
        menu.style.top = y + "px";
        menu.style.left = x + "px";
        menu.style.background = "#262d3a";
        menu.style.border = "1px solid #3a4a5e";
        menu.style.borderRadius = "4px";
        menu.style.padding = "0.25rem 0";
        menu.style.zIndex = "1000";
        menu.style.fontFamily = "monospace";
        menu.style.fontSize = "12px";
        menu.style.color = "#d3d8e0";

        for (const it of items) {
            const btn = document.createElement("button");
            btn.textContent = it.label + " (pid " + node.pid + ")";
            btn.style.display = "block";
            btn.style.width = "100%";
            btn.style.padding = "0.4rem 0.8rem";
            btn.style.background = "transparent";
            btn.style.color = "#d3d8e0";
            btn.style.border = "none";
            btn.style.textAlign = "left";
            btn.style.cursor = "pointer";
            btn.addEventListener("mouseover", () => { btn.style.background = "#3a4a5e"; });
            btn.addEventListener("mouseout", () => { btn.style.background = "transparent"; });
            btn.addEventListener("click", () => {
                document.body.removeChild(menu);
                submitAction(it.action, node.pid);
            });
            menu.appendChild(btn);
        }
        document.body.appendChild(menu);
        const dismiss = (ev) => {
            if (!menu.contains(ev.target)) {
                if (menu.parentNode) menu.parentNode.removeChild(menu);
                document.removeEventListener("click", dismiss, true);
            }
        };
        setTimeout(() => document.addEventListener("click", dismiss, true), 0);
    }

    function submitAction(action, pid) {
        // Posts the same form shape /alerts/{id}/respond accepts.
        const form = document.createElement("form");
        form.method = "post";
        form.action = "/alerts/" + alertID + "/respond";
        const fields = { action: action, target: String(pid) };
        for (const k of Object.keys(fields)) {
            const inp = document.createElement("input");
            inp.type = "hidden";
            inp.name = k;
            inp.value = fields[k];
            form.appendChild(inp);
        }
        document.body.appendChild(form);
        form.submit();
    }

    // Initial fetch.
    fetchTree(0, 4)
        .then(render)
        .catch((err) => {
            const p = document.createElement("p");
            p.className = "muted";
            p.textContent = "Failed to load process tree: " + err.message;
            root.appendChild(p);
        });
})();
