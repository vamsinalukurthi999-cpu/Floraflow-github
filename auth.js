/**
 * FloraFlow - browser side of login + database sync.
 * Loaded before the app starts. Exposes window.FloraAuth.
 *
 *  - boot():     checks the login session and loads this user's data from the database
 *  - sync(db):   sends ONLY what changed (not the whole database) so one user's old screen
 *                can never overwrite another user's newer changes
 *  - polling:    refreshes the screen every few seconds so staff / couriers / customers
 *                see each other's updates without reloading
 */
(function () {
    // table -> primary-key columns (only tables the browser is allowed to change)
    const TABLES = {
        categories: ['category_id'], flowers: ['flower_id'], orders: ['order_id'],
        order_items: ['order_id', 'item_id'], payments: ['payment_id'], deliveries: ['delivery_id']
    };
    const keyOf = (t, r) => TABLES[t].map(k => r[k]).join(':');

    function snapshotOf(db) {
        const snap = {};
        for (const t in TABLES) {
            snap[t] = {};
            (db[t] || []).forEach(r => { snap[t][keyOf(t, r)] = { json: JSON.stringify(r), row: r }; });
        }
        return snap;
    }

    const Auth = {
        user: null,
        db: null,
        _snap: null,
        _serverJSON: '',
        _queue: Promise.resolve(),
        _pending: 0,

        async _json(url, opts) {
            const r = await fetch(url, opts);
            let data = {};
            try { data = await r.json(); } catch (e) { /* empty body */ }
            return { ok: r.ok, status: r.status, data };
        },

        _adopt(text) {
            this._serverJSON = text;
            this.db = JSON.parse(text);
            this._snap = snapshotOf(this.db);
        },

        async boot() {
            try {
                const me = await this._json('/api/me');
                if (!me.ok) { location.replace('/login.html'); return false; }
                this.user = me.data.user;
                const st = await fetch('/api/state', { cache: 'no-store' });
                if (!st.ok) { location.replace('/login.html'); return false; }
                this._adopt(await st.text());
                return true;
            } catch (e) {
                document.body.innerHTML = '<div style="font-family:sans-serif;padding:3rem;text-align:center">' +
                    '<h2>Cannot reach the FloraFlow server</h2><p>Start it with <code>python server.py</code> and open ' +
                    '<a href="http://localhost:8000">http://localhost:8000</a></p></div>';
                return false;
            }
        },

        async reload() {
            const st = await fetch('/api/state', { cache: 'no-store' });
            if (st.status === 401) { location.replace('/login.html'); return; }
            if (st.ok) this._adopt(await st.text());
        },

        // Work out what changed since the last sync.
        _diff(db) {
            const changes = {};
            const next = snapshotOf(db);
            for (const t in TABLES) {
                const up = [], del = [];
                for (const k in next[t]) {
                    if (!this._snap[t][k] || this._snap[t][k].json !== next[t][k].json) up.push(next[t][k].row);
                }
                for (const k in this._snap[t]) {
                    if (!next[t][k]) del.push(this._snap[t][k].row[TABLES[t][0]]);
                }
                if (up.length || del.length) changes[t] = { upsert: up, delete: del };
            }
            return { changes, next };
        },

        // Returns a promise: { ok, error?, order_id? }
        sync(db) {
            const { changes, next } = this._diff(db);
            if (!Object.keys(changes).length) return Promise.resolve({ ok: true });
            this._snap = next;
            this._pending++;
            const job = this._queue.then(async () => {
                try {
                    const r = await this._json('/api/changes', {
                        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(changes)
                    });
                    if (r.status === 401) { location.replace('/login.html'); return { ok: false, error: 'Session expired.' }; }
                    if (!r.ok) return { ok: false, error: r.data.error || 'Server error' };
                    if (r.data.order_id) await this.reload();        // server assigns the real order number and prices
                    return { ok: true, order_id: r.data.order_id };
                } catch (e) {
                    return { ok: false, error: 'Cannot reach the server. Your change was not saved.' };
                } finally {
                    this._pending--;
                }
            });
            this._queue = job.catch(() => {});
            return job;
        },

        startPolling(onChange, ms = 8000) {
            setInterval(async () => {
                if (document.hidden || this._pending > 0) return;
                try {
                    const r = await fetch('/api/state', { cache: 'no-store' });
                    if (r.status === 401) { location.replace('/login.html'); return; }
                    if (!r.ok) return;
                    const text = await r.text();
                    if (text !== this._serverJSON && this._pending === 0) {
                        this._adopt(text);
                        onChange(this.db);
                    }
                } catch (e) { /* offline: try again next time */ }
            }, ms);
        },

        async logout(portal) {
            try { await this._json('/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); } catch (e) { }
            location.replace('/login.html' + (portal ? '#' + portal : ''));
        },

        async resetDatabase() {
            const r = await this._json('/api/reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
            if (!r.ok) return false;
            await this.reload();
            return true;
        }
    };
    window.FloraAuth = Auth;
})();
