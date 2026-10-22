/* Blockchain-Lite web frontend. Talks to web/bridge.py: JSON under /api/*, live updates on /events (SSE). */
(() => {
  'use strict';

  // ------------------------------------------------------------------ helpers

  const $ = (id) => document.getElementById(id);
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /** Build an element. attrs: class, text, style (object), on* handlers, anything else as an attribute. */
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k === 'style') Object.assign(node.style, v);
      else if (k.startsWith('on')) node.addEventListener(k.slice(2).toLowerCase(), v);
      else node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function svg(tag, attrs) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
    return node;
  }

  const short = (h, a = 8, b = 6) => (h && h.length > a + b ? `${h.slice(0, a)}…${h.slice(-b)}` : h || '');
  const fmt = (n) => Number(n).toLocaleString('en-US');
  const compact = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${Math.round(n / 1e3)}k` : String(n));
  const secs = (s) => (s === null || s === undefined ? '–' : `${Number(s).toFixed(Number(s) % 1 ? 1 : 0)}s`);
  const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
  const sleep = (ms) => new Promise((r) => setTimeout(r, reducedMotion ? 0 : ms));

  async function call(method, path, body) {
    const res = await fetch(path, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    let payload;
    try { payload = await res.json(); } catch (_) { throw new Error(`HTTP ${res.status}`); }
    if (!payload.ok) throw new Error(payload.error ? payload.error.message : `HTTP ${res.status}`);
    return payload.result;
  }
  const api = { get: (p) => call('GET', p), post: (p, b) => call('POST', p, b || {}) };

  /** Ring gauge (black dock). */
  function gauge(node, pct, color, value, label, icon) {
    const C = 2 * Math.PI * 30;
    node.replaceChildren(
      el('div', { class: 'gauge-ring' },
        (() => {
          const s = svg('svg', { width: 72, height: 72, viewBox: '0 0 72 72', 'aria-hidden': 'true' });
          s.append(svg('circle', { class: 'g-bg', cx: 36, cy: 36, r: 30 }));
          s.append(svg('circle', {
            class: 'g-fg', cx: 36, cy: 36, r: 30, stroke: color,
            'stroke-dasharray': `${(C * Math.max(0.03, Math.min(1, pct))).toFixed(1)} ${C.toFixed(1)}`,
            transform: 'rotate(-90 36 36)',
          }));
          return s;
        })(),
        el('span', { 'aria-hidden': 'true', text: icon })),
      el('span', { class: 'gauge-value', text: value }),
      el('span', { class: 'gauge-label', text: label }));
  }

  const linkSvg = (bad) => {
    const s = svg('svg', { width: 56, height: 20, viewBox: '0 0 56 20', class: 'link', 'aria-hidden': 'true' });
    s.append(svg('path', { d: 'M6 10 L50 10', stroke: bad ? '#B4523C' : '#4FB8B4', 'stroke-width': 3, 'stroke-linecap': 'round', 'stroke-dasharray': bad ? '3 7' : 'none' }));
    s.append(svg('circle', { cx: 6, cy: 10, r: 5, fill: bad ? '#E2B3A5' : '#98D8D0' }));
    s.append(svg('circle', { cx: 50, cy: 10, r: 5, fill: bad ? '#E2B3A5' : '#10606F' }));
    return s;
  };

  // ------------------------------------------------------------------ state

  const S = {
    state: null,
    selected: null,
    detail: null,
    proofTx: null,
    from: 'Alice',
    trace: null,
    step: 0,
    playing: false,
    playToken: 0,
    renders: new Set(),
    mining: false,
  };

  // ------------------------------------------------------------------ routing

  const VIEWS = ['explorer', 'forge', 'tamper', 'people'];
  function route() {
    const view = VIEWS.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'explorer';
    document.querySelectorAll('[data-view-panel]').forEach((p) => p.classList.toggle('hidden', p.dataset.viewPanel !== view));
    document.querySelectorAll('[data-view]').forEach((a) => {
      if (a.dataset.view === view) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    if (view === 'forge' && !S.trace && !S.mining && S.state) loadTrace(S.state.blocks.length - 1);
    if (view === 'tamper' && S.state && !$('tamper-tx').options.length) onTamperBlockChange();
    window.scrollTo({ top: 0 });
  }
  window.addEventListener('hashchange', route);

  // ------------------------------------------------------------------ explorer

  let refreshTimer = null;
  function refreshSoon() {
    if (refreshTimer) return;
    refreshTimer = setTimeout(() => { refreshTimer = null; refresh(); }, 600);
  }

  async function refresh() {
    const btn = $('refresh-btn');
    btn.classList.add('is-busy');
    try {
      S.state = await api.get('/api/state');
      renderState();
      const tip = S.state.blocks.length - 1;
      if (S.selected === null || S.selected > tip) await selectBlock(tip);
    } catch (err) {
      setLive(false, `Bridge unreachable: ${err.message}`);
    } finally {
      btn.classList.remove('is-busy');
    }
  }

  function renderState() {
    const { chain, blocks, mempool, wallets } = S.state;
    const tip = blocks[blocks.length - 1];

    $('stat-height').textContent = fmt(chain.height);
    $('stat-supply').textContent = fmt(chain.total_supply);
    $('tip-label').textContent = `Tip hash · block #${tip.index}`;
    const zeros = Math.floor(tip.difficulty / 4); // hex digits that must be 0 at the tip's difficulty
    $('tip-hash').replaceChildren(
      el('span', { style: { color: 'var(--teal-900)', fontWeight: 600 }, text: chain.tip_hash_hex.slice(0, zeros) }),
      chain.tip_hash_hex.slice(zeros));
    const chip = $('valid-chip');
    chip.className = chain.is_valid ? 'chip' : 'chip chip-danger';
    chip.textContent = chain.is_valid ? '✓ Valid Genesis → tip' : '✗ Chain invalid';

    // Next-block ring: fills as the mempool fills (4 tx = full).
    const fill = Math.min(1, (mempool.length + 1) / 5);
    const C = 2 * Math.PI * 112;
    const ang = (-90 + 360 * fill) * Math.PI / 180;
    $('next-ring').setAttribute('stroke-dasharray', `${(C * fill).toFixed(1)} ${C.toFixed(1)}`);
    $('next-knob').setAttribute('cx', (130 + 112 * Math.cos(ang)).toFixed(1));
    $('next-knob').setAttribute('cy', (130 + 112 * Math.sin(ang)).toFixed(1));
    $('next-num').textContent = `#${chain.height}`;
    $('next-label').textContent = `${mempool.length} tx waiting`;
    $('next-note').textContent = `${mempool.length} pending transfer${mempool.length === 1 ? '' : 's'} + coinbase of ${chain.block_reward} + fees.`;

    gauge($('gauge-valid'), chain.is_valid ? 1 : 0.05, chain.is_valid ? '#4FB8B4' : '#F0A592', chain.is_valid ? '100%' : 'broken', 'valid', chain.is_valid ? '✓' : '✗');
    gauge($('gauge-mempool'), mempool.length / 10, '#98D8D0', `${mempool.length}/10`, 'mempool', 'tx');
    const cons = S.state.consensus;
    gauge($('gauge-diff'), cons.difficulty / cons.max_difficulty, '#E8DDCF', `${cons.difficulty} bits`, 'difficulty', 'D');

    renderDifficulty(cons);
    renderEffort();
    renderChain();
    renderPeople(wallets);
    renderMempool(mempool);
    renderSelectors();
    renderNetwork();
    renderPeoplePage();
  }

  function renderDifficulty(c) {
    $('diff-now').textContent = c.difficulty;
    const auto = $('auto-btn');
    auto.setAttribute('aria-pressed', c.auto_mining ? 'true' : 'false');
    auto.textContent = c.auto_mining ? 'Auto-mining… stop' : 'Auto-mine';
    const next = $('diff-next');
    const delta = c.next_difficulty - c.difficulty;
    next.className = `diff-arrow${delta > 0 ? ' is-up' : delta < 0 ? ' is-down' : ''}`;
    next.textContent = delta > 0 ? `next block ↑ ${c.next_difficulty}` : delta < 0 ? `next block ↓ ${c.next_difficulty}` : `next block = ${c.next_difficulty}`;
    if (!c.retargeting) {
      $('retarget-chip').textContent = 'fixed difficulty';
      $('diff-rule').textContent = 'Retargeting is off (bridge started with --retarget-interval 0).';
      document.querySelector('.pace').classList.add('hidden');
      $('pace-scale').classList.add('hidden');
      return;
    }
    $('retarget-chip').textContent = c.blocks_until_retarget === 0
      ? 'retargets on the next block'
      : `retarget in ${c.blocks_until_retarget} block${c.blocks_until_retarget === 1 ? '' : 's'}`;
    $('diff-rule').textContent = `Target ${secs(c.target_block_time)} per block. Every ${c.retarget_interval} blocks: average faster than ${secs(c.fast_below)} → +1 bit (twice the work), slower than ${secs(c.slow_above)} → −1 bit. Last ${c.retarget_interval} blocks averaged ${secs(c.window_avg_block_time)}.`;
    // Pace bar runs 0 .. 2 × target.
    const span = 2 * c.target_block_time;
    const pct = (v) => Math.max(0, Math.min(100, (v / span) * 100));
    $('pace-fast').style.width = `${pct(c.fast_below)}%`;
    $('pace-ok').style.width = `${pct(c.slow_above) - pct(c.fast_below)}%`;
    $('pace-slow').style.width = `${100 - pct(c.slow_above)}%`;
    $('pace-marker').style.left = `${pct(c.window_avg_block_time || 0)}%`;
    $('pace-scale').replaceChildren(
      el('span', { style: { left: '2%' }, text: '0s' }),
      el('span', { style: { left: `${pct(c.fast_below)}%` }, text: secs(c.fast_below) }),
      el('span', { style: { left: `${pct(c.slow_above)}%` }, text: secs(c.slow_above) }),
      el('span', { style: { left: '96%' }, text: secs(span) }));
  }

  function renderEffort() {
    const recent = S.state.blocks.slice(1).slice(-8);
    // Log scale: one difficulty bit doubles the expected work.
    const logMax = Math.max(...recent.map((b) => Math.log2(b.nonce + 1)), 4);
    $('effort').replaceChildren(...recent.map((b) => el('button', {
      class: `effort-col${b.index === S.selected ? ' is-selected' : ''}`,
      type: 'button', style: { border: 0, background: 'none', padding: 0 },
      'aria-label': `Block ${b.index}: ${b.nonce + 1} hashes at difficulty ${b.difficulty}`,
      onclick: () => selectBlock(b.index),
    },
      el('span', { class: 'mono', style: { color: 'var(--teal-900)' }, text: compact(b.nonce + 1) }),
      el('div', { class: 'effort-pill' }, el('div', { class: 'effort-fill', style: { height: `${Math.max(6, Math.round(Math.log2(b.nonce + 1) / logMax * 112))}px` } })),
      el('span', { text: `#${b.index}` }),
      el('span', { class: 'mono', style: { fontSize: '11px' }, text: `D${b.difficulty}` }))));
  }

  let knownTip = -1;
  const CHAIN_WINDOW = 12;
  function renderChain() {
    const all = S.state.blocks;
    const blocks = all.slice(-CHAIN_WINDOW);
    const items = [];
    if (all.length > blocks.length) {
      items.push(el('div', { class: 'pending-block', style: { width: '150px' } },
        el('span', { class: 'num', text: `+${all.length - blocks.length}` }),
        el('span', { text: 'earlier blocks, back to Genesis' })));
    }
    blocks.forEach((b, i) => {
      if (i === 0 && items.length) items.push(linkSvg(false));
      if (i > 0) items.push(linkSvg(false));
      items.push(el('button', {
        type: 'button',
        class: `block-card${b.index === S.selected ? ' is-selected' : ''}${knownTip >= 0 && b.index > knownTip ? ' is-new' : ''}`,
        'aria-pressed': b.index === S.selected ? 'true' : 'false',
        onclick: () => selectBlock(b.index),
      },
        el('div', { class: 'block-top' },
          el('span', { class: 'num', text: b.index === 0 ? 'Genesis' : `#${b.index}` }),
          el('span', { class: 'chip', text: `${b.tx_count} tx` })),
        el('div', { class: 'k', text: 'hash' }), el('div', { class: 'v hash', text: short(b.hash) }),
        el('div', { class: 'k', text: 'prev' }), el('div', { class: 'v', text: short(b.previous_hash) }),
        el('div', { class: 'k', text: 'merkle root' }), el('div', { class: 'v', text: short(b.merkle_root) }),
        el('div', { class: 'block-foot' },
          el('span', {}, 'nonce ', el('span', { class: 'mono', style: { color: 'var(--ink)' }, text: b.nonce })),
          el('span', {}, 'D ', el('span', { class: 'mono', style: { color: 'var(--ink)' }, text: b.difficulty }),
            b.block_time === null ? '' : ` · ${secs(b.block_time)}`))));
    });
    const dashed = svg('svg', { width: 56, height: 20, viewBox: '0 0 56 20', class: 'link', 'aria-hidden': 'true' });
    dashed.append(svg('path', { d: 'M6 10 L50 10', stroke: '#CFD8C4', 'stroke-width': 3, 'stroke-linecap': 'round', 'stroke-dasharray': '2 7' }));
    items.push(dashed, el('div', { class: 'pending-block' },
      el('span', { class: 'num', text: `#${S.state.chain.height}` }),
      el('span', { text: S.state.mempool.length ? `${S.state.mempool.length} tx ready to mine` : 'Waiting for transactions' })));
    $('chain').replaceChildren(...items);
    const grew = knownTip >= 0 && all.length - 1 > knownTip;
    if (knownTip < 0 || grew) {
      const scroller = $('chain-scroll');
      requestAnimationFrame(() => { scroller.scrollLeft = scroller.scrollWidth; });
    }
    knownTip = all.length - 1;
  }

  function renderPeople(wallets) {
    const people = wallets.filter((w) => w.name !== 'Miner').slice(0, 8);
    $('people').replaceChildren(...people.map((w) => el('button', {
      type: 'button', class: 'person', 'aria-pressed': w.name === S.from ? 'true' : 'false',
      'aria-label': `${w.name}, balance ${w.balance}`, title: `${w.name} · ${w.balance}`,
      text: w.name[0],
      onclick: () => { S.from = w.name; renderPeople(S.state.wallets); },
    })));
    const me = wallets.find((w) => w.name === S.from);
    $('from-balance').value = me ? `${me.name} · ${fmt(me.balance)}` : '';
    $('send-btn').textContent = `Sign & send from ${S.from}`;
    const sel = $('to-select');
    const keep = sel.value;
    sel.replaceChildren(...wallets.filter((w) => w.name !== S.from).map((w) => el('option', { value: w.name, text: w.name })));
    sel.value = [...sel.options].some((o) => o.value === keep) ? keep : (S.from === 'Bob' ? 'Alice' : 'Bob');
  }

  function renderMempool(mempool) {
    $('mempool-count').textContent = `${mempool.length} waiting`;
    $('mempool').replaceChildren(...(mempool.length ? mempool.map((tx) => el('div', { class: 'list-item' },
      el('span', {}, el('span', { class: 'mono', style: { color: 'var(--teal-900)' }, text: tx.tx_id.slice(0, 8) }),
        ` · ${tx.from} → ${tx.outputs[0].to}`),
      el('span', { class: 'mono', style: { fontWeight: 500 }, text: tx.outputs[0].amount })))
      : [el('p', { class: 'muted', style: { margin: 0, fontSize: '14px' }, text: 'Quiet. Every transaction is already in a block.' })]));
  }

  function renderSelectors() {
    const blocks = S.state.blocks;
    const forgeSel = $('forge-select');
    const forgeKeep = S.trace ? String(S.trace.block.index) : String(blocks.length - 1);
    forgeSel.replaceChildren(...blocks.slice(1).reverse().map((b) => el('option', { value: b.index, text: `#${b.index}` })));
    forgeSel.value = forgeKeep;

    const pSel = $('tamper-person');
    const pKeep = pSel.value;
    pSel.replaceChildren(...S.state.wallets.map((w) => el('option', { value: w.name, text: w.name })));
    pSel.value = pKeep || (S.state.wallets.some((w) => w.name === 'Grace') ? 'Grace' : S.state.wallets[0].name);

    const tSel = $('tamper-block');
    const tKeep = tSel.value;
    tSel.replaceChildren(...blocks.slice(1).map((b) => el('option', { value: b.index, text: `#${b.index}` })));
    if (tKeep && [...tSel.options].some((o) => o.value === tKeep)) tSel.value = tKeep;
    else if (tSel.options.length) tSel.value = String(Math.max(1, blocks.length - 5));
  }

  async function selectBlock(index) {
    S.selected = index;
    S.proofTx = null;
    if (S.state) { renderChain(); renderEffort(); }
    try {
      S.detail = await api.get(`/api/block?index=${index}`);
      renderInspector();
    } catch (err) {
      $('inspect-kv').replaceChildren(el('dd', { text: err.message }));
    }
  }

  function renderInspector(proof) {
    const d = S.detail;
    $('inspect-h').textContent = d.index === 0 ? 'Genesis block' : `Block #${d.index}`;
    $('replay-link').href = '#forge';
    $('replay-link').onclick = () => { if (d.index > 0) loadTrace(d.index); };
    const rows = [
      ['Block hash', d.hash, 'var(--teal-900)'],
      ['Previous', d.previous_hash],
      ['Merkle root', d.merkle_root],
      ['Nonce', `${d.nonce} · found after ${d.nonce + 1} hash${d.nonce ? 'es' : ''}`],
      ['Time', `${clock(d.timestamp)} · ${d.block_time === null ? 'genesis' : `${secs(d.block_time)} after the previous block`} · difficulty ${d.difficulty} bits`],
    ];
    $('inspect-kv').replaceChildren(...rows.flatMap(([k, v, color]) => [
      el('dt', { text: k }), el('dd', { text: v, style: color ? { color } : {} })]));

    const levels = d.merkle_levels;
    $('tree-title').textContent = `Merkle tree · ${levels[0].length} tx → 1 root`;
    const onPath = new Set((proof ? proof.path : []).map(([l, i]) => `${l}-${i}`));
    const sibs = new Set((proof ? proof.siblings : []).map(([l, i]) => `${l}-${i}`));
    const top = levels.length - 1;
    $('tree').replaceChildren(...levels.slice().reverse().map((level, r) => {
      const l = top - r;
      return el('div', { class: 'tree-level' }, ...level.map((h, i) => {
        const key = `${l}-${i}`;
        let cls = 'node';
        if (l === top) cls += ' is-root';
        else if (onPath.has(key)) cls += ' is-path';
        else if (sibs.has(key)) cls += ' is-sibling';
        return el('span', { class: cls, title: h, text: h.slice(0, 8) });
      }));
    }));
    $('proof-label').textContent = proof
      ? `Proof for tx ${proof.tx_id.slice(0, 8)} · ${proof.step_count} hashes · ${proof.verified ? 'verified ✓' : 'FAILED'}`
      : 'Pick a transaction to see its proof path';

    $('tx-list').replaceChildren(...d.transactions.map((tx, i) => el('button', {
      type: 'button', class: 'list-item', 'aria-pressed': S.proofTx === i ? 'true' : 'false',
      onclick: () => loadProof(i),
    },
      el('span', {}, el('span', { class: 'mono', style: { color: 'var(--teal-900)' }, text: tx.tx_id.slice(0, 8) }),
        tx.type === 'coinbase' ? ` · coinbase → ${tx.outputs[0].to}` : ` · ${tx.from} → ${tx.outputs[0].to}`),
      el('span', { class: 'mono', style: { fontWeight: 500 }, text: tx.outputs[0].amount }))));
  }

  async function loadProof(txIndex) {
    S.proofTx = txIndex;
    try {
      const proof = await api.get(`/api/proof?block=${S.detail.index}&tx=${txIndex}`);
      renderInspector(proof);
    } catch (err) {
      $('proof-label').textContent = err.message;
    }
  }

  $('send-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const note = $('send-note');
    const btn = $('send-btn');
    btn.disabled = true;
    note.className = 'form-note';
    note.textContent = 'Selecting UTXOs and signing…';
    try {
      const res = await api.post('/api/tx', {
        from: S.from, to: $('to-select').value,
        amount: Number($('amount').value), fee: Number($('fee').value),
      });
      const tx = res.tx;
      const change = tx.outputs.find((o) => o.to === S.from);
      note.textContent = `Sent ${tx.outputs[0].amount} to ${tx.outputs[0].to} · spent ${tx.inputs.length} UTXO${tx.inputs.length > 1 ? 's' : ''}${change ? ` · ${change.amount} change` : ''} · tx ${tx.tx_id.slice(0, 8)}`;
      await refresh();
    } catch (err) {
      note.className = 'form-note is-error';
      note.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  });

  $('refresh-btn').addEventListener('click', refresh);
  $('auto-btn').addEventListener('click', async () => {
    const on = $('auto-btn').getAttribute('aria-pressed') !== 'true';
    try {
      await api.post('/api/autominer', { on });
      await refresh();
    } catch (err) {
      logEvent('error', err.message, '#F0A592');
    }
  });
  $('mine-btn').addEventListener('click', () => { location.hash = '#forge'; mineAndWatch(); });

  // ------------------------------------------------------------------ live events

  function setLive(on, text) {
    $('live').classList.toggle('is-on', on);
    $('live-text').textContent = text;
  }

  function logEvent(kind, msg, color) {
    const now = new Date().toLocaleTimeString([], { hour12: false });
    const list = $('events');
    list.prepend(el('div', { class: 'event' },
      el('span', { class: 't', text: now }),
      el('span', { class: 'k', style: { color }, text: kind }),
      el('span', { text: msg })));
    while (list.children.length > 40) list.lastChild.remove();
  }

  function connectEvents() {
    const es = new EventSource('/events');
    es.addEventListener('open', () => setLive(true, `Live · ${location.host}`));
    es.addEventListener('error', () => setLive(false, 'Reconnecting…'));
    es.addEventListener('tx_submitted', (e) => {
      const { tx, mempool_size: size } = JSON.parse(e.data);
      logEvent('tx_submitted', `${tx.tx_id.slice(0, 8)} ${tx.from} → ${tx.outputs[0].to} · ${tx.outputs[0].amount} (mempool ${size})`, '#98D8D0');
      if (!S.mining) refreshSoon();
    });
    es.addEventListener('block_mined', (e) => {
      const { block, stats } = JSON.parse(e.data);
      logEvent('block_mined', `#${block.index} ${short(block.hash)} · D${block.difficulty} · ${compact(stats.hashes_tried)} hashes in ${stats.elapsed_seconds.toFixed(2)}s · ${block.tx_count} tx`, '#4FB8B4');
      if (!S.mining) refreshSoon();
    });
    es.addEventListener('difficulty_changed', (e) => {
      const d = JSON.parse(e.data);
      const why = d.to > d.from ? `blocks averaged ${secs(d.window_avg_block_time)} (target ${secs(d.target_block_time)}): too fast` : `blocks averaged ${secs(d.window_avg_block_time)} (target ${secs(d.target_block_time)}): too slow`;
      logEvent('retarget', `difficulty ${d.from} → ${d.to} bits · ${why}`, d.to > d.from ? '#E8DDCF' : '#CFD8C4');
    });
    es.addEventListener('autominer', (e) => {
      logEvent('auto_miner', JSON.parse(e.data).running ? 'started' : 'stopping after the current block', '#98D8D0');
      refreshSoon();
    });
    es.addEventListener('copy_tampered', (e) => {
      const d = JSON.parse(e.data);
      logEvent('copy_tampered', `${d.name}'s copy · block #${d.block_index} amount ${d.old_amount} → ${d.new_amount}`, '#F0A592');
      toast(`⚠ ${d.name}'s ledger copy was tampered`, `Block #${d.block_index}: amount ${d.old_amount} changed to ${d.new_amount}. The network will check every copy in ${Math.ceil(d.next_audit_in)}s.`, 'danger');
      refreshNetwork();
    });
    es.addEventListener('network_audit', (e) => {
      const d = JSON.parse(e.data);
      logEvent('network_check', `${d.valid_copies} of ${d.copies} copies valid · majority ${d.majority_size} · repaired ${d.repaired.length}`, '#98D8D0');
      refreshNetwork();
    });
    es.addEventListener('ledger_repaired', (e) => {
      const d = JSON.parse(e.data);
      S.repairedFlash[d.name] = Date.now() + 10000;
      logEvent('ledger_repaired', `${d.name}'s copy restored from the majority (${d.majority_size} of ${d.copies}) · block #${d.block_index}`, '#4FB8B4');
      toast(`✓ Tamper fixed: ${d.name}'s copy restored`, `Block #${d.block_index} ${d.reason}. ${d.majority_size} of ${d.copies} copies agreed, so ${d.name} now holds that majority ledger again.`, 'ok');
      if (S.lastTamper && S.lastTamper.name === d.name) {
        S.lastTamper.repaired = d;
        renderLab(S.lastTamper);
      }
      refreshNetwork();
    });
    es.addEventListener('person_joined', (e) => {
      const d = JSON.parse(e.data);
      logEvent('person_joined', `${d.person.name} · ${d.person.address.slice(0, 8)}…${d.funding_tx ? ` · ${d.funding_tx.outputs[0].amount} coins pending` : ''}`, '#E8DDCF');
      toast(`${d.person.name} joined the network`, `New RSA wallet and a full copy of the ledger.${d.funding_tx ? ` ${d.funding_tx.outputs[0].amount} coins from the Miner arrive in the next block.` : ''}`, 'ok');
      refreshSoon();
    });
    es.addEventListener('render_ready', (e) => {
      const { block_index: idx, files } = JSON.parse(e.data);
      files.forEach((f) => S.renders.add(f));
      logEvent('render_ready', `Manim video for #${idx}`, '#E8DDCF');
      if (S.trace && S.trace.block.index === idx) showRender();
    });
  }

  // ------------------------------------------------------------------ forge

  const STEPS = [
    {
      tab: 'Collect', title: 'Gather transactions',
      body: (t) => `The miner takes the ${t.block.transactions.length - 1} waiting transfer${t.block.transactions.length === 2 ? '' : 's'} and puts a coinbase in slot 0 that pays itself the reward plus every fee.`,
      code: 'ledger.mine_pending_transactions(miner)',
      manim: 'class CollectTxScene(Scene):\n  tx pills slide from the mempool\n  into the block outline',
    },
    {
      tab: 'Hash', title: 'Hash every transaction',
      body: (t) => `Each transaction becomes canonical bytes and goes through SHA-256 to get its tx_id. Flipping one input bit changed ${t.hash_sample.avalanche_flipped} of the 256 output bits.`,
      code: 'tx.compute_tx_id() · hash_merkle_leaf(tx_id)',
      manim: 'class HashScene(Scene):\n  bytes stream into the SHA ring,\n  64 round states tick past,\n  the digest writes itself out',
    },
    {
      tab: 'Merkle', title: 'Grow the Merkle tree',
      body: (t) => `${t.leaves.length} leaves are paired and hashed upward until one 32-byte root is left. That root commits to every transaction in the block.`,
      code: 'MerkleTree.from_transactions(txs).root',
      manim: 'class MerkleScene(Scene):\n  leaves on a row, pairs merge\n  into parents level by level',
    },
    {
      tab: 'Proof-of-Work', title: 'Search for the nonce',
      body: (t) => `The 88-byte header is hashed over and over, nonce +1 each time, until the hash starts with ${t.target_bits} zero bits. This block took ${t.hashes_tried} tr${t.hashes_tried === 1 ? 'y' : 'ies'}.`,
      code: 'ProofOfWorkMiner.mine_block_with_stats()',
      manim: 'class PoWScene(Scene):\n  the nonce counter spins,\n  misses fade, the winner\n  locks in teal',
    },
    {
      tab: 'Append', title: 'Join the chain',
      body: () => 'The block stores the previous block’s hash. The validator re-checks it, the UTXO hash map updates, and every open browser gets a block_mined event.',
      code: 'ledger.append_mined_block(block)',
      manim: 'class AppendScene(Scene):\n  the new block glides in and\n  the prev_hash link draws itself',
    },
  ];

  async function loadTrace(index) {
    stopPlay();
    try {
      const trace = await api.get(`/api/trace?index=${index}`);
      if (S.mining) return; // a freshly mined block is about to take the stage
      S.trace = trace;
      $('forge-select').value = String(index);
      setStep(0);
      showRender();
    } catch (err) {
      $('forge-title').textContent = err.message;
    }
  }

  function renderTabs() {
    $('stage-tabs').replaceChildren(...STEPS.map((s, i) => el('button', {
      type: 'button',
      class: i === S.step ? 'is-active' : (i < S.step ? 'is-done' : ''),
      'aria-current': i === S.step ? 'step' : null,
      onclick: () => { stopPlay(); setStep(i); },
    }, el('span', { class: 'mono', style: { fontSize: '11px' }, text: `0${i + 1}` }), s.tab)));
  }

  function setStep(n) {
    S.step = n;
    const t = S.trace;
    const s = STEPS[n];
    $('forge-title').textContent = `Block Forge · block #${t.block.index}`;
    document.querySelectorAll('.stage-step').forEach((p) => p.classList.toggle('is-active', Number(p.dataset.step) === n));
    renderTabs();
    $('step-no').textContent = `${n + 1}/5`;
    const C = 2 * Math.PI * 23;
    $('step-ring').setAttribute('stroke-dasharray', `${(C * (n + 1) / 5).toFixed(1)} ${C.toFixed(1)}`);
    $('step-title').textContent = s.title;
    $('step-body').textContent = s.body(t);
    $('step-code').textContent = s.code;
    $('step-manim').textContent = s.manim;
    $('step-progress').style.width = `calc(${(n + 1) * 20}% - 6px)`;
    $('step-next').textContent = n >= 4 ? 'Start over' : 'Next step →';
    return [drawCollect, drawHash, drawMerkle, drawPow, drawAppend][n](t);
  }

  function drawCollect(t) {
    const txs = t.block.transactions;
    $('collect-list').replaceChildren(...txs.slice(0, 7).map((tx, i) => el('div', {
      class: `tx-pill${tx.type === 'coinbase' ? ' is-coinbase' : ''}`, style: { animationDelay: `${i * 120}ms` },
    },
      el('span', { class: 'mono', style: { fontSize: '13px', color: tx.type === 'coinbase' ? 'var(--teal-200)' : 'var(--teal-900)' }, text: tx.tx_id.slice(0, 8) }),
      el('span', { style: { flexGrow: 1, fontSize: '14px' }, text: tx.type === 'coinbase' ? `coinbase → ${tx.outputs[0].to}` : `${tx.from} → ${tx.outputs[0].to}` }),
      el('span', { class: 'mono', style: { fontWeight: 500 }, text: tx.outputs[0].amount }))),
    txs.length > 7 ? el('div', { class: 'muted', style: { paddingLeft: '18px', fontSize: '13px' }, text: `+ ${txs.length - 7} more` }) : null);
    $('candidate-title').textContent = `Candidate block #${t.block.index}`;
    $('slots').replaceChildren(...txs.map((tx, i) => el('div', { class: 'slot', style: { animationDelay: `${300 + i * 120}ms` }, text: tx.tx_id.slice(0, 8) })));
    const cb = txs[0];
    $('candidate-note').textContent = `${txs.length} transactions · coinbase pays ${cb.outputs[0].amount} to ${cb.outputs[0].to}. Double-spends and bad signatures are rejected before this point.`;
    return sleep(1200);
  }

  async function drawHash(t) {
    const hs = t.hash_sample;
    const token = S.playToken;
    $('hash-in').textContent = `${hs.tx_bytes_hex.slice(0, 120)}…`;
    $('hash-out').textContent = '';
    $('hash-leaf').textContent = '';
    $('aval-title').textContent = `Avalanche · 1 input bit flipped → ${hs.avalanche_flipped} of 256 output bits flipped`;
    const bits = hs.avalanche_bits.map(() => el('span', { class: 'bit' }));
    $('bits').replaceChildren(...bits);
    for (let r = 0; r <= 64; r += 4) {
      if (token !== S.playToken || S.step !== 1) return;
      $('sha-rounds').textContent = r;
      $('hash-out').textContent = hs.tx_id.slice(0, Math.round(64 * r / 64));
      await sleep(45);
    }
    $('hash-leaf').textContent = `leaf[${hs.tx_index}] = ${hs.leaf.slice(0, 8)}…`;
    for (let i = 0; i < bits.length; i += 16) {
      if (token !== S.playToken || S.step !== 1) return;
      for (let j = i; j < i + 16; j++) if (hs.avalanche_bits[j]) bits[j].classList.add('on');
      await sleep(40);
    }
    await sleep(800);
  }

  function drawMerkle(t) {
    const levels = t.block.merkle_levels;
    const top = levels.length - 1;
    const rows = levels.slice().reverse().map((level, r) => {
      const l = top - r;
      const name = l === top ? 'root' : l === 0 ? 'leaves' : `level ${l}`;
      const cls = l === top ? 'node is-root' : l === 0 ? 'node' : l === 1 ? 'node l1' : 'node mid';
      // Leaves appear first, the root last: delay grows with the level.
      return el('div', { class: 'merkle-row' },
        el('span', { class: 'eyebrow', text: name }),
        el('div', { class: 'tree-level' }, ...level.map((h, i) => el('span', {
          class: cls, title: h, text: h.slice(0, 8), style: { animationDelay: `${l * 450 + i * 50}ms` },
        }))));
    });
    $('merkle-rows').replaceChildren(...rows,
      el('div', { class: 'hash-flow', style: { justifyContent: 'center' } },
        el('span', { class: 'chip', text: 'parent = H(0x01 ‖ L ‖ R)' }),
        el('span', { class: 'chip', style: { background: 'var(--sand)', color: '#4A3F30' }, text: 'odd tail → pairs with itself' }),
        el('span', { class: 'chip', style: { background: 'var(--sage)', color: '#33402C' }, text: `proof = ${top} hashes` })));
    return sleep(top * 450 + 1200);
  }

  async function drawPow(t) {
    const b = t.block;
    const token = S.playToken;
    const field = (bg, txt, color) => el('div', { style: { background: bg, color: color || 'var(--ink)' }, title: txt, text: txt });
    const nonceField = field('var(--teal-900)', 'n=0', 'var(--cream)');
    $('header-fields').replaceChildren(
      field('var(--sage)', String(b.index)),
      field('var(--teal-200)', `prev ${short(b.previous_hash)}`),
      field('var(--teal-400)', `merkle ${short(b.merkle_root)}`),
      field('var(--sage)', 'time'),
      field('var(--sand)', `D=${b.difficulty}`),
      nonceField);
    $('pow-target').replaceChildren(`target: first ${t.target_bits} bits zero`, el('br'),
      el('span', { class: 'mono', style: { color: 'var(--teal-50)' }, text: `hash < 2^${256 - t.target_bits}` }), el('br'),
      `expected ≈ 2^${t.target_bits} = ${2 ** t.target_bits}`);
    const list = $('tries');
    list.replaceChildren();
    const C = 2 * Math.PI * 64;
    const total = t.hashes_tried;
    const skipped = total - t.attempts.length;
    const delay = Math.max(25, Math.min(140, 2400 / t.attempts.length));
    for (let i = 0; i < t.attempts.length; i++) {
      if (token !== S.playToken || S.step !== 3) return;
      const a = t.attempts[i];
      nonceField.textContent = `n=${a.nonce}`;
      $('pow-count').textContent = fmt(skipped + i + 1);
      $('pow-ring').setAttribute('stroke-dasharray', `${(C * (skipped + i + 1) / total).toFixed(1)} ${C.toFixed(1)}`);
      list.append(el('div', { class: `try${a.ok ? ' ok' : ''}` },
        el('span', { text: `n=${a.nonce}` }), el('span', { text: `${a.hash.slice(0, 16)}…` }), el('span', { text: a.ok ? 'FOUND' : '×' })));
      while (list.children.length > 16) list.firstChild.remove();
      await sleep(delay);
    }
    await sleep(1000);
  }

  function drawAppend(t) {
    const idx = t.block.index;
    const blocks = S.state ? S.state.blocks.filter((b) => b.index >= idx - 2 && b.index <= idx) : [];
    const items = [];
    blocks.forEach((b, i) => {
      if (i > 0) items.push(linkSvg(false));
      items.push(el('div', { class: `mini-block${b.index === idx ? ' is-new' : ''}` },
        el('div', { class: 'num', text: `#${b.index}` }),
        el('div', { class: 'eyebrow', style: { marginTop: '10px', color: 'inherit', opacity: 0.75, fontSize: '11px' }, text: 'hash' }),
        el('div', { class: 'mono', style: { fontSize: '13px' }, text: short(b.hash, 8, 4) }),
        el('div', { class: 'eyebrow', style: { marginTop: '6px', color: 'inherit', opacity: 0.75, fontSize: '11px' }, text: 'prev' }),
        el('div', { class: 'mono', style: { fontSize: '13px' }, text: short(b.previous_hash, 8, 4) })));
    });
    $('append-chain').replaceChildren(...items);
    const bal = t.balances;
    const fact = (title, text) => el('div', { class: 'card' }, el('h3', { text: title }), el('div', { style: { fontSize: '14px', color: 'var(--ink-2)' }, text }));
    $('facts').replaceChildren(
      fact('Validator', 'prev_hash matches tip · PoW ok · Merkle root recomputed · coinbase ≤ reward + fees'),
      fact('UTXO hash map', `${t.utxo_delta.spent} spent output${t.utxo_delta.spent === 1 ? '' : 's'} removed · ${t.utxo_delta.created} new (tx_id, index) keys`),
      fact('Balances now', `Miner ${fmt(bal.Miner)} · Alice ${fmt(bal.Alice)} · Bob ${fmt(bal.Bob)}`));
    return sleep(2600);
  }

  function stopPlay() {
    S.playing = false;
    S.playToken += 1;
    $('step-play').textContent = 'Play';
    $('step-play').setAttribute('aria-pressed', 'false');
  }

  async function play(from) {
    stopPlay();
    S.playing = true;
    const token = S.playToken;
    $('step-play').textContent = 'Pause';
    $('step-play').setAttribute('aria-pressed', 'true');
    for (let n = from; n < STEPS.length; n++) {
      if (token !== S.playToken) return;
      await setStep(n);
      if (token !== S.playToken) return;
      await sleep(1600);
    }
    if (token === S.playToken) stopPlay();
  }

  async function mineAndWatch() {
    if (S.mining) return;
    S.mining = true;
    const btns = [$('mine-btn'), $('forge-mine')];
    btns.forEach((b) => { b.disabled = true; });
    $('next-card').classList.add('is-mining');
    $('forge-title').textContent = 'Mining…';
    try {
      const trace = await api.post('/api/mine');
      S.trace = trace;
      await refresh();
      $('forge-select').value = String(trace.block.index);
      showRender();
      play(0);
    } catch (err) {
      $('forge-title').textContent = `Could not mine: ${err.message}`;
    } finally {
      S.mining = false;
      btns.forEach((b) => { b.disabled = false; });
      $('next-card').classList.remove('is-mining');
    }
  }

  async function showRender() {
    if (!S.trace) return;
    const name = `block_${S.trace.block.index}.mp4`;
    if (!S.renders.has(name)) {
      try { (await api.get('/api/renders')).forEach((f) => S.renders.add(f)); } catch (_) { /* renders are optional */ }
    }
    const video = $('render-video');
    if (S.renders.has(name)) {
      video.src = `/renders/${name}`;
      video.classList.remove('hidden');
      $('render-note').textContent = `Manim render of block #${S.trace.block.index}`;
    } else {
      video.classList.add('hidden');
      video.removeAttribute('src');
      $('render-note').textContent = 'No Manim video for this block yet. Start the bridge with --render, or run python3 -m viz.render.';
    }
  }

  $('step-prev').addEventListener('click', () => { stopPlay(); if (S.trace) setStep(Math.max(0, S.step - 1)); });
  $('step-next').addEventListener('click', () => { stopPlay(); if (S.trace) setStep(S.step >= 4 ? 0 : S.step + 1); });
  $('step-play').addEventListener('click', () => { if (S.playing) stopPlay(); else if (S.trace) play(S.step >= 4 ? 0 : S.step); });
  $('pow-replay').addEventListener('click', () => { stopPlay(); if (S.trace) setStep(3); });
  $('forge-select').addEventListener('change', (e) => { stopPlay(); loadTrace(Number(e.target.value)); });
  $('forge-mine').addEventListener('click', mineAndWatch);

  // ------------------------------------------------------------------ toasts

  const ICONS = {
    ok: 'M5 12l5 5 9-10',
    danger: 'M12 4 3 20h18L12 4zM12 10v4M12 17v.5',
  };
  function toast(title, body, kind) {
    const icon = svg('svg', { width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', stroke: '#FAF6F0', 'stroke-width': 2.4, 'stroke-linecap': 'round', 'aria-hidden': 'true' });
    icon.append(svg('path', { d: ICONS[kind] || ICONS.ok }));
    const node = el('div', { class: `toast${kind === 'danger' ? ' is-danger' : ''}`, role: 'status' },
      el('span', { class: 'icon' }, icon),
      el('div', {}, el('b', { text: title }), el('span', { text: body })),
      el('button', { type: 'button', 'aria-label': 'Dismiss', text: '×', onclick: () => dismiss() }));
    const dismiss = () => {
      node.classList.add('is-leaving');
      setTimeout(() => node.remove(), 300);
    };
    $('toasts').prepend(node);
    while ($('toasts').children.length > 4) $('toasts').lastChild.remove();
    setTimeout(dismiss, kind === 'danger' ? 9000 : 7000);
  }

  // ------------------------------------------------------------------ ledger copies (tamper lab)

  S.repairedFlash = {};
  S.lastTamper = null;
  let auditDeadline = 0;

  async function refreshNetwork() {
    try {
      S.state.network = await api.get('/api/network');
      renderNetwork();
      renderPeoplePage();
    } catch (_) { /* the next state refresh will catch up */ }
  }

  function renderNetwork() {
    const net = S.state && S.state.network;
    if (!net) return;
    auditDeadline = Date.now() + net.next_audit_in * 1000;
    tickAudit();
    const now = Date.now();
    const tampered = net.peers.filter((p) => p.status === 'tampered');
    $('copies-summary').textContent = `${net.peers.length} copies · ${tampered.length ? `${tampered.length} tampered` : 'all in sync'}`;
    $('copies').replaceChildren(...net.peers.map((p) => {
      const flash = S.repairedFlash[p.name] && S.repairedFlash[p.name] > now;
      const bad = p.status === 'tampered';
      const danger = bad ? (() => {
        const i = svg('svg', { width: 16, height: 16, viewBox: '0 0 24 24', fill: 'none', stroke: '#FAF6F0', 'stroke-width': 2.6, 'stroke-linecap': 'round', 'aria-hidden': 'true' });
        i.append(svg('path', { d: ICONS.danger }));
        return el('span', { class: 'danger', title: 'Tampered copy' }, i);
      })() : null;
      return el('div', { class: `copy${bad ? ' is-tampered' : flash ? ' is-repaired' : ''}`, 'aria-label': `${p.name}: ${bad ? `tampered at block ${p.tampered_block}` : flash ? 'restored' : 'in sync'}` },
        el('span', { class: 'avatar', 'aria-hidden': 'true', text: p.name[0] }),
        el('div', { class: 'who' }, el('b', { text: p.name }),
          el('span', { text: bad ? `⚠ block #${p.tampered_block} changed` : flash ? '↺ restored' : `✓ ${p.height} blocks` })),
        danger);
    }));
  }

  function tickAudit() {
    const net = S.state && S.state.network;
    if (!net) return;
    const left = Math.max(0, (auditDeadline - Date.now()) / 1000);
    const C = 2 * Math.PI * 26;
    const frac = net.audit_interval ? 1 - left / net.audit_interval : 0;
    $('audit-ring').setAttribute('stroke-dasharray', `${(C * Math.max(0, Math.min(1, frac))).toFixed(1)} ${C.toFixed(1)}`);
    $('audit-count').textContent = `${Math.ceil(left)}s`;
    const last = net.last_audit;
    $('audit-text').textContent = last
      ? `Every ${net.audit_interval}s · last: ${last.valid_copies}/${last.copies} valid${last.repaired.length ? `, ${last.repaired.length} repaired` : ''}`
      : `Every ${net.audit_interval}s every copy is checked`;
  }
  setInterval(tickAudit, 1000);

  async function onTamperBlockChange() {
    const idx = Number($('tamper-block').value);
    if (!idx) return;
    try {
      const d = await api.get(`/api/block?index=${idx}`);
      $('tamper-tx').replaceChildren(...d.transactions.map((tx, i) => el('option', {
        value: i, 'data-amount': tx.outputs[0].amount,
        text: tx.type === 'coinbase' ? `${i} · coinbase → ${tx.outputs[0].to} · ${tx.outputs[0].amount}` : `${i} · ${tx.from} → ${tx.outputs[0].to} · ${tx.outputs[0].amount}`,
      })));
      if (d.transactions.length > 1) $('tamper-tx').value = '1';
      onTamperTxChange();
    } catch (err) {
      toast('Could not load the block', err.message, 'danger');
    }
  }

  function onTamperTxChange() {
    const opt = $('tamper-tx').selectedOptions[0];
    if (opt) $('tamper-amount').value = Number(opt.dataset.amount) * 100;
  }

  function renderLab(r) {
    $('lab-result').classList.remove('hidden');
    const idx = r.block_index;
    const fixed = Boolean(r.repaired);
    const blocks = S.state.blocks.filter((b) => b.index >= idx - 1 && b.index <= idx + 3);
    const items = [];
    blocks.forEach((b, i) => {
      const edited = !fixed && b.index === idx;
      const down = !fixed && b.index > idx;
      if (i > 0) {
        const bad = !fixed && b.index > idx;
        items.push(el('div', { class: `lab-link${bad ? ' is-bad' : ''}` }, linkSvg(bad),
          el('span', { text: bad ? (b.index === idx + 1 ? 'broken' : 'orphaned') : 'linked' })));
      }
      items.push(el('div', { class: `lab-block${edited ? ' is-edited' : down ? ' is-down' : ''}` },
        el('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' } },
          el('span', { class: 'num', text: `#${b.index}` }),
          el('span', { class: `chip${edited || down ? ' chip-danger' : ''}`, text: edited ? 'EDITED' : down ? 'INVALID' : fixed && b.index === idx ? 'RESTORED' : 'VALID' })),
        el('div', { class: 'k', text: 'prev' }),
        el('div', { class: `v${!fixed && b.index === idx + 1 ? ' bad' : ''}`, style: !fixed && b.index === idx + 1 ? { textDecoration: 'line-through' } : {}, text: short(b.previous_hash) }),
        el('div', { class: 'k', text: 'merkle root' }),
        el('div', { class: `v${edited ? ' bad' : ''}`, text: edited ? short(r.recomputed_merkle_root) : short(b.merkle_root) }),
        el('div', { class: 'k', text: 'hash' }),
        el('div', { class: `v${edited ? ' bad' : ''}`, style: edited ? {} : { color: 'var(--teal-900)' }, text: edited ? short(r.recomputed_block_hash) : short(b.hash) }),
        el('div', { style: { marginTop: '8px', fontSize: '13px', color: 'var(--ink-2)' },
          text: fixed ? (b.index === idx ? `Back to ${r.old_amount} from the majority` : `${b.tx_count} tx · PoW ok`)
            : edited ? `Amount ${r.old_amount} → ${r.new_amount} → tx_id → root → hash`
              : b.index === idx + 1 ? 'Still points at the OLD hash' : down ? 'Built on a broken parent' : `${b.tx_count} tx · PoW ok` })));
    });
    $('lab-chain').replaceChildren(...items);

    const kv = [
      ['Whose copy', `${r.name} (only this copy; everyone else is untouched)`],
      ['Amount', `${r.old_amount} → ${r.new_amount}`],
      ['tx_id', `${short(r.original_tx_id)} → ${short(r.tampered_tx_id)}`],
      ['Signature', r.signature_valid_after_tamper ? 'still valid (!)' : 'no longer valid: it signed the old amount'],
      ['Merkle root', `header ${short(r.original_merkle_root)} ≠ recomputed ${short(r.recomputed_merkle_root)}`],
      ['Block hash', `${short(r.original_block_hash)} → ${short(r.recomputed_block_hash)} if the root were updated`],
    ];
    $('lab-kv').replaceChildren(...kv.flatMap(([k, v]) => [el('dt', { text: k }),
      el('dd', { text: v, style: k !== 'Whose copy' && !fixed ? { color: 'var(--danger)' } : {} })]));

    const line = (cls, text) => el('div', { class: cls, text });
    const lines = [
      line('err', `⚠ ${r.name}'s copy: block #${idx} amount ${r.old_amount} → ${r.new_amount}`),
      line('err', `✗ #${idx}  merkle root mismatch · signature ${r.signature_valid_after_tamper ? 'valid' : 'invalid'}`),
      r.downstream_broken.length ? line('err', `✗ #${r.downstream_broken[0]} … #${r.downstream_broken[r.downstream_broken.length - 1]}  previous_hash chain broken in this copy`) : null,
    ];
    if (fixed) {
      lines.push(
        line('', `network check: ${r.repaired.majority_size} of ${r.repaired.copies} copies valid and identical`),
        line('ok', `✓ ${r.name}'s copy replaced with the majority ledger`),
        line('ok', `✓ block #${idx} amount is ${r.old_amount} again · copy in sync`));
    } else {
      lines.push(line('', `… waiting for the next network check (every ${S.state.network.audit_interval}s) — or press Check now`));
    }
    $('lab-log').replaceChildren(...lines.filter(Boolean));
  }

  $('tamper-block').addEventListener('change', onTamperBlockChange);
  $('tamper-tx').addEventListener('change', onTamperTxChange);
  $('tamper-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const btn = $('tamper-btn');
    btn.disabled = true;
    try {
      S.lastTamper = await api.post('/api/network/tamper', {
        name: $('tamper-person').value,
        block: Number($('tamper-block').value),
        tx: Number($('tamper-tx').value),
        amount: Number($('tamper-amount').value),
      });
      renderLab(S.lastTamper);
      refreshNetwork();
    } catch (err) {
      toast('Tamper refused', err.message, 'danger');
    } finally {
      btn.disabled = false;
    }
  });
  $('audit-now').addEventListener('click', async () => {
    const btn = $('audit-now');
    btn.disabled = true;
    try { await api.post('/api/network/audit'); } catch (err) { toast('Network check failed', err.message, 'danger'); }
    btn.disabled = false;
  });

  // ------------------------------------------------------------------ people page

  function fillSelect(sel, names, fallback) {
    const keep = sel.value;
    sel.replaceChildren(...names.map((n) => el('option', { value: n, text: n })));
    sel.value = names.includes(keep) ? keep : fallback;
  }

  function renderPeoplePage() {
    if (!S.state) return;
    const wallets = S.state.wallets;
    const names = wallets.map((w) => w.name);
    fillSelect($('manual-from'), names, names.includes('Alice') ? 'Alice' : names[0]);
    const from = $('manual-from').value;
    fillSelect($('manual-to'), names.filter((n) => n !== from), names.includes('Bob') && from !== 'Bob' ? 'Bob' : names.find((n) => n !== from));
    const me = wallets.find((w) => w.name === from);
    const note = $('manual-note');
    if (!note.dataset.locked) note.textContent = `From balance: ${me ? fmt(me.balance) : '–'} coins`;

    const mempool = S.state.mempool;
    $('pending-count').textContent = `${mempool.length} waiting`;
    $('pending-list').replaceChildren(...(mempool.length ? mempool.map((tx) => el('div', { class: 'list-item' },
      el('span', {}, el('span', { class: 'mono', style: { color: 'var(--teal-900)' }, text: tx.tx_id.slice(0, 8) }),
        ` · ${tx.from} → ${tx.outputs[0].to}`),
      el('span', { class: 'mono', style: { fontWeight: 500 }, text: tx.outputs[0].amount })))
      : [el('p', { class: 'muted', style: { margin: 0, fontSize: '14px' }, text: 'Nothing pending. Add a transaction, or press the button to add a block with just the Miner’s reward.' })]));
    $('auto-warning').classList.toggle('hidden', !S.state.consensus.auto_mining);

    const peers = new Map(((S.state.network || {}).peers || []).map((p) => [p.name, p]));
    $('everyone-count').textContent = `${wallets.length} people · ${peers.size} ledger copies`;
    $('people-grid').replaceChildren(...wallets.map((w) => {
      const p = peers.get(w.name);
      const status = p ? (p.status === 'tampered' ? `⚠ copy tampered (#${p.tampered_block})` : `✓ copy in sync`) : '';
      return el('button', {
        type: 'button', class: `person-card${w.name === S.newPerson ? ' is-new' : ''}`,
        title: `Use ${w.name} as the sender`, onclick: () => { $('manual-from').value = w.name; renderPeoplePage(); },
      },
        el('span', { class: 'avatar', 'aria-hidden': 'true', text: w.name[0] }),
        el('span', { class: 'meta' }, el('b', { text: `${w.name} · ${fmt(w.balance)}` }),
          el('span', { text: `${w.address.slice(0, 10)}… ${status}` })));
    }));
  }

  $('manual-from').addEventListener('change', renderPeoplePage);

  $('person-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const note = $('person-note');
    const btn = $('person-btn');
    btn.disabled = true;
    note.className = 'form-note';
    note.textContent = 'Generating RSA keys and copying the ledger…';
    try {
      const res = await api.post('/api/people', { name: $('person-name').value, fund: Number($('person-fund').value || 0) });
      S.newPerson = res.person.name;
      note.textContent = `${res.person.name} added · address ${res.person.address.slice(0, 12)}…${res.funding_tx ? ` · ${res.funding_tx.outputs[0].amount} coins pending — add a block to deliver them` : ''}${res.fund_error ? ` · funding failed: ${res.fund_error}` : ''}`;
      $('person-name').value = '';
      await refresh();
    } catch (err) {
      note.className = 'form-note is-error';
      note.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  });

  $('manual-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const note = $('manual-note');
    const btn = $('manual-btn');
    btn.disabled = true;
    note.dataset.locked = '1';
    note.className = 'form-note';
    try {
      const res = await api.post('/api/tx', {
        from: $('manual-from').value, to: $('manual-to').value,
        amount: Number($('manual-amount').value), fee: Number($('manual-fee').value),
      });
      const tx = res.tx;
      note.textContent = `Added to pending: ${tx.from} → ${tx.outputs[0].to} · ${tx.outputs[0].amount} (tx ${tx.tx_id.slice(0, 8)}). Press “Add block to blockchain” to confirm it.`;
      await refresh();
    } catch (err) {
      note.className = 'form-note is-error';
      note.textContent = err.message;
    } finally {
      btn.disabled = false;
      setTimeout(() => { delete note.dataset.locked; }, 6000);
    }
  });

  $('add-block-btn').addEventListener('click', async () => {
    const btn = $('add-block-btn');
    const note = $('add-block-note');
    btn.disabled = true;
    S.mining = true;
    note.textContent = `Mining at difficulty ${S.state.consensus.next_difficulty} bits…`;
    try {
      const t = await api.post('/api/mine');
      const b = t.block;
      note.textContent = `Block #${b.index} added · ${b.transactions.length} transaction${b.transactions.length === 1 ? '' : 's'} · nonce ${b.nonce} · ${fmt(t.hashes_tried)} hashes`;
      toast(`Block #${b.index} added to the blockchain`, `${b.transactions.length - 1} transfer${b.transactions.length === 2 ? '' : 's'} confirmed, every ledger copy updated.`, 'ok');
      await refresh();
    } catch (err) {
      note.textContent = `Could not add the block: ${err.message}`;
    } finally {
      S.mining = false;
      btn.disabled = false;
    }
  });

  $('auto-off').addEventListener('click', async () => {
    await api.post('/api/autominer', { on: false });
    refresh();
  });

  // ------------------------------------------------------------------ boot

  (async () => {
    connectEvents();
    await refresh();
    route();
  })();
})();
