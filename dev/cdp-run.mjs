// 用 CDP 驱动无头 Chrome：不依赖 --virtual-time-budget，等待条件用真实时间轮询
// 用法: node dev/cdp-run.mjs <port> <url> <maxMs>
const PORT = process.argv[2] || '9333';
const TARGET_URL = process.argv[3];
const MAX_MS = Number(process.argv[4] || 300000);
const sleep = ms => new Promise(r => setTimeout(r, ms));

const ver = await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json();
const ws = new WebSocket(ver.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = e => rej(new Error('ws fail')); });

let seq = 0;
const pending = new Map();
ws.onmessage = ev => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(new Error(JSON.stringify(msg.error)));
    else resolve(msg.result);
  }
};
function send(method, params, sessionId) {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
}

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Runtime.enable', {}, sessionId);
await send('Page.enable', {}, sessionId);
await send('Page.navigate', { url: TARGET_URL }, sessionId);

const t0 = Date.now();
let result = null;
while (Date.now() - t0 < MAX_MS) {
  const r = await send('Runtime.evaluate', {
    expression: `(() => {
      const el = document.querySelector('#out');
      return el ? { title: document.title, text: el.textContent } : null;
    })()`,
    returnByValue: true
  }, sessionId);
  const v = r.result && r.result.value;
  if (v && (v.title === 'done' || v.title === 'fatal')) { result = v; break; }
  await sleep(500);
}

console.log(result ? result.text : 'TIMEOUT after ' + MAX_MS + 'ms');
await send('Target.closeTarget', { targetId }).catch(() => {});
ws.close();
