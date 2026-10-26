// 截取 MD5 区块：node dev/cdp-shot.mjs <port> <url> <width> <height> <light|dark> <outfile> [done|progress]
const [PORT = '9333', URL_, W = '900', H = '1200', SCHEME = 'light', OUT, MODE = 'done'] = process.argv.slice(2);
const sleep = ms => new Promise(r => setTimeout(r, ms));

const ver = await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json();
const ws = new WebSocket(ver.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws fail')); });

let seq = 0;
const pending = new Map();
ws.onmessage = ev => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  }
};
const send = (m, p, s) => {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method: m, params: p, sessionId: s }));
  });
};

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Runtime.enable', {}, sessionId);
await send('Emulation.setDeviceMetricsOverride', {
  width: +W, height: +H, deviceScaleFactor: 2, mobile: false
}, sessionId);
await send('Emulation.setEmulatedMedia', {
  features: [{ name: 'prefers-color-scheme', value: SCHEME }]
}, sessionId);
await send('Page.navigate', { url: URL_ }, sessionId);
await sleep(1800);

await send('Runtime.evaluate', {
  expression: `(async () => {
    const wait = ms => new Promise(r => setTimeout(r, ms));
    const $ = id => document.getElementById(id);
    const gen = n => { const b = new Uint8Array(n); for (let i = 0; i < n; i++) b[i] = (i * 37 + ((i >> 8) * 11)) & 0xff; return b; };
    const MB = 1024 * 1024;
    const isProgress = ${MODE === 'progress'};
    const dt = new DataTransfer();
    dt.items.add(new File([gen(5 * MB)], '示例文件.zip'));
    const input = $('md5Input');
    input.files = dt.files;
    input.dispatchEvent(new Event('change'));
    if (isProgress) {
      await wait(60);
      const part = gen(4 * MB), parts = [];
      for (let i = 0; i < 220; i++) parts.push(part);
      const dt2 = new DataTransfer();
      dt2.items.add(new File(parts, '大型备份.zip'));
      input.files = dt2.files;
      input.dispatchEvent(new Event('change'));
      await wait(700);
      window.scrollTo(0, $('md5card').offsetTop - 12);
      return $('md5Pct').textContent;
    }
    const t0 = Date.now();
    while (Date.now() - t0 < 30000 && $('md5Val').textContent.length !== 32) await wait(50);
    await wait(300);
    window.scrollTo(0, $('md5card').offsetTop - 12);
    return $('md5Val').textContent;
  })()`,
  awaitPromise: true, returnByValue: true, userGesture: true
}, sessionId);

await sleep(600);
const shot = await send('Page.captureScreenshot', { format: 'png' }, sessionId);
const fs = await import('node:fs');
fs.writeFileSync(OUT, Buffer.from(shot.data, 'base64'));
console.log('saved', OUT);
await send('Target.closeTarget', { targetId }).catch(() => {});
ws.close();
