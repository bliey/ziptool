// 直接在 index.html 上跑（file:// 下 iframe 跨源，只能用这种方式验证）
const PORT = process.argv[2] || '9333';
const URL_ = process.argv[3];
const sleep = ms => new Promise(r => setTimeout(r, ms));

const ver = await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json();
const ws = new WebSocket(ver.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws fail')); });

let seq = 0;
const pending = new Map();
const logs = [];
ws.onmessage = ev => {
  const msg = JSON.parse(ev.data);
  if (msg.method === 'Runtime.exceptionThrown') {
    logs.push('EXC: ' + (msg.params.exceptionDetails.exception && msg.params.exceptionDetails.exception.description || msg.params.exceptionDetails.text));
  }
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  }
};
const send = (method, params, sessionId) => {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
};

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Runtime.enable', {}, sessionId);
await send('Log.enable', {}, sessionId).catch(() => {});
await send('Page.navigate', { url: URL_ }, sessionId);
await sleep(1800);

const expr = `(async () => {
  const wait = ms => new Promise(r => setTimeout(r, ms));
  const $ = id => document.getElementById(id);
  const env = {
    protocol: location.protocol,
    SparkMD5: typeof window.SparkMD5,
    QRCode: typeof window.QRCode,
    toCanvas: typeof (window.QRCode && window.QRCode.toCanvas),
    ZipInspector: typeof window.ZipInspector,
    scripts: [...document.scripts].map(s => s.src || '(inline)')
  };
  let qrText = null;
  const orig = window.QRCode.toCanvas;
  window.QRCode.toCanvas = function (c, t) { qrText = t; return orig.apply(this, arguments); };

  const gen = n => { const b = new Uint8Array(n); for (let i = 0; i < n; i++) b[i] = (i * 37 + ((i >> 8) * 11)) & 0xff; return b; };
  const dt = new DataTransfer();
  dt.items.add(new File([gen(3)], 'tiny.bin'));
  const input = $('md5Input');
  input.files = dt.files;
  input.dispatchEvent(new Event('change'));
  const t0 = Date.now();
  while (Date.now() - t0 < 20000 && $('md5Val').textContent.length !== 32) await wait(50);

  const c = $('md5Qr');
  const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
  let dark = 0;
  for (let i = 0; i < d.length; i += 4) if (d[i + 3] > 128 && d[i] < 128) dark++;

  return {
    env,
    md5: $('md5Val').textContent,
    md5ok: $('md5Val').textContent === 'd62478a52246cec25989b858b9b222ee',
    qrText, qrIsPlainMd5: qrText === 'd62478a52246cec25989b858b9b222ee',
    qrDark: dark,
    error: $('md5Error').hidden ? null : $('md5Error').textContent,
    privacy: document.querySelector('.md5privacy').textContent
  };
})()`;

const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true, userGesture: true }, sessionId);
console.log(JSON.stringify(r.result && r.result.value ? r.result.value : r, null, 1));
console.log('pageErrors:', JSON.stringify(logs));
await send('Target.closeTarget', { targetId }).catch(() => {});
ws.close();
