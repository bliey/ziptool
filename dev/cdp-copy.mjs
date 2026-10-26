// 验证复制按钮走的是 navigator.clipboard（带用户手势 + 剪贴板权限）
const PORT = process.argv[2] || '9333';
const URL_ = process.argv[3];
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
const send = (method, params, sessionId) => {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
};

const origin = new URL(URL_).origin;
await send('Browser.grantPermissions', {
  origin,
  permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite']
});

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Runtime.enable', {}, sessionId);
await send('Page.navigate', { url: URL_ }, sessionId);
await sleep(1500);

const expr = `(async () => {
  const wait = ms => new Promise(r => setTimeout(r, ms));
  const input = document.getElementById('md5Input');
  const dt = new DataTransfer();
  dt.items.add(new File([new Uint8Array([0, 37, 74])], 'tiny.bin'));
  input.files = dt.files;
  input.dispatchEvent(new Event('change'));
  const t0 = Date.now();
  while (Date.now() - t0 < 20000 && document.getElementById('md5Val').textContent.length !== 32) await wait(50);
  const md5 = document.getElementById('md5Val').textContent;
  const btn = document.getElementById('md5Copy');
  const hasApi = !!(navigator.clipboard && navigator.clipboard.writeText);
  btn.click();
  await wait(400);
  let clip = null;
  try { clip = await navigator.clipboard.readText(); } catch (e) { clip = 'ERR:' + e.name; }
  return { md5, hasApi, btnText: btn.textContent, clip };
})()`;

const r = await send('Runtime.evaluate', {
  expression: expr,
  awaitPromise: true,
  returnByValue: true,
  userGesture: true
}, sessionId);

console.log(JSON.stringify(r.result && r.result.value ? r.result.value : r, null, 1));
await send('Target.closeTarget', { targetId }).catch(() => {});
ws.close();
