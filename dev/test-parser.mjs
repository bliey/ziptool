/*
 * dev/test-parser.mjs — 解析核心的自测脚本（不参与页面部署）
 * 运行：node dev/test-parser.mjs
 *
 * 用 Node 手工构造各种 ZIP 结构（含 GBK 文件名、ZipCrypto、AES、ZIP64 标记、截断），
 * 检查 assets/zip-inspector.js 的判定是否符合预期。
 */
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const src = fs.readFileSync(path.join(here, '..', 'assets', 'zip-inspector.js'), 'utf8');
vm.runInThisContext(src);
const { inspect } = globalThis.ZipInspector;

/* ---------------------------------------------------------------- 构造 ZIP */

function u16(n) { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; }
function u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; }

function buildZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const e of entries) {
    const name = Buffer.isBuffer(e.name) ? e.name : Buffer.from(e.name, 'utf8');
    const extra = e.extra || Buffer.alloc(0);
    const data = e.data || Buffer.from('x'.repeat(e.size ?? 10));
    const method = e.method ?? 8;
    const flags = e.flags ?? 0;
    const crc = e.crc ?? 0;

    const local = Buffer.concat([
      Buffer.from([0x50, 0x4b, 0x03, 0x04]),
      u16(20), u16(flags), u16(method), u16(0), u16(0),
      u32(crc), u32(data.length), u32(e.usize ?? data.length),
      u16(name.length), u16(extra.length),
      name, extra, data
    ]);

    const central = Buffer.concat([
      Buffer.from([0x50, 0x4b, 0x01, 0x02]),
      u16(20), u16(20), u16(flags), u16(method), u16(0), u16(0),
      u32(crc), u32(data.length), u32(e.usize ?? data.length),
      u16(name.length), u16(extra.length), u16(0), u16(0), u16(0), u32(0),
      u32(offset),
      name, extra
    ]);

    locals.push(local);
    centrals.push(central);
    offset += local.length;
  }

  const cd = Buffer.concat(centrals);
  const cdOffset = offset;
  const eocd = Buffer.concat([
    Buffer.from([0x50, 0x4b, 0x05, 0x06]),
    u16(0), u16(0), u16(entries.length), u16(entries.length),
    u32(cd.length), u32(cdOffset), u16(0)
  ]);

  return Buffer.concat([...locals, cd, eocd]);
}

function aesExtra(strength) {
  return Buffer.concat([
    u16(0x9901), u16(7), u16(2), Buffer.from('AE', 'ascii'), Buffer.from([strength]), u16(8)
  ]);
}

/* ------------------------------------------------------------------ 断言 */

let pass = 0, fail = 0;

function check(label, cond, detail) {
  if (cond) { pass++; console.log('  ok   ' + label); }
  else { fail++; console.log('  FAIL ' + label + (detail ? '  →  ' + detail : '')); }
}

async function run(name, bytes, assertions) {
  console.log('\n[' + name + ']');
  const file = new File([bytes], name + '.zip');
  let report;
  try {
    report = await inspect(file);
  } catch (err) {
    check('解析未抛错', false, err.message);
    return null;
  }
  await assertions(report);
  return report;
}

/* ------------------------------------------------------------------ 用例 */

// 1. 普通包：UTF-8 中文名（带 bit 11）
await run('plain-utf8', buildZip([
  { name: '说明.txt', flags: 0x0800, method: 8 },
  { name: 'docs/readme.md', flags: 0x0800, method: 0 }
]), (r) => {
  check('条目数 2', r.entries.length === 2, r.entries.length);
  check('中文名正确', r.entries[0].name === '说明.txt', r.entries[0].name);
  check('编码识别为 utf-8', r.entries[0].nameEncoding === 'utf-8', r.entries[0].nameEncoding);
  check('未加密', r.entries.every((e) => !e.isEncrypted));
  check('无警告', r.warnings.length === 0, r.warnings.join('|'));
});

// 2. GBK 文件名、不设 bit 11（Windows 资源管理器 / 国产压缩软件的典型输出）
await run('gbk-name', buildZip([
  { name: Buffer.from([0xB2, 0xE2, 0xCA, 0xD4, 0x2E, 0x74, 0x78, 0x74]), method: 8 }
]), (r) => {
  check('GBK 名解码为「测试.txt」', r.entries[0].name === '测试.txt', r.entries[0].name);
  check('编码标记为 gbk', r.entries[0].nameEncoding === 'gbk', r.entries[0].nameEncoding);
});

// 3. 西欧 CP437 名（不应被误判成 GBK 乱码）
await run('cp437-name', buildZip([
  { name: Buffer.from([0x63, 0x61, 0x66, 0x82, 0x2E, 0x74, 0x78, 0x74]), method: 8 }
]), (r) => {
  check('CP437 名解码为 café.txt', r.entries[0].name === 'café.txt', r.entries[0].name);
  check('编码标记为 cp437', r.entries[0].nameEncoding === 'cp437', r.entries[0].nameEncoding);
});

// 4. 传统 ZipCrypto
await run('zipcrypto', buildZip([
  { name: 'a.txt', flags: 0x0001, method: 8 },
  { name: 'b.txt', flags: 0x0001, method: 8 }
]), (r) => {
  check('两条都判为 ZipCrypto', r.entries.every((e) => e.encryptionType === 'ZipCrypto'));
});

// 5. WinZip AES-256
await run('aes256', buildZip([
  { name: 'secret.bin', flags: 0x0001, method: 99, extra: aesExtra(3) }
]), (r) => {
  check('判为 AES-256', r.entries[0].encryptionType === 'AES-256', r.entries[0].encryptionType);
  check('读到 vendor AE', r.entries[0].aes && r.entries[0].aes.vendor === 'AE');
  check('真实压缩方法为 8', r.entries[0].aes.actualMethod === 8);
});

// 6. method=99 但缺 0x9901 扩展字段
await run('aes-missing-extra', buildZip([
  { name: 'x.bin', flags: 0x0001, method: 99 }
]), (r) => {
  check('仍判为 AES', r.entries[0].encryptionType === 'AES', r.entries[0].encryptionType);
  check('给出缺字段提示', !!r.entries[0].note, r.entries[0].note);
});

// 7. PKWARE 强加密标志
await run('strong-encryption', buildZip([
  { name: 's.bin', flags: 0x0041, method: 8 }
]), (r) => {
  check('判为强加密', r.entries[0].encryptionType === '强加密（PKWARE）', r.entries[0].encryptionType);
});

// 8. 混合加密
await run('mixed', buildZip([
  { name: 'zc.txt', flags: 0x0001, method: 8 },
  { name: 'aes.txt', flags: 0x0001, method: 99, extra: aesExtra(1) }
]), (r) => {
  const types = new Set(r.entries.map((e) => e.encryptionType));
  check('同时存在两种类型', types.has('ZipCrypto') && types.has('AES-128'), [...types].join(','));
});

// 9. EOCD 偏移被写坏（模拟前置数据的自解压包）：把 cdOffset 改大
{
  const base = buildZip([{ name: 'a.txt', method: 8 }, { name: 'b.txt', method: 8 }]);
  const bad = Buffer.from(base);
  bad.writeUInt32LE(0x7fffffff, bad.length - 22 + 16); // cdOffset 字段
  await run('bad-cd-offset', bad, (r) => {
    check('仍解析出 2 条', r.entries.length === 2, r.entries.length);
    check('给出回推警告', r.warnings.some((w) => w.indexOf('回推') >= 0), r.warnings.join('|'));
  });
}

// 10. 截断文件（去掉 EOCD 尾部）
{
  const base = buildZip([{ name: 'a.txt', method: 8 }]);
  const cut = base.subarray(0, base.length - 10);
  console.log('\n[truncated]');
  try {
    await inspect(new File([cut], 'cut.zip'));
    check('应当报错', false);
  } catch (err) {
    check('报错信息合理', /EOCD/.test(err.message), err.message);
  }
}

// 11. 空压缩包
await run('empty', buildZip([]), (r) => {
  check('0 条目', r.entries.length === 0);
  check('无警告', r.warnings.length === 0, r.warnings.join('|'));
});

// 12. 大包分块读取（3000 条，中央目录 > 512KB 分块边界）
{
  const many = [];
  for (let i = 0; i < 3000; i++) many.push({ name: 'dir/file-' + i + '.txt', method: 8 });
  await run('many-entries', buildZip(many), (r) => {
    check('解析出 3000 条', r.entries.length === 3000, r.entries.length);
    check('最后一条名字正确', r.entries[2999].name === 'dir/file-2999.txt', r.entries[2999].name);
  });
}

// 13. 文件头指纹比对
{
  const { matchKnownHeaders, KNOWN_HEADERS } = globalThis.ZipInspector;
  const b = (arr) => new Uint8Array(arr);
  const h360 = matchKnownHeaders(b([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00]));
  const h2345 = matchKnownHeaders(b([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x01, 0x08, 0x08, 0x00]));
  const hrar = matchKnownHeaders(b([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x09, 0x00, 0x08, 0x00]));
  const hnone = matchKnownHeaders(b([0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00]));

  console.log('\n[header-fingerprint]');
  check('指纹表有 5 条', KNOWN_HEADERS.length === 5, KNOWN_HEADERS.length);
  check('360 命中', h360.length === 1 && h360[0].vendors.indexOf('7-Zip') >= 0, JSON.stringify(h360.map((h) => h.label)));
  check('2345 好压命中', h2345.length === 1 && h2345[0].vendors[0] === '2345 好压');
  check('0x0009 命中 Bandizip / WinRAR', hrar.length === 1 && hrar[0].vendors.length === 2, JSON.stringify(hrar.map((h) => h.vendors)));
  check('未知指纹不命中', hnone.length === 0);
}

// 14. 本地文件头解析 + 条目 localOffset
await run('local-header', buildZip([
  { name: Buffer.from([0xB2, 0xE2, 0xCA, 0xD4, 0x2E, 0x74, 0x78, 0x74]), flags: 0x0801, method: 8 },
  { name: 'b.txt', method: 0 }
]), async (r) => {
  check('条目带 localOffset', typeof r.entries[0].localOffset === 'number', r.entries[0].localOffset);
  check('第二个条目 offset > 0', r.entries[1].localOffset > 0, r.entries[1].localOffset);

  const info = await globalThis.ZipInspector.parseLocalHeader(new File([buildZip([
    { name: Buffer.from([0xB2, 0xE2, 0xCA, 0xD4, 0x2E, 0x74, 0x78, 0x74]), flags: 0x0801, method: 8 }
  ])], 'lh.zip'), 0);

  check('本地头签名有效', info.ok);
  check('版本 20', info.version === 20, info.version);
  check('标志 0x0801', info.flags === 0x0801, info.flags);
  check('方法 8', info.method === 8, info.method);
  check('文件名 GBK 解码正确', info.name === '测试.txt', info.name);
  check('标志位说明含「加密」', info.flagList.join('|').indexOf('加密') >= 0, info.flagList.join('|'));
});

// 15. 自解压包：前置 100 字节，偏移字段没有跟着改
{
  const base = buildZip([{ name: 'a.txt', method: 8 }, { name: 'b.txt', method: 8 }]);
  const sfx = Buffer.concat([Buffer.alloc(100, 0x4d), base]);
  console.log('\n[sfx-prefix]');

  const file = new File([sfx], 'sfx.exe');
  const r = await inspect(file);
  check('解析出 2 条', r.entries.length === 2, r.entries.length);
  check('localOffset 已平移 +100', r.entries[0].localOffset === 100, r.entries[0].localOffset);

  const lh = await globalThis.ZipInspector.parseLocalHeader(file, r.entries[0].localOffset);
  check('平移后仍指向真实本地头', lh.ok && lh.name === 'a.txt', lh.name);
}

console.log('\n通过 ' + pass + ' / 失败 ' + fail);
process.exit(fail ? 1 : 0);
