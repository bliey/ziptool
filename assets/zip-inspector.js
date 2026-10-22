/*
 * zip-inspector.js — ZIP 加密类型检测解析核心
 *
 * 设计要点：
 *  1. 只读取文件末尾的 EOCD 与中央目录，绝不整包载入内存，因此没有文件大小上限。
 *  2. 中央目录按 512KB 分块顺序读取，条目数极多（几十万）也不会一次性分配大块内存。
 *  3. 文件名解码走 UTF-8 标志位 → 严格 UTF-8 → GBK → CP437 的回退链，
 *     解决 Windows/国产压缩软件打的 GBK 文件名乱码问题。
 *  4. ZIP64 字段（0xFFFFFFFF）会真正去读 EOCD64，读不到则降级并给出警告，
 *     而不是把 0xFFFFFFFF 当成真实偏移报“文件被截断”。
 *  5. 中央目录偏移异常（自解压包前置数据、老工具写坏偏移）会按 EOCD 位置回推修正。
 *
 * 暴露：window.ZipInspector.inspect(file) -> Promise<Report>
 */
(function (global) {
  'use strict';

  var SIG_LOCAL = [0x50, 0x4b, 0x03, 0x04];
  var SIG_EOCD = [0x50, 0x4b, 0x05, 0x06];
  var SIG_EOCD64_LOCATOR = [0x50, 0x4b, 0x06, 0x07];
  var SIG_EOCD64 = [0x50, 0x4b, 0x06, 0x06];
  var SIG_CENTRAL = [0x50, 0x4b, 0x01, 0x02];

  var EOCD_MIN = 22;
  var MAX_COMMENT = 0xffff;
  var TAIL_WINDOW = EOCD_MIN + MAX_COMMENT;   // 65557
  var CHUNK = 512 * 1024;
  var MAX_ENTRIES = 500000;                   // 防御性上限，避免损坏文件把浏览器拖死

  var METHOD_NAMES = {
    0: 'Store（不压缩）',
    1: 'Shrink',
    6: 'Implode',
    8: 'Deflate',
    9: 'Deflate64',
    12: 'BZip2',
    14: 'LZMA',
    93: 'Zstandard',
    95: 'XZ',
    96: 'JPEG',
    97: 'WavPack',
    98: 'PPMd',
    99: 'AES（WinZip 方案）'
  };

  // CP437 高半区（0x80-0xFF），ZIP 规范在未声明编码时的默认字符集
  var CP437_HIGH =
    'ÇüéâäàåçêëèïîìÄÅ' +
    'ÉæÆôöòûùÿÖÜ¢£¥₧ƒ' +
    'áíóúñÑªº¿⌐¬½¼¡«»' +
    '░▒▓│┤╡╢╖╕╣║╗╝╜╛┐' +
    '└┴┬├─┼╞╟╚╔╩╦╠═╬╧' +
    '╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀' +
    'αßΓπΣσµτΦΘΩδ∞φε∩' +
    '≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00a0';

  /* ---------------------------------------------------------------- 基础工具 */

  function sigMatch(buf, pos, sig) {
    return buf[pos] === sig[0] && buf[pos + 1] === sig[1] &&
           buf[pos + 2] === sig[2] && buf[pos + 3] === sig[3];
  }

  function readRange(file, start, end) {
    var safeStart = Math.max(0, Math.min(start, file.size));
    var safeEnd = Math.max(safeStart, Math.min(end, file.size));
    if (safeEnd <= safeStart) return Promise.resolve(new Uint8Array(0));
    return file.slice(safeStart, safeEnd).arrayBuffer().then(function (buf) {
      return new Uint8Array(buf);
    });
  }

  function decode(label, bytes, fatal) {
    try {
      return new TextDecoder(label, { fatal: !!fatal }).decode(bytes);
    } catch (e) {
      return null;
    }
  }

  function decodeCp437(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      out += b < 0x80 ? String.fromCharCode(b) : CP437_HIGH.charAt(b - 0x80);
    }
    return out;
  }

  var RE_CJK = /[\u2e80-\u9fff\uf900-\ufaff\u3000-\u303f\uff00-\uffef]/;

  /**
   * 文件名解码。返回 { name, encoding }，encoding 用于在界面上说明用了哪种编码。
   */
  function decodeName(bytes, flags) {
    if (!bytes || bytes.length === 0) return { name: '', encoding: 'empty' };

    var ascii = true;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] > 0x7f) { ascii = false; break; }
    }
    if (ascii) return { name: decode('utf-8', bytes, false), encoding: 'ascii' };

    // 通用位标志 bit 11：文件名/注释为 UTF-8
    // 注意：部分国产软件会置上 bit 11 却仍写 GBK，所以这里先严格校验，不合法就继续回退
    if (flags & 0x0800) {
      var forced = decode('utf-8', bytes, true);
      if (forced !== null) return { name: forced, encoding: 'utf-8' };
    }

    var utf8 = decode('utf-8', bytes, true);
    if (utf8 !== null) return { name: utf8, encoding: 'utf-8' };

    // 中文环境下最常见的乱码来源：Windows 资源管理器 / 好压 / 360压缩 用 GBK 且不设 bit 11
    var gbk = decode('gbk', bytes, true);
    if (gbk !== null && RE_CJK.test(gbk)) return { name: gbk, encoding: 'gbk' };

    return { name: decodeCp437(bytes), encoding: 'cp437' };
  }

  function findEocd(tail) {
    var fallback = -1;
    for (var i = tail.length - EOCD_MIN; i >= 0; i--) {
      if (!sigMatch(tail, i, SIG_EOCD)) continue;
      var commentLen = tail[i + 20] | (tail[i + 21] << 8);
      if (i + EOCD_MIN + commentLen === tail.length) return i;
      if (fallback === -1) fallback = i;
    }
    return fallback;
  }

  /* -------------------------------------------------------- 分块读取中央目录 */

  function makeReader(file, start, length) {
    var buf = null, bufStart = 0, bufEnd = 0;

    return {
      ensure: function (offset, size) {
        var abs = start + offset;
        var remain = (start + length) - abs;
        var n = Math.min(size, remain, file.size - abs);
        if (n <= 0) return Promise.resolve(new Uint8Array(0));

        if (!buf || abs < bufStart || abs + n > bufEnd) {
          var end = Math.min(start + length, abs + Math.max(CHUNK, n), file.size);
          return readRange(file, abs, end).then(function (chunk) {
            buf = chunk;
            bufStart = abs;
            bufEnd = abs + chunk.length;
            return chunk.subarray(0, n);
          });
        }
        return Promise.resolve(buf.subarray(abs - bufStart, abs - bufStart + n));
      }
    };
  }

  /** 解析 WinZip AES 扩展字段（0x9901），返回强度/厂商/真实压缩方法 */
  function parseAesExtra(extra) {
    var p = 0;
    while (p + 4 <= extra.length) {
      var id = extra[p] | (extra[p + 1] << 8);
      var size = extra[p + 2] | (extra[p + 3] << 8);
      if (id === 0x9901 && size >= 7 && p + 11 <= extra.length) {
        return {
          version: extra[p + 4] | (extra[p + 5] << 8),
          vendor: String.fromCharCode(extra[p + 6], extra[p + 7]),
          strength: extra[p + 8],
          actualMethod: extra[p + 9] | (extra[p + 10] << 8)
        };
      }
      if (size <= 0) break;              // 防止损坏字段导致死循环
      p += 4 + size;
    }
    return null;
  }

  /* -------------------------------------------------------------- 主流程 */

  function inspect(file) {
    var warnings = [];

    return Promise.resolve().then(function () {
      if (!file || typeof file.size !== 'number') throw new Error('没有取到文件。');
      if (file.size < EOCD_MIN) {
        throw new Error('文件只有 ' + file.size + ' 字节，不可能是有效的 ZIP（最小 22 字节）。');
      }
      return readRange(file, file.size - Math.min(file.size, TAIL_WINDOW), file.size);
    }).then(function (tail) {
      var eocdPos = findEocd(tail);
      if (eocdPos < 0) throw new Error('找不到 EOCD 记录：不是 ZIP，或文件已损坏 / 被截断。');

      var absEocd = file.size - tail.length + eocdPos;
      var dv = new DataView(tail.buffer, tail.byteOffset + eocdPos, EOCD_MIN);

      var diskNumber = dv.getUint16(4, true);
      var cdDisk = dv.getUint16(6, true);
      var entriesOnDisk = dv.getUint16(8, true);
      var entryCount = dv.getUint16(10, true);
      var cdSize = dv.getUint32(12, true);
      var cdOffset = dv.getUint32(16, true);

      if (diskNumber !== 0 || cdDisk !== 0 || entriesOnDisk !== entryCount) {
        warnings.push('这个包声明为分卷压缩（第 ' + (diskNumber + 1) + ' 卷）。单卷文件只能看到当前卷的条目，结论可能不完整。');
      }

      var zip64 = false;
      var needZip64 = entryCount === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff;

      // 找 ZIP64 定位器：规范要求紧贴 EOCD 之前，但个别实现会多几个字节，做一次小范围回扫
      var locAbs = -1;
      if (eocdPos >= 20 && sigMatch(tail, eocdPos - 20, SIG_EOCD64_LOCATOR)) {
        locAbs = absEocd - 20;
      } else if (needZip64) {
        for (var k = 20; k <= 64 && eocdPos - k >= 0; k++) {
          if (sigMatch(tail, eocdPos - k, SIG_EOCD64_LOCATOR)) { locAbs = absEocd - k; break; }
        }
      }

      var zip64Promise = Promise.resolve(null);
      if (locAbs >= 0) {
        zip64Promise = readRange(file, locAbs, locAbs + 20).then(function (loc) {
          if (loc.length < 20 || !sigMatch(loc, 0, SIG_EOCD64_LOCATOR)) return null;
          var eocd64Offset = Number(new DataView(loc.buffer, loc.byteOffset, 20).getBigUint64(8, true));
          return readRange(file, eocd64Offset, eocd64Offset + 56).then(function (rec) {
            if (rec.length < 56 || !sigMatch(rec, 0, SIG_EOCD64)) {
              warnings.push('检测到 ZIP64 定位器，但它指向的 EOCD64 记录无效，已退回 32 位字段解析。');
              return null;
            }
            var d64 = new DataView(rec.buffer, rec.byteOffset, 56);
            return {
              entryCount: Number(d64.getBigUint64(32, true)),
              cdSize: Number(d64.getBigUint64(40, true)),
              cdOffset: Number(d64.getBigUint64(48, true))
            };
          });
        });
      }

      return zip64Promise.then(function (z64) {
        if (z64) {
          zip64 = true;
          entryCount = z64.entryCount;
          cdSize = z64.cdSize;
          cdOffset = z64.cdOffset;
        } else if (needZip64) {
          warnings.push('EOCD 中的条目数 / 偏移为 0xFFFFFFFF（ZIP64 标记），但没有读到有效的 ZIP64 记录，结果可能不准。');
        }

        if (cdSize === 0xffffffff || cdOffset === 0xffffffff) {
          throw new Error('无法确定中央目录位置：这是 ZIP64 包，但缺少可用的 ZIP64 记录。');
        }

        return parseCentralDirectory(file, {
          absEocd: absEocd,
          cdSize: cdSize,
          cdOffset: cdOffset,
          entryCount: entryCount,
          warnings: warnings
        }).then(function (entries) {
          return {
            fileName: file.name,
            fileSize: file.size,
            entries: entries,
            entryCount: entryCount,
            cdSize: cdSize,
            cdOffset: cdOffset,
            eocdOffset: absEocd,
            zip64: zip64,
            warnings: warnings
          };
        });
      });
    });
  }

  function parseCentralDirectory(file, ctx) {
    var cdSize = ctx.cdSize;
    var warnings = ctx.warnings;

    if (cdSize === 0) {
      if (ctx.entryCount > 0) {
        warnings.push('EOCD 声称有 ' + ctx.entryCount + ' 个条目，但中央目录长度为 0，文件很可能已损坏。');
      }
      return Promise.resolve([]);
    }

    var cdStart = ctx.cdOffset;
    var delta = 0;   // 中央目录被整体平移了多少，条目内的本地头偏移要同步修正

    // 偏移越界 → 按 EOCD 位置回推（自解压包前置了数据时常见）
    if (cdStart + cdSize > file.size) {
      var alt = ctx.absEocd - cdSize;
      if (alt >= 0 && alt + cdSize <= file.size) {
        delta = alt - cdStart;
        cdStart = alt;
        warnings.push('中央目录偏移超出文件范围，已按 EOCD 位置回推修正（常见于前置了数据的自解压包）。');
      } else {
        throw new Error('中央目录范围超出文件，文件可能被截断。');
      }
    }

    var reader = makeReader(file, cdStart, cdSize);

    return reader.ensure(0, 4).then(function (head) {
      if (head.length < 4 || !sigMatch(head, 0, SIG_CENTRAL)) {
        var alt2 = ctx.absEocd - cdSize;
        if (alt2 >= 0 && alt2 !== cdStart && alt2 + cdSize <= file.size) {
          return readRange(file, alt2, alt2 + 4).then(function (h2) {
            if (h2.length === 4 && sigMatch(h2, 0, SIG_CENTRAL)) {
              warnings.push('按 EOCD 记录的偏移读到的不是中央目录，已改用回推位置（偏移字段可能被写坏）。');
              return walk(makeReader(file, alt2, cdSize), alt2 - cdStart);
            }
            warnings.push('中央目录签名不匹配，文件可能已损坏，下面结果仅供参考。');
            return walk(reader, delta);
          });
        }
        warnings.push('中央目录签名不匹配，文件可能已损坏，下面结果仅供参考。');
      }
      return walk(reader, delta);
    });

    function walk(r, shift) {
      var entries = [];
      var pos = 0;
      var offsetShift = shift || 0;

      function step() {
        if (pos + 46 > cdSize) return Promise.resolve(entries);
        if (entries.length >= MAX_ENTRIES) {
          warnings.push('条目数超过 ' + MAX_ENTRIES + '，只解析了前 ' + MAX_ENTRIES + ' 个。');
          return Promise.resolve(entries);
        }

        return r.ensure(pos, 46).then(function (hdr) {
          if (hdr.length < 46 || !sigMatch(hdr, 0, SIG_CENTRAL)) return entries;

          var dv = new DataView(hdr.buffer, hdr.byteOffset, 46);
          var flags = dv.getUint16(8, true);
          var method = dv.getUint16(10, true);
          var crc = dv.getUint32(16, true);
          var compressedSize = dv.getUint32(20, true);
          var uncompressedSize = dv.getUint32(24, true);
          var nameLen = dv.getUint16(28, true);
          var extraLen = dv.getUint16(30, true);
          var commentLen = dv.getUint16(32, true);
          var localOffset = dv.getUint32(42, true);

          var headerEnd = pos + 46;
          return r.ensure(headerEnd, nameLen).then(function (nameBytes) {
            var decoded = decodeName(nameBytes, flags);
            return r.ensure(headerEnd + nameLen, extraLen).then(function (extra) {
              var entry = buildEntry({
                name: decoded.name,
                encoding: decoded.encoding,
                flags: flags,
                method: method,
                crc: crc,
                compressedSize: compressedSize,
                uncompressedSize: uncompressedSize,
                localOffset: localOffset === 0xffffffff ? localOffset : Math.max(0, localOffset + offsetShift),
                extra: extra
              });
              entries.push(entry);
              pos = headerEnd + nameLen + extraLen + commentLen;
              return step();
            });
          });
        });
      }

      return step().then(function (list) {
        if (ctx.entryCount && list.length !== ctx.entryCount) {
          warnings.push('EOCD 记录的条目数是 ' + ctx.entryCount + '，实际解析到 ' + list.length +
                        ' 个，两者不一致（文件可能损坏，或含不支持的条目类型）。');
        }
        return list;
      });
    }
  }

  function buildEntry(raw) {
    var isEncrypted = (raw.flags & 0x0001) !== 0;
    var encryptionType = null;
    var aes = null;
    var note = null;

    var localOffset = raw.localOffset;
    if (localOffset === 0xffffffff) {
      var z = parseZip64Extra(raw.extra, {
        uncompressedSize: raw.uncompressedSize,
        compressedSize: raw.compressedSize,
        localOffset: 0xffffffff
      });
      if (z && typeof z.localOffset === 'number') localOffset = z.localOffset;
    }

    if (isEncrypted) {
      if (raw.method === 99) {
        aes = parseAesExtra(raw.extra);
        if (aes) {
          var bits = aes.strength === 1 ? 128 : aes.strength === 2 ? 192 : aes.strength === 3 ? 256 : 0;
          encryptionType = bits ? 'AES-' + bits : 'AES';
          if (!bits) note = 'AES 强度字段为 ' + aes.strength + '，无法识别具体位数。';
        } else {
          encryptionType = 'AES';
          note = '压缩方法为 99（AES），但缺少 0x9901 扩展字段，无法确定密钥强度。';
        }
      } else if (raw.flags & 0x0040) {
        encryptionType = '强加密（PKWARE）';
        note = '使用了 PKWARE 强加密标志位，非 WinZip AES，也不是传统 ZipCrypto。';
      } else {
        encryptionType = 'ZipCrypto';
      }
    }

    return {
      name: raw.name,
      nameEncoding: raw.encoding,
      flags: raw.flags,
      method: raw.method,
      methodName: METHOD_NAMES[raw.method] || ('方法 ' + raw.method),
      crc: raw.crc,
      compressedSize: raw.compressedSize,
      uncompressedSize: raw.uncompressedSize,
      localOffset: localOffset,
      isEncrypted: isEncrypted,
      encryptionType: encryptionType,
      aes: aes,
      note: note,
      isDirectory: /\/$|\\$/.test(raw.name)
    };
  }

  /* -------------------------------------------- ZIP64 扩展字段 / 标志位说明 */

  /** 解析 0x0001（ZIP64）扩展字段；只对调用方标为 0xFFFFFFFF 的字段取值 */
  function parseZip64Extra(extra, wanted) {
    if (!extra || extra.length < 4) return null;
    var p = 0;
    while (p + 4 <= extra.length) {
      var id = extra[p] | (extra[p + 1] << 8);
      var size = extra[p + 2] | (extra[p + 3] << 8);
      if (id === 0x0001) {
        var avail = Math.min(size, extra.length - p - 4);
        if (avail < 8) return null;
        var dv = new DataView(extra.buffer, extra.byteOffset + p + 4, avail);
        var out = {};
        var q = 0;
        if (wanted.uncompressedSize === 0xffffffff && q + 8 <= avail) {
          out.uncompressedSize = Number(dv.getBigUint64(q, true)); q += 8;
        }
        if (wanted.compressedSize === 0xffffffff && q + 8 <= avail) {
          out.compressedSize = Number(dv.getBigUint64(q, true)); q += 8;
        }
        if (wanted.localOffset === 0xffffffff && q + 8 <= avail) {
          out.localOffset = Number(dv.getBigUint64(q, true)); q += 8;
        }
        return out;
      }
      if (size <= 0) break;
      p += 4 + size;
    }
    return null;
  }

  var FLAG_BITS = [
    [0x0001, '加密'],
    [0x0002, '压缩选项（方法相关）'],
    [0x0004, '压缩选项（方法相关）'],
    [0x0008, '使用数据描述符（CRC/大小写在数据之后）'],
    [0x0010, '增强压缩（方法相关）'],
    [0x0020, '补丁数据'],
    [0x0040, '强加密'],
    [0x0800, '文件名与注释为 UTF-8'],
    [0x2000, '掩码头（中央目录加密）']
  ];

  function describeFlags(flags) {
    var out = [];
    for (var i = 0; i < FLAG_BITS.length; i++) {
      if (flags & FLAG_BITS[i][0]) out.push(FLAG_BITS[i][1]);
    }
    return out;
  }

  function dosDateTime(date, time) {
    if (!date) return null;
    var y = 1980 + ((date >> 9) & 0x7f);
    var m = (date >> 5) & 0x0f;
    var d = date & 0x1f;
    var hh = (time >> 11) & 0x1f;
    var mm = (time >> 5) & 0x3f;
    var ss = (time & 0x1f) * 2;
    if (m < 1 || m > 12 || d < 1 || d > 31) return null;
    return { y: y, m: m, d: d, hh: hh, mm: mm, ss: ss };
  }

  function pad2(n) { return n < 10 ? '0' + n : String(n); }

  function formatDos(date, time) {
    var t = dosDateTime(date, time);
    if (!t) return '—';
    return t.y + '-' + pad2(t.m) + '-' + pad2(t.d) + ' ' +
           pad2(t.hh) + ':' + pad2(t.mm) + ':' + pad2(t.ss);
  }

  /* ------------------------------------------------ 十六进制查看 / 文件头比对 */

  /** 只读指定区间，绝不整包载入 */
  function readBytes(file, start, length) {
    return readRange(file, start, start + length);
  }

  // 常见 ZIP 本地文件头指纹（前 10 字节：签名 + 解压版本 + 通用标志 + 压缩方法）
  var KNOWN_HEADERS = [
    { label: '360压缩 / 7-Zip', vendors: ['360压缩', '7-Zip'],
      bytes: [0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00] },
    { label: 'Bandizip', vendors: ['Bandizip'],
      bytes: [0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x0b, 0x00, 0x08, 0x00] },
    { label: 'Bandizip / WinRAR', vendors: ['Bandizip', 'WinRAR'],
      bytes: [0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x09, 0x00, 0x08, 0x00] },
    { label: 'Bandizip', vendors: ['Bandizip'],
      bytes: [0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00] },
    { label: '2345 好压', vendors: ['2345 好压'],
      bytes: [0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x01, 0x08, 0x08, 0x00] }
  ];

  function matchKnownHeaders(bytes) {
    var hits = [];
    for (var i = 0; i < KNOWN_HEADERS.length; i++) {
      var sig = KNOWN_HEADERS[i].bytes;
      if (bytes.length < sig.length) continue;
      var ok = true;
      for (var j = 0; j < sig.length; j++) {
        if (bytes[j] !== sig[j]) { ok = false; break; }
      }
      if (ok) {
        hits.push({
          index: i,
          label: KNOWN_HEADERS[i].label,
          vendors: KNOWN_HEADERS[i].vendors,
          bytes: sig
        });
      }
    }
    return hits;
  }

  /** 解析一个本地文件头（30 字节固定部分 + 文件名 + 扩展字段） */
  function parseLocalHeader(file, offset) {
    return readBytes(file, offset, 30).then(function (head) {
      if (head.length < 30 || !sigMatch(head, 0, SIG_LOCAL)) {
        return { ok: false, offset: offset, reason: head.length < 30 ? '数据不足 30 字节' : '此处不是本地文件头（PK 03 04）' };
      }
      var dv = new DataView(head.buffer, head.byteOffset, 30);
      var info = {
        ok: true,
        offset: offset,
        version: dv.getUint16(4, true),
        flags: dv.getUint16(6, true),
        method: dv.getUint16(8, true),
        modTime: dv.getUint16(10, true),
        modDate: dv.getUint16(12, true),
        crc: dv.getUint32(14, true),
        compressedSize: dv.getUint32(18, true),
        uncompressedSize: dv.getUint32(22, true),
        nameLen: dv.getUint16(26, true),
        extraLen: dv.getUint16(28, true)
      };
      info.methodName = METHOD_NAMES[info.method] || ('方法 ' + info.method);
      info.flagList = describeFlags(info.flags);
      info.modified = formatDos(info.modDate, info.modTime);

      return readBytes(file, offset + 30, info.nameLen + info.extraLen).then(function (body) {
        var decoded = decodeName(body.subarray(0, info.nameLen), info.flags);
        info.name = decoded.name;
        info.nameEncoding = decoded.encoding;
        info.extra = body.subarray(info.nameLen, info.nameLen + info.extraLen);
        return info;
      });
    });
  }

  global.ZipInspector = {
    inspect: inspect,
    readBytes: readBytes,
    parseLocalHeader: parseLocalHeader,
    matchKnownHeaders: matchKnownHeaders,
    describeFlags: describeFlags,
    formatDos: formatDos,
    METHOD_NAMES: METHOD_NAMES,
    KNOWN_HEADERS: KNOWN_HEADERS,
    decodeName: decodeName
  };
})(typeof window !== 'undefined' ? window : globalThis);
