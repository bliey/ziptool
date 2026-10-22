/* app.js — 界面层：文件选择、渲染、报告导出 */
(function () {
  'use strict';

  var MAX_ROWS = 300;

  var drop = document.getElementById('drop');
  var fileInput = document.getElementById('fileInput');
  var fileInfo = document.getElementById('fileInfo');
  var errorBox = document.getElementById('error');
  var resultBox = document.getElementById('result');
  var statusEl = document.getElementById('status');
  var summaryEl = document.getElementById('summary');
  var warnBox = document.getElementById('warnings');
  var entriesEl = document.getElementById('entries');
  var hintEl = document.getElementById('hint');
  var copyBtn = document.getElementById('copyBtn');

  var hexCard = document.getElementById('hexcard');
  var hexBody = document.getElementById('hexBody');
  var hexMeta = document.getElementById('hexMeta');
  var hexLen = document.getElementById('hexLen');
  var hexJump = document.getElementById('hexJump');
  var sigList = document.getElementById('sigList');
  var sigVerdict = document.getElementById('sigVerdict');
  var fieldsEl = document.getElementById('fields');
  var fieldsTitle = document.getElementById('fieldsTitle');

  var lastReport = null;
  var currentFile = null;
  var hexState = { start: 0, len: 256 };
  var headerInfo = { hex: '', vendors: [] };

  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(2) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  /* ------------------------------------------------------------ 结论判定 */

  function verdict(report) {
    var entries = report.entries;
    var enc = entries.filter(function (e) { return e.isEncrypted; });
    var plain = entries.filter(function (e) { return !e.isEncrypted; });
    var types = [];
    enc.forEach(function (e) {
      if (e.encryptionType && types.indexOf(e.encryptionType) === -1) types.push(e.encryptionType);
    });

    var hasZipCrypto = types.indexOf('ZipCrypto') !== -1;
    var hasAes = types.some(function (t) { return t.indexOf('AES') === 0; });
    var hasOther = types.some(function (t) { return t.indexOf('AES') !== 0 && t !== 'ZipCrypto'; });

    var out = { types: types, encrypted: enc, plain: plain };

    if (entries.length === 0) {
      out.cls = 'gray';
      out.title = '空压缩包（没有条目）';
      out.hint = '文件里没有任何条目，无法判断加密类型。';
      return out;
    }
    if (enc.length === 0) {
      out.cls = 'gray';
      out.title = '未加密';
      out.hint = '所有条目都没有设置加密标志，打开不需要密码。';
      return out;
    }
    if (hasOther) {
      out.cls = 'orange';
      out.title = '非标准加密：' + types.filter(function (t) { return t !== 'ZipCrypto' && t.indexOf('AES') !== 0; }).join('、');
      out.hint = '不是常见的 ZipCrypto 或 WinZip AES，常规明文攻击与字典工具大多不适用，需要先确认加密方案。';
      return out;
    }
    if (hasZipCrypto && !hasAes) {
      out.cls = 'green';
      out.title = '传统 ZipCrypto 加密';
      out.hint = '可以尝试已知明文攻击（bkcrack / pkcrack）。前提：至少有 12 字节已知明文、其中 8 字节连续，且明文与原包由同一压缩软件、同一压缩方法生成。';
      return out;
    }
    if (hasAes && !hasZipCrypto) {
      out.cls = 'red';
      out.title = types.join('、') + ' 加密';
      out.hint = 'AES 加密无法使用明文攻击。常规手段下基本无法破解，只剩字典、暴力、掩码等猜密码的方式。';
      return out;
    }
    out.cls = 'orange';
    out.title = '混合加密类型';
    out.hint = '部分条目是 ZipCrypto，部分是 AES。ZipCrypto 条目理论上可尝试明文攻击，AES 条目不行。';
    return out;
  }

  /* -------------------------------------------------------------- 渲染 */

  function render(report) {
    var v = verdict(report);

    statusEl.className = 'status ' + v.cls;
    statusEl.textContent = v.title;

    // 摘要
    clear(summaryEl);
    var encodings = [];
    report.entries.forEach(function (e) {
      if (e.nameEncoding && encodings.indexOf(e.nameEncoding) === -1) encodings.push(e.nameEncoding);
    });

    var items = [
      ['文件名', report.fileName],
      ['文件大小', fmtSize(report.fileSize)],
      ['条目总数', String(report.entries.length)],
      ['加密条目', String(v.encrypted.length)],
      ['未加密条目', String(v.plain.length)],
      ['加密类型', v.types.join('、') || '—'],
      ['文件名编码', encodings.join('、') || '—']
    ];

    items.forEach(function (pair) {
      var box = el('div');
      box.appendChild(el('dt', null, pair[0]));
      box.appendChild(el('dd', null, pair[1]));
      summaryEl.appendChild(box);
    });

    // 警告
    clear(warnBox);
    if (report.warnings && report.warnings.length) {
      var title = el('p', 'warn-title', '注意');
      warnBox.appendChild(title);
      var ul = el('ul');
      report.warnings.forEach(function (w) { ul.appendChild(el('li', null, w)); });
      warnBox.appendChild(ul);
      warnBox.hidden = false;
    } else {
      warnBox.hidden = true;
    }

    // 条目列表
    clear(entriesEl);
    report.entries.slice(0, MAX_ROWS).forEach(function (e) {
      var li = el('li');

      var nameWrap = el('span', 'name');
      nameWrap.textContent = e.name || '(空文件名)';
      nameWrap.title = e.name + '\n压缩方法：' + e.methodName +
        '\n原始大小：' + fmtSize(e.uncompressedSize) +
        '\n压缩后大小：' + fmtSize(e.compressedSize);
      if (e.isDirectory) nameWrap.classList.add('dir');

      var tag = el('span', 'tag');
      if (!e.isEncrypted) {
        tag.className = 'tag none';
        tag.textContent = '未加密';
      } else if (e.encryptionType === 'ZipCrypto') {
        tag.className = 'tag zc';
        tag.textContent = 'ZipCrypto';
      } else if (e.encryptionType && e.encryptionType.indexOf('AES') === 0) {
        tag.className = 'tag aes';
        tag.textContent = e.encryptionType;
      } else {
        tag.className = 'tag other';
        tag.textContent = e.encryptionType || '未知加密';
      }
      if (e.note) tag.title = e.note;

      li.appendChild(nameWrap);
      li.appendChild(tag);
      entriesEl.appendChild(li);
    });

    if (report.entries.length > MAX_ROWS) {
      entriesEl.appendChild(el('li', 'more', '… 还有 ' + (report.entries.length - MAX_ROWS) + ' 个条目未显示'));
    }
    if (report.entries.length === 0) {
      entriesEl.appendChild(el('li', 'more', '（没有条目）'));
    }

    hintEl.textContent = v.hint;
    resultBox.hidden = false;
    errorBox.hidden = true;
  }

  /* ---------------------------------------------------------- 报告文本 */

  function buildReportText(report) {
    var v = verdict(report);
    var lines = [];
    lines.push('ZIP 加密类型检测报告');
    lines.push('文件名：' + report.fileName);
    lines.push('文件大小：' + fmtSize(report.fileSize) + '（' + report.fileSize + ' 字节）');
    lines.push('条目总数：' + report.entries.length + '（加密 ' + v.encrypted.length + '，未加密 ' + v.plain.length + '）');
    lines.push('加密类型：' + (v.types.join('、') || '—'));
    lines.push('结论：' + v.title);
    if (headerInfo.hex) lines.push('文件头：' + headerInfo.hex);
    if (headerInfo.vendors.length) {
      lines.push('文件头指纹：' + headerInfo.vendors.join('、') +
                 (headerInfo.vendors.length > 1 ? '（这几款软件头部一致，无法区分）' : ''));
    }
    lines.push('说明：' + v.hint);
    if (report.zip64) lines.push('ZIP64：是');
    if (report.warnings && report.warnings.length) {
      lines.push('警告：');
      report.warnings.forEach(function (w) { lines.push('  - ' + w); });
    }
    if (v.encrypted.length) {
      lines.push('加密条目（最多 50 条）：');
      v.encrypted.slice(0, 50).forEach(function (e) {
        lines.push('  - ' + (e.name || '(空文件名)') + '  [' + (e.encryptionType || '未知') + ']');
      });
    }
    return lines.join('\n');
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy') ? resolve() : reject(new Error('复制失败'));
      } catch (err) {
        reject(err);
      } finally {
        document.body.removeChild(ta);
      }
    });
  }

  /* --------------------------------------------------------- 十六进制查看 */

  var HEX_SIGS = [
    { bytes: [0x50, 0x4b, 0x03, 0x04], cls: 'sig-local' },
    { bytes: [0x50, 0x4b, 0x01, 0x02], cls: 'sig-cd' },
    { bytes: [0x50, 0x4b, 0x05, 0x06], cls: 'sig-eocd' },
    { bytes: [0x50, 0x4b, 0x06, 0x06], cls: 'sig-eocd' },
    { bytes: [0x50, 0x4b, 0x06, 0x07], cls: 'sig-eocd' }
  ];

  var EXTRA_NAMES = {
    0x0001: 'ZIP64',
    0x5455: '扩展时间戳',
    0x5855: 'Info-ZIP Unix',
    0x6375: 'Unicode 注释',
    0x7075: 'Unicode 路径',
    0x7855: 'Info-ZIP Unix 新',
    0x7875: 'Unix UID/GID',
    0x9901: 'AES'
  };

  function addClasses(node, str) {
    if (!str) return;
    str.split(' ').forEach(function (c) { if (c) node.classList.add(c); });
  }

  function hex2(n) { return (n < 16 ? '0' : '') + n.toString(16).toUpperCase(); }
  function hex4(n) { var s = (n >>> 0).toString(16).toUpperCase(); while (s.length < 4) s = '0' + s; return '0x' + s; }
  function hex8(n) { var s = (n >>> 0).toString(16).toUpperCase(); while (s.length < 8) s = '0' + s; return s; }
  function bytesToHex(bytes) { return Array.prototype.map.call(bytes, hex2).join(' '); }

  function firstLocalOffset(report) {
    if (report && report.entries && report.entries.length &&
        typeof report.entries[0].localOffset === 'number') {
      return report.entries[0].localOffset;
    }
    return 0;
  }

  function drawHex() {
    if (!currentFile) return;
    var start = hexState.start;
    var len = hexState.len;

    window.ZipInspector.readBytes(currentFile, start, len).then(function (bytes) {
      clear(hexBody);

      if (!bytes.length) {
        hexMeta.textContent = '偏移 0x' + hex8(start) + ' 已超出文件末尾（文件共 ' + fmtSize(currentFile.size) + '）。';
        return;
      }

      // 标出窗口内出现的 ZIP 结构签名
      var marks = {};
      for (var i = 0; i + 4 <= bytes.length; i++) {
        for (var s = 0; s < HEX_SIGS.length; s++) {
          var sg = HEX_SIGS[s];
          if (bytes[i] === sg.bytes[0] && bytes[i + 1] === sg.bytes[1] &&
              bytes[i + 2] === sg.bytes[2] && bytes[i + 3] === sg.bytes[3]) {
            for (var k = 0; k < 4; k++) marks[start + i + k] = sg.cls;
            break;
          }
        }
      }

      // 命中的常见文件头，额外加底色
      var rel = firstLocalOffset(lastReport) - start;
      if (rel >= 0 && rel + 10 <= bytes.length) {
        if (window.ZipInspector.matchKnownHeaders(bytes.subarray(rel, rel + 10)).length) {
          for (var h = 0; h < 10; h++) {
            var mp = start + rel + h;
            marks[mp] = marks[mp] ? marks[mp] + ' sig-match' : 'sig-match';
          }
        }
      }

      var rows = Math.ceil(bytes.length / 16);
      for (var r = 0; r < rows; r++) {
        var tr = el('tr');
        tr.appendChild(el('td', 'off', hex8(start + r * 16)));

        for (var g = 0; g < 2; g++) {
          var cell = el('td', 'hx');
          for (var b = 0; b < 8; b++) {
            var idx = r * 16 + g * 8 + b;
            if (b > 0) cell.appendChild(document.createTextNode(' '));
            if (idx < bytes.length) {
              var byteEl = el('span', bytes[idx] === 0 ? 'b zero' : 'b', hex2(bytes[idx]));
              addClasses(byteEl, marks[start + idx]);
              cell.appendChild(byteEl);
            } else {
              cell.appendChild(el('span', 'b zero', '--'));
            }
          }
          tr.appendChild(cell);
        }

        var asc = el('td', 'asc');
        for (var a = 0; a < 16; a++) {
          var ai = r * 16 + a;
          if (ai >= bytes.length) break;
          var printable = bytes[ai] >= 0x20 && bytes[ai] <= 0x7e;
          var chSpan = el('span', printable ? 'a' : 'a dim', printable ? String.fromCharCode(bytes[ai]) : '.');
          addClasses(chSpan, marks[start + ai]);
          asc.appendChild(chSpan);
        }
        tr.appendChild(asc);
        hexBody.appendChild(tr);
      }

      hexMeta.textContent = '偏移 0x' + hex8(start) + ' – 0x' + hex8(start + bytes.length - 1) +
        '（' + bytes.length + ' 字节）· 文件共 ' + fmtSize(currentFile.size) +
        ' · 只读取这一段，未加载整包';
    });
  }

  function verdictLine(prefix, strong, suffix) {
    clear(sigVerdict);
    if (prefix) sigVerdict.appendChild(document.createTextNode(prefix));
    if (strong) sigVerdict.appendChild(el('b', null, strong));
    if (suffix) sigVerdict.appendChild(document.createTextNode(suffix));
  }

  function renderSignatures(report) {
    var offset = firstLocalOffset(report);

    window.ZipInspector.readBytes(currentFile, offset, 10).then(function (bytes) {
      var hits = window.ZipInspector.matchKnownHeaders(bytes);
      var hitMap = {};
      hits.forEach(function (h) { hitMap[h.index] = true; });

      clear(sigList);
      window.ZipInspector.KNOWN_HEADERS.forEach(function (sig, i) {
        var li = el('li', hitMap[i] ? 'hit' : 'miss');
        li.appendChild(el('span', 'v', sig.label));
        li.appendChild(el('span', 'by', bytesToHex(sig.bytes)));
        li.appendChild(el('span', 'st', hitMap[i] ? '匹配' : '不匹配'));
        sigList.appendChild(li);
      });

      if (bytes.length < 10) {
        verdictLine('读不到 10 字节文件头，无法比对。', null, null);
        return;
      }

      var actual = bytesToHex(bytes);
      headerInfo.hex = actual;

      if (!hits.length) {
        verdictLine('实际文件头 ' + actual + ' 与下表任何指纹都不一致 —— 可能是其他软件生成，' +
                    '或者首个条目结构比较特殊。', null, null);
        return;
      }

      var vendors = [];
      hits.forEach(function (h) {
        h.vendors.forEach(function (v) { if (vendors.indexOf(v) === -1) vendors.push(v); });
      });

      headerInfo.vendors = vendors;
      var prefix = '实际文件头 ' + actual + '，命中 ' + hits.length + ' 条指纹';

      if (vendors.length === 1) {
        verdictLine(prefix + '：最可能由 ', vendors[0], ' 生成。');
      } else {
        verdictLine(prefix + '，但无法区分 ', vendors.join('、'),
                    ' —— 这几款软件写出的头部完全一致，仅凭文件头分不出来。');
      }
    });
  }

  function listExtras(extra) {
    var out = [];
    var p = 0;
    while (p + 4 <= extra.length) {
      var id = extra[p] | (extra[p + 1] << 8);
      var size = extra[p + 2] | (extra[p + 3] << 8);
      out.push({
        id: id,
        size: size,
        name: EXTRA_NAMES[id] || '未知扩展',
        hex: hex4(id)
      });
      if (size <= 0) break;
      p += 4 + size;
    }
    return out;
  }

  function renderFields(report) {
    var offset = firstLocalOffset(report);
    fieldsTitle.textContent = '首个本地文件头字段（偏移 0x' + hex8(offset) + '）';
    clear(fieldsEl);

    window.ZipInspector.parseLocalHeader(currentFile, offset).then(function (info) {
      function row(label, value, sub) {
        var box = el('div');
        box.appendChild(el('dt', null, label));
        var dd = el('dd', null, value);
        if (sub) dd.appendChild(el('span', 'sub', ' ' + sub));
        box.appendChild(dd);
        fieldsEl.appendChild(box);
      }

      if (!info.ok) {
        row('状态', info.reason || '此处不是本地文件头');
        row('说明', '只能显示原始字节', '可能不是 ZIP，或首个条目使用了不常见结构');
        return;
      }

      row('签名', '50 4B 03 04', '本地文件头');
      row('解压所需版本', hex4(info.version), (info.version / 10).toFixed(1));
      row('通用位标志', hex4(info.flags), info.flagList.length ? info.flagList.join(' / ') : '无特殊标志');
      row('压缩方法', hex4(info.method), info.methodName);
      row('修改时间', info.modified);
      row('CRC32', '0x' + hex8(info.crc));

      row('压缩后大小', info.compressedSize === 0xffffffff ? '0xFFFFFFFF' : String(info.compressedSize),
          info.compressedSize === 0xffffffff ? 'ZIP64，真实值在扩展字段' : '字节');
      row('原始大小', info.uncompressedSize === 0xffffffff ? '0xFFFFFFFF' : String(info.uncompressedSize),
          info.uncompressedSize === 0xffffffff ? 'ZIP64，真实值在扩展字段' : '字节');

      row('文件名', info.name || '(空)', '编码 ' + info.nameEncoding);

      var extras = listExtras(info.extra);
      row('扩展字段', info.extraLen + ' 字节',
          extras.length ? extras.map(function (e) { return e.name + '（' + e.size + ' 字节）'; }).join(' / ') : '无');
      row('本地头总长', String(30 + info.nameLen + info.extraLen), '字节');
    });
  }

  function renderHexView(file, report) {
    currentFile = file;
    headerInfo = { hex: '', vendors: [] };
    hexState.start = 0;
    hexState.len = 256;

    Array.prototype.forEach.call(hexLen.querySelectorAll('button'), function (b) {
      b.classList.toggle('on', b.getAttribute('data-len') === '256');
    });

    hexCard.hidden = false;
    drawHex();
    renderSignatures(report);
    renderFields(report);
  }

  /* ------------------------------------------------------------ 交互 */

  function setBusy(on, fileName) {
    drop.classList.toggle('busy', on);
    if (on) {
      fileInfo.textContent = '正在读取 ' + fileName + ' 的中央目录…';
      errorBox.hidden = true;
      resultBox.hidden = true;
    }
  }

  function handleFile(file) {
    lastReport = null;
    setBusy(true, file.name);

    window.ZipInspector.inspect(file).then(function (report) {
      lastReport = report;
      setBusy(false);
      fileInfo.textContent = '已检测：' + report.fileName + '（' + fmtSize(report.fileSize) + '）';
      render(report);
      renderHexView(file, report);
    }).catch(function (err) {
      setBusy(false);
      fileInfo.textContent = '';
      resultBox.hidden = true;
      errorBox.hidden = false;
      errorBox.textContent = '检测失败：' + (err && err.message ? err.message : String(err));
      // 解析失败也照样把原始字节摆出来，方便人工看文件头
      renderHexView(file, null);
    });
  }

  drop.addEventListener('click', function () { fileInput.click(); });

  drop.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', function () {
    if (fileInput.files && fileInput.files[0]) handleFile(fileInput.files[0]);
    fileInput.value = '';
  });

  ['dragenter', 'dragover'].forEach(function (evt) {
    drop.addEventListener(evt, function (e) {
      e.preventDefault();
      e.stopPropagation();
      drop.classList.add('over');
    });
  });

  ['dragleave', 'drop'].forEach(function (evt) {
    drop.addEventListener(evt, function (e) {
      e.preventDefault();
      e.stopPropagation();
      drop.classList.remove('over');
    });
  });

  drop.addEventListener('drop', function (e) {
    var files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) {
      if (files.length > 1) {
        errorBox.hidden = false;
        errorBox.textContent = '一次只能检测一个文件，已取第一个：' + files[0].name;
      }
      handleFile(files[0]);
    }
  });

  // 防止拖到页面空白处时浏览器直接打开文件
  window.addEventListener('dragover', function (e) { e.preventDefault(); });
  window.addEventListener('drop', function (e) { e.preventDefault(); });

  Array.prototype.forEach.call(hexLen.querySelectorAll('button'), function (btn) {
    btn.addEventListener('click', function () {
      Array.prototype.forEach.call(hexLen.querySelectorAll('button'), function (b) {
        b.classList.remove('on');
      });
      btn.classList.add('on');
      hexState.len = parseInt(btn.getAttribute('data-len'), 10) || 256;
      drawHex();
    });
  });

  Array.prototype.forEach.call(hexJump.querySelectorAll('button'), function (btn) {
    btn.addEventListener('click', function () {
      if (!currentFile) return;
      var kind = btn.getAttribute('data-jump');
      var target = 0;

      if (kind === 'local') {
        target = firstLocalOffset(lastReport);
      } else if (kind === 'cd') {
        if (!lastReport) { fileInfo.textContent = '这个文件没解析出中央目录，无法跳转。'; return; }
        target = lastReport.cdOffset;
      } else if (kind === 'eocd') {
        if (!lastReport) { fileInfo.textContent = '这个文件没解析出 EOCD，无法跳转。'; return; }
        target = lastReport.eocdOffset;
      }

      if (target < 0 || target >= currentFile.size) {
        fileInfo.textContent = '偏移 0x' + hex8(target) + ' 超出文件范围。';
        return;
      }
      hexState.start = target - (target % 16);
      drawHex();
    });
  });

  copyBtn.addEventListener('click', function () {
    if (!lastReport) return;
    copyText(buildReportText(lastReport)).then(function () {
      copyBtn.textContent = '已复制';
      setTimeout(function () { copyBtn.textContent = '复制报告'; }, 1500);
    }).catch(function () {
      copyBtn.textContent = '复制失败';
      setTimeout(function () { copyBtn.textContent = '复制报告'; }, 1500);
    });
  });
})();
