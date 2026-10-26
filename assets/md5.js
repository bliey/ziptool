/* md5.js — MD5 计算与二维码（与上方 ZIP 检测完全独立） */
(function () {
  'use strict';

  var CHUNK_SIZE = 4 * 1024 * 1024;   // 4 MB / 块

  var drop = document.getElementById('md5Drop');
  var input = document.getElementById('md5Input');
  var fileInfo = document.getElementById('md5FileInfo');
  var progressBox = document.getElementById('md5Progress');
  var fill = document.getElementById('md5Fill');
  var pctEl = document.getElementById('md5Pct');
  var cancelBtn = document.getElementById('md5Cancel');
  var outBox = document.getElementById('md5Out');
  var valEl = document.getElementById('md5Val');
  var copyBtn = document.getElementById('md5Copy');
  var errBox = document.getElementById('md5Error');
  var canvas = document.getElementById('md5Qr');

  // 当前这一次计算。取消 = 打标记 + 把 current 置空，
  // 旧循环下一次检查就会发现「我已不是当前任务」而退出，
  // 这样用户取消后立刻选新文件也不会被上一轮的结果覆盖。
  var current = null;

  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(2) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }

  function showError(msg) {
    errBox.textContent = msg;
    errBox.hidden = false;
  }

  function clearError() {
    errBox.textContent = '';
    errBox.hidden = true;
  }

  function clearQr() {
    var ctx = canvas.getContext && canvas.getContext('2d');
    if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
    canvas.setAttribute('aria-label', 'MD5 二维码');
  }

  function setBusy(on) {
    drop.classList.toggle('busy', on);
    drop.setAttribute('aria-disabled', on ? 'true' : 'false');
    input.disabled = on;
    if (on) drop.setAttribute('tabindex', '-1');
    else drop.setAttribute('tabindex', '0');
  }

  function reset() {
    progressBox.hidden = true;
    fill.style.width = '0%';
    pctEl.textContent = '0%';
    outBox.hidden = true;
    valEl.textContent = '';
    copyBtn.textContent = '复制';
    clearQr();
  }

  function setProgress(pct) {
    fill.style.width = pct + '%';
    pctEl.textContent = pct + '%';
  }

  /* ------------------------------------------------------------ 分块读取 */

  // Safari 14 以下没有 Blob.prototype.arrayBuffer，退回 FileReader
  function readChunk(blob) {
    if (blob.arrayBuffer) return blob.arrayBuffer();
    return new Promise(function (resolve, reject) {
      var fr = new FileReader();
      fr.onload = function () { resolve(fr.result); };
      fr.onerror = function () { reject(fr.error || new Error('读取中断')); };
      fr.readAsArrayBuffer(blob);
    });
  }

  // 让出主线程一帧，保证进度条真的画出来（后台标签页里 rAF 不触发，所以用 setTimeout）
  function yieldToUI() {
    return new Promise(function (resolve) { setTimeout(resolve, 0); });
  }

  function isStale(task) {
    return task !== current || task.cancelled;
  }

  /* -------------------------------------------------------------- 二维码 */

  function drawQr(text) {
    if (typeof QRCode === 'undefined' || typeof QRCode.toCanvas !== 'function') {
      showError('二维码库未加载，MD5 已算出但无法生成二维码。');
      return;
    }

    function onError(err) {
      showError('二维码生成失败：' + (err && err.message ? err.message : String(err)));
    }

    try {
      // qrcode 1.5.3 传了回调就直接回调；某些版本忽略回调只返回 Promise，
      // 两条路都接上，避免某一侧不触发时卡住。
      var ret = QRCode.toCanvas(canvas, text, { width: 200, margin: 1 }, function (err) {
        if (err) onError(err);
        else canvas.setAttribute('aria-label', 'MD5 二维码：' + text);
      });
      if (ret && typeof ret.then === 'function') ret.then(null, onError);
    } catch (err) {
      onError(err);
    }
  }

  /* ------------------------------------------------------------ 计算主流程 */

  async function compute(file) {
    var task = { cancelled: false };
    current = task;

    clearError();
    reset();
    fileInfo.textContent = file.name + '（' + fmtSize(file.size) + '）';
    progressBox.hidden = false;
    setBusy(true);

    var spark = new SparkMD5.ArrayBuffer();
    var offset = 0;

    try {
      while (offset < file.size) {
        if (isStale(task)) return;

        var end = Math.min(offset + CHUNK_SIZE, file.size);
        var buf = await readChunk(file.slice(offset, end));

        if (isStale(task)) return;

        spark.append(buf);
        offset = end;
        setProgress(Math.round(offset / file.size * 100));

        await yieldToUI();
      }

      if (isStale(task)) return;

      var md5 = spark.end();          // 32 位小写十六进制
      valEl.textContent = md5;
      outBox.hidden = false;
      progressBox.hidden = true;
      drawQr(md5);
    } catch (err) {
      if (isStale(task)) return;
      reset();
      fileInfo.textContent = '';
      showError('读取失败：' + (err && err.message ? err.message : String(err)));
    } finally {
      if (!isStale(task)) {
        setBusy(false);
        current = null;
      }
    }
  }

  function handleFile(file) {
    if (current) {
      showError('正在计算中，请等待或取消。');
      return;
    }
    if (!file) return;
    if (file.size === 0) {
      clearError();
      reset();
      fileInfo.textContent = file.name + '（0 B）';
      showError('文件为空，没有可计算的内容。');
      return;
    }
    if (typeof SparkMD5 === 'undefined') {
      showError('MD5 库未加载，无法计算。');
      return;
    }
    compute(file);
  }

  /* ---------------------------------------------------------------- 交互 */

  drop.addEventListener('click', function () {
    if (current) return;
    input.click();
  });

  drop.addEventListener('keydown', function (e) {
    if (current) return;
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      input.click();
    }
  });

  input.addEventListener('change', function () {
    if (input.files && input.files[0]) handleFile(input.files[0]);
    input.value = '';   // 清空 value，同一文件再次选择才会触发 change
  });

  ['dragenter', 'dragover'].forEach(function (evt) {
    drop.addEventListener(evt, function (e) {
      e.preventDefault();
      e.stopPropagation();
      if (!current) drop.classList.add('over');
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
    if (!files || !files.length) return;
    if (current) {
      showError('正在计算中，请等待或取消。');
      return;
    }
    if (files.length > 1) showError('一次只能计算一个文件，已取第一个：' + files[0].name);
    else clearError();
    handleFile(files[0]);
  });

  cancelBtn.addEventListener('click', function () {
    if (!current) return;
    current.cancelled = true;
    current = null;
    reset();
    clearError();
    fileInfo.textContent = '';
    setBusy(false);
  });

  copyBtn.addEventListener('click', function () {
    var md5 = valEl.textContent;
    if (!md5) return;

    function done() {
      copyBtn.textContent = '已复制';
      setTimeout(function () { copyBtn.textContent = '复制'; }, 1500);
    }

    function fallback() {
      // 非安全上下文里 clipboard API 不可用，退化为选中文本让用户手动复制
      var range = document.createRange();
      range.selectNodeContents(valEl);
      var sel = window.getSelection();
      if (sel) {
        sel.removeAllRanges();
        sel.addRange(range);
      }
      copyBtn.textContent = '请按 Ctrl+C';
      setTimeout(function () { copyBtn.textContent = '复制'; }, 2500);
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(md5).then(done, fallback);
    } else {
      fallback();
    }
  });
})();
