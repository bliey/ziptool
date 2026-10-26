# ZIP 加密类型检测 + MD5 二维码

一个纯前端的 ZIP 压缩包加密类型检测工具。拖入 `.zip`，直接在浏览器里判断它是**传统 ZipCrypto**、**WinZip AES-128/192/256**，还是**未加密**，并据此判断能否尝试已知明文攻击。

页面下方还带一个 **MD5 计算与二维码** 区块：拖入任意文件，分块算出 MD5，并把纯 MD5 字符串渲染成二维码，方便手机扫码查询。

- 全部在本地完成，文件不上传、不联网
- 只读取文件末尾的 EOCD 与中央目录，不整包载入内存，**没有文件大小限制**
- 中央目录分块顺序读取，条目数几十万也不爆内存
- MD5 按 4 MB 分块顺序读取，几 GB 的文件内存占用也只有几十 MB
- 支持 ZIP64、自解压包前置数据、GBK 文件名
- 依赖（spark-md5、qrcode）**全部内联进 `index.html`**，不走任何 CDN，断网可用

## 目录结构

```
.
├── index.html              # 页面骨架 + 内联的 spark-md5 / qrcode
├── assets/
│   ├── style.css           # 样式
│   ├── zip-inspector.js    # ZIP 解析核心（可独立复用）
│   ├── app.js              # ZIP 界面层
│   └── md5.js              # MD5 与二维码逻辑（与 ZIP 区块完全独立）
├── dev/                    # 不参与部署
│   ├── test-parser.mjs     # 解析核心自测
│   ├── e2e.html            # ZIP 区块端到端测试
│   ├── md5-e2e.html        # MD5 区块端到端测试
│   ├── md5-mem.html        # 大文件内存占用测试
│   ├── cdp-run.mjs         # 用 CDP 驱动无头 Chrome 跑测试
│   ├── cdp-copy.mjs        # 剪贴板行为验证
│   ├── cdp-file.mjs        # file:// 下的自包含验证
│   └── cdp-shot.mjs        # 截图
├── .nojekyll               # 让 GitHub Pages 跳过 Jekyll
└── README.md
```

`assets/zip-inspector.js` 不依赖 DOM，挂载为 `window.ZipInspector`：

```js
const report = await ZipInspector.inspect(file);
// report: { fileName, fileSize, entryCount, zip64, warnings, entries: [...] }
```

## 本地运行

直接双击 `index.html` 就能用（脚本刻意没用 ES Module，`file://` 下也能跑）。

想跑本地服务器：

```bash
python -m http.server 8000
# 打开 http://localhost:8000
```

跑自测：

```bash
node dev/test-parser.mjs
```

## 部署到 GitHub Pages

本地仓库已经初始化好并完成了首次提交（分支 `main`），只剩两步。

**1. 在 GitHub 上建一个空仓库**

打开 <https://github.com/new>：

- Repository name 填 `ziptool`（或你喜欢的名字）
- 选 **Public**（私有仓库开 Pages 需要付费计划）
- **不要**勾 `Add a README file` / `Add .gitignore` / `Choose a license` —— 本地已经有这些文件，勾了会产生分叉，push 会被拒绝

**2. 关联远程仓库并推送**

```bash
cd "C:/Users/bliey/Project/.workbuddy-ai/ziptool"
git remote add origin https://github.com/<你的用户名>/ziptool.git
git push -u origin main
```

Windows 上 Git Credential Manager 会接管认证，第一次可能弹浏览器登录一次，之后就不用再输密码。

**3. 开启 Pages**

仓库 **Settings → Pages** → Source 选 `Deploy from a branch` → Branch 选 `main`、目录选 `/(root)` → **Save**。

等 30–60 秒，访问 `https://<你的用户名>.github.io/ziptool/`。

> 如果仓库名直接叫 `<你的用户名>.github.io`，地址会变成 `https://<你的用户名>.github.io/`，不带子路径。

### 后续更新

```bash
git add -A
git commit -m "更新说明"
git push
```

Pages 会自动重新构建，不用再点任何按钮。

### 不想用命令行？

GitHub 网页也能传：仓库页 **Add file → Upload files**，把 `index.html`、`assets/`、`README.md` 拖进去提交。

但 `.nojekyll` 是空文件，拖拽上传经常被浏览器忽略，需要手动补一个：**Add file → Create new file**，文件名填 `.nojekyll`，内容留空，直接 Commit。少了它，以 `_` 开头的文件/目录会被 Jekyll 吞掉。

### 路径说明

所有资源都是相对路径（`assets/...`），放在仓库根目录或 `/docs` 子目录都能正常工作；如果放到子目录，记得把 Pages 的目录也改成对应目录。`dev/` 里是测试页，会被一起发布但不影响使用，介意的话可以加到 `.gitignore`。

## 文件头十六进制查看器

检测结果下方是一块 FFV 风格的三段式十六进制视图：**偏移 | 十六进制 | ASCII**。

- 默认只读前 256 字节，可切 64 B / 1 KB；`file.slice()` 只取这一段，**不会把整包读进内存**
- 窗口内出现的 ZIP 签名按类型上色：本地文件头（红）、中央目录项（绿）、EOCD / ZIP64（橙）
- 命中下方常见指纹的 10 字节会额外加底色
- `首个本地头 / 中央目录 / EOCD` 三个按钮直接跳到对应结构，行首按 16 字节对齐
- 解析失败（比如根本不是 ZIP）时这块照样显示，方便人工对着字节看

### 常见文件头指纹

判定依据是第一个本地文件头的前 10 字节：

```
50 4B 03 04 | 14 00 | xx 00 | 08 00
   签名        版本    标志    压缩方法
```

| 来源 | 文件头 |
| --- | --- |
| 360压缩 / 7-Zip | `50 4B 03 04 14 00 01 00 08 00` |
| Bandizip | `50 4B 03 04 14 00 0B 00 08 00` |
| Bandizip / WinRAR | `50 4B 03 04 14 00 09 00 08 00` |
| Bandizip | `50 4B 03 04 14 00 00 00 08 00` |
| 2345 好压 | `50 4B 03 04 14 00 01 08 08 00` |

注意这只是**启发式**指纹，不是权威标识：

- 同一款软件不同版本、不同加密选项会写出不同头部，所以表里同一家会出现多条
- `0x0009` 这一条 Bandizip 与 WinRAR 完全相同，仅凭文件头无法区分
- 改过头部、二次打包、或用了其他压缩库的包，可能一条都不命中——此时界面会直接说"与任何指纹都不一致"

## MD5 计算与二维码

页面最下方的独立区块，和上面的 ZIP 检测互不干扰，各用各的文件选择框。

- 拖入任意文件，**按 4 MB 分块顺序读取**（`file.slice().arrayBuffer()` + `SparkMD5.ArrayBuffer` 增量 API），不会把整个文件读进内存
- 每读完一块刷新一次进度条，计算中可随时点「取消」
- 算完显示 32 位小写 MD5，旁边「复制」走 `navigator.clipboard.writeText`
- MD5 下方是二维码，内容**就是 32 位 MD5 字符串本身**，不加前缀、不加 URL，方便「解压缩全能王」这类工具直接扫
- 计算期间文件选择区被禁用，此时再拖入文件会提示「正在计算中，请等待或取消」

实测（无头 Chrome，4 MB 分块）：

| 文件大小 | 耗时 | JS 堆峰值增量 | MD5 |
| --- | --- | --- | --- |
| 512 MB | 4.5 s | 48.8 MB | 校验一致 |
| 1 GB | 8.7 s | 54.6 MB | 校验一致 |

堆占用基本不随文件变大而增长，因为每次只持有一个分块。

### 依赖为什么内联

`spark-md5@3.0.2` 和 `qrcode@1.5.3` 的 minified 源码直接写在 `index.html` 里，**不引任何 CDN**，断网、`file://` 双击都能用。

- `spark-md5.min.js` 取自 npm 包 `spark-md5@3.0.2`，原样内联（sha256 前缀 `4cc433fc805298ff`）
- `qrcode.min.js` 由 `qrcode@1.5.3` 官方 `rollup.config.js` 原样构建（`lib/browser.js` → IIFE，`name: 'QRCode'`，babel + terser），库代码未做任何改动。npm 包里没有 `build/` 目录，所以按官方配置自己跑了一遍 rollup
- 两个脚本都排在业务脚本之前，全局暴露 `SparkMD5` / `QRCode`
- 页面加载时只请求自身的 HTML、CSS 和 3 个 `assets/*.js`，没有任何第三方脚本请求

## 判定逻辑

| 现象 | 结论 |
| --- | --- |
| 通用位标志 bit 0 未置位 | 未加密 |
| bit 0 置位，压缩方法 = 99，扩展字段 0x9901 强度 1/2/3 | AES-128 / AES-192 / AES-256 |
| bit 0 置位，压缩方法 = 99，无 0x9901 | AES（强度未知） |
| bit 0 置位，bit 6 置位 | PKWARE 强加密（非 AES、非 ZipCrypto） |
| bit 0 置位，其余情况 | ZipCrypto |

文件名解码顺序：bit 11 声明 UTF-8 → 严格 UTF-8 校验 → GBK（结果含中日韩字符才采纳）→ CP437。

## 已知限制

- **分卷压缩**（`.z01`/`.z02`…）只看得到当前卷的条目，会给出警告。
- 中央目录被加密（ZipCrypto 的 "central directory encryption"）的包无法解析，会报错。
- 文件名既不是 UTF-8 也不是 GBK 的极端编码（如 Big5、Shift-JIS）会退化成 CP437 显示，可能乱码，但不影响加密判定。
- 只做**检测**，不做解密；检测结果不构成破解能力的承诺。

## 说明

ZipCrypto 之所以被标成「可尝试明文攻击」，是因为它的密钥流可以被已知明文还原（bkcrack / pkcrack）。这要求你**合法持有**该压缩包及其中某个文件的明文版本。AES 没有这类结构性弱点，只能猜密码。
