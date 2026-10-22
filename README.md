# ZIP 加密类型检测

一个纯前端的 ZIP 压缩包加密类型检测工具。拖入 `.zip`，直接在浏览器里判断它是**传统 ZipCrypto**、**WinZip AES-128/192/256**，还是**未加密**，并据此判断能否尝试已知明文攻击。

- 全部在本地完成，文件不上传、不联网
- 只读取文件末尾的 EOCD 与中央目录，不整包载入内存，**没有文件大小限制**
- 中央目录分块顺序读取，条目数几十万也不爆内存
- 支持 ZIP64、自解压包前置数据、GBK 文件名
- 零依赖、零构建，纯静态文件

## 目录结构

```
.
├── index.html              # 页面骨架
├── assets/
│   ├── style.css           # 样式
│   ├── zip-inspector.js    # 解析核心（可独立复用）
│   └── app.js              # 界面层
├── dev/
│   └── test-parser.mjs     # 解析核心自测（不参与部署）
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

1. 新建仓库，把 `index.html`、`assets/`、`.nojekyll` 推到 `main` 分支根目录：

   ```bash
   git init
   git add index.html assets .nojekyll README.md
   git commit -m "feat: ZIP 加密类型检测"
   git branch -M main
   git remote add origin https://github.com/<你的用户名>/<仓库名>.git
   git push -u origin main
   ```

2. 仓库 **Settings → Pages** → Source 选 `Deploy from a branch`，Branch 选 `main` / `(root)`，保存。
3. 等 1 分钟左右，访问 `https://<你的用户名>.github.io/<仓库名>/`。

所有资源都是相对路径（`assets/...`），放在仓库根目录或 `/docs` 子目录都能正常工作；如果放到子目录，记得把 Pages 的目录也改成对应目录。

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
