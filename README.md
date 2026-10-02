# Armory 右键增强 · v0.3（两轮审计返修）

对应文档：`D:\codex\11-Armory-右键增强.md`
v0.1 通道 → v0.2 接模型 → v0.3 按两轮审计返修（提交 `246d602`）
审计：`audit-report-armory-rightclick-v0.2.md` + 第 2 轮整改核验

---

## 一句话

文档里 60 多个 AI 动作是下游能力调用，不是工程难点。本仓库建的是中间那条**通道**：

```
入口(SendTo) → Permission Gate → Context Extractor → Action Router → Executor → Evidence
```

动作表只是 `actions.json` 的一张配置。将来入口换成注册表 verb 或 IExplorerCommand，
这层代码一行都不用改。

---

## 第 2 轮新增 P0：外发路径没接凭据防护

**这是第 1 轮返修自己捅的娄子。** 我把敏感文件名单和脱敏只接在「本地留存」那条路上，
「外发」那条一条没接。`_read_for_model` 只有体积闸门和二进制判定，于是：

- 右键「总结」自己的 `model_config.json` → 明文 API key 进请求体，还返回 `status: ok`
- `D:\新建文件夹\key.txt` 只有 1.3KB，**远在 2MB 体积闸门内**，右键「总结」它
  等于把 15 条 nvapi key 整个发给第三方

**修法（双保险）：**

1. 敏感文件名（`key` / `secret` / `token` / `.env` / `config.json` / `.pem` / `id_rsa` …）
   → **直接拒绝发送**，明确说明为什么。脱敏可能漏，拒绝不会。
2. 非敏感文件名但内容里夹着凭据形状（`nvapi-` / `sk-` / `-----BEGIN` / `api_key=` …）
   → **抹掉再发**，并在结果里写明「已抹掉 N 处疑似凭据」

现在 `_read_for_model` 是五道闸门：体积 → 敏感文件名 → 是否纯文本 → 读多少 → 内容脱敏。

---

## 三处回归（都是我这轮改出来的）

| 回归 | 真相 | 修法 |
|---|---|---|
| outline「分块读」峰值内存 121.6MB → **153.6MB** | `chunks` 攒完再 `join`，等于全文进内存还多一份 | 改成逐行流式扫描，单行超 1MB 跳过匹配。**实测 20.4MB 输入：0.8 秒、峰值 ~0MB** |
| `install_sendto` 校验了 label 漏了 action | action 键同样被拼进 `$lnk.Arguments` | 加 `^[a-z][a-z0-9_]*$` 白名单 |
| 「默认拒绝」只对声明了 `risk` 的动作成立 | `meta.get("risk", "none")` —— 没写 risk 键就当 none 放行 | 改成 `meta.get("risk")`，缺失得 `None` 照样拒绝；`kind` 未知也拒绝 |

## 两条 P1

- **688 行返修一行没提交**（HEAD 还在 v0.1 而 README 自称 v0.3）→ 已提交 `246d602`
- **`LOCALAPPDATA` 缺失时 evidence 回落 `<仓库>/evidence`**，而 `.gitignore` 既没有
  `evidence/`、死规则 `evidencetmp/` 还占着位——P0-2 原地复活的通道没堵
  → 回落到 `~/.armory/evidence`，`.gitignore` 补 `evidence/` 删死规则

---

## 第 1 轮修复（已通过第 2 轮核验）

### P0

**P0-1 HTTP 总线是无鉴权的「任意本地文件读取」原语** —— 已修且实测到位

| 探针 | 结果 |
|---|---|
| 无 token / 错 token | 401 |
| 伪造 Host | 403 |
| 坏 Origin | 403 |
| 白名单外路径 | 403 |
| 超大请求体 | 413 |
| 非数字 Content-Length | 400 |
| 未知动作 | 400 |
| 不设 `ARMORY_ALLOWED_ROOTS` 时 `serve()` | rc=1 拒启 |

信任模型分两档：`route(trusted=True)` 给 SendTo（用户本人右键，不做路径限制），
`False` 给网络调用（强制白名单）。

**P0-2 evidence 明文留存并被 git 跟踪** —— 已修

默认落 `%LOCALAPPDATA%\Armory\evidence`；`preview` 默认关闭，开了也要过敏感文件
黑名单 + 凭据脱敏 + 200 字符上限；18 份历史 evidence 已迁出仓库（逐字段等值、
sha256 自校验仍成立）。

**历史已清理（2026-10-02）**：用 `git filter-repo --invert-paths --path evidence/`
重写了两个提交，旧的 15 份 evidence blob 已不可访问（`git cat-file -t 6203c0d`
报 not a valid object），reflog 清空、对象库重新打包。
新历史：`d221eda`(v0.1) → `bc6d297`(v0.3) → `04e5e97`(docs)。

> 清理时踩到一个坑：`filter-repo` 会丢弃工作树里未提交的改动，
> 当时未提交的 README 被回滚到旧版。靠着清理前做的工作树备份恢复。
> **改历史之前先备份，这句话不是口号。**

### P1 / P2

gate 默认拒绝、体积闸门、剪贴板查返回码、二进制不送模型、测试、解释器路径告警；
vision MIME 按后缀、HTTP 状态码语义、install 注入面、info 补摘要、缓存与 lstat 复用。

---

## 目录

| 文件 | 职责 |
|---|---|
| `detector.py` | 类型检测 + 抽取；`is_sensitive_path` / `redact` 供两条路共用 |
| `actions.json` | 动作表 + 高危清单 + `egress` 外发标注 |
| `model.py` | 模型层，OpenAI 兼容，零依赖 |
| `model_config.json` | 模型配置（**含 key，已 gitignore**） |
| `ocr.ps1` | Windows 自带 OCR，本地不联网 |
| `executor.py` | 执行层，五道闸门 |
| `router.py` | 通道核心 + 加固后的 HTTP 总线 |
| `cli.py` | SendTo 入口 |
| `evidence.py` | 落盘（仓库外）+ SHA-256 + `elapsed_ms` |
| `tests/test_channel.py` | **28 条断言，0.47 秒，不联网** |

## 用法

选中对象 → 右键 → **发送到** → `Armory · ...`（10 个动作）

```bash
python install_sendto.py             # 装所有已实现动作
python uninstall_sendto.py           # 卸载，不留注册表
python -m unittest discover -s tests # 28 条自检
```

HTTP 总线（**默认不可用**）：

```bash
set ARMORY_ALLOWED_ROOTS=D:\Armory\rightclick   # 别照抄成整个 D:\Armory
python router.py 8791
```

## 渠道判定（审计口径）

| 渠道 | 判定 |
|---|---|
| A. 本机 SendTo 自用 | **可用**。别对配置/密钥文件点「总结」「翻译」——现在会拒绝，但别习惯性去试 |
| B. HTTP 总线 | **可开启**，白名单别开太大 |
| C. 仓库外发 | **可外发**。历史已清理；外发前自查一遍 `.gitignore` 覆盖与工作树无 `model_config.json` |

## 实测耗时（evidence 里记 `elapsed_ms`，可复证）

| 动作 | 耗时 |
|---|---|
| 总结 | 约 3–15 秒 |
| 翻译 | 数十秒（长文） |
| 图片描述 | 约 10 秒（视觉模型出英文 + 回译中文） |
| OCR | 数秒，本地引擎，**精度一般**（`services`→`servlces`） |
| 其余 6 个 | <1 秒 |

模型：`openai/gpt-oss-20b` + `meta/llama-3.2-11b-vision-instruct`（NVIDIA NIM，
81 个在架模型逐个实测选出；原文档推荐的 `llama-3.3-nemotron-super-49b` 已下架 410）。

## 踩过的坑

1. **推理模型的 token 预算陷阱。** `reasoning_content`（思考）先吃掉几百 token，
   `max_tokens` 给小了 → 想完了但 `content` 还空。**绝不能拿 `reasoning_content` 顶替**。
2. **短问题选不出模型。** 必须拿真实长度的输入测。
3. **配置数据是潜在注入入口。** 动作 label 和 action 键都会被拼进 PowerShell 字符串，
   两个都要白名单。
4. **修一个面别忘了另一条路。** 这次就是：本地留存加了防护，外发那条没加，
   结果外发反而成了最大的漏点。
5. **"分块读"不等于流式。** 攒 chunks 再 join 比直接 read 还费内存。要真流式就逐行迭代。
6. PowerShell 5.1 只认带 BOM 的 UTF-8（`utf-8-sig`）。

## 真相边界

**已验证：** 28 条断言通过；敏感文件拒绝外发、内容凭据脱敏后发送；
gate 拦住缺 `risk`/`kind` 的动作；outline 20.4MB 输入峰值 ~0MB；
HTTP 八项加固实测达标；evidence 不回落仓库。

**仍 stub：** `audit`（缺 GOLink 通道）

**未实机验证：** 系统通知弹窗（GUI 断言不了）

**已清理：** git 历史里 15 份含正文 evidence 已用 `filter-repo` 摘除并 gc，
旧对象不可访问。

## 下一步

1. **等你用顺了再说** —— 先攒真实使用反馈
2. 接 GOLink 让 `audit` 转正、`rename` 补确认流程
3. **换壳（IExplorerCommand）**：风险未验证，动手前先做最小验证包探路，不赌
4. 剥离非系统右键对象：「选中文本」归 IN 输入法，「网页内容」归 Dory 扩展
