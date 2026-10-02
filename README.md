# Armory 右键增强 · v0.3（审计返修版）

对应文档：`D:\codex\11-Armory-右键增强.md`
v0.1 通道 · v0.2 接模型 · v0.3 按 `audit-report-armory-rightclick-v0.2.md` 返修

---

## 一句话

文档里 60 多个 AI 动作是下游能力调用，不是工程难点。本仓库建的是中间那条**通道**：

```
入口(SendTo) → Permission Gate → Context Extractor → Action Router → Executor → Evidence
```

动作表只是 `actions.json` 的一张配置。将来入口换成注册表 verb 或 IExplorerCommand，
这层代码一行都不用改。

---

## v0.3 修了什么

第三方审计（2026-10-02）判定：渠道 A（SendTo 自用）可用但有隐私自伤，
渠道 B（HTTP 总线）不可开启，渠道 C（仓库外发）不可外发。缺陷 P0×2 · P1×6 · P2×11。
本次逐条返修：

### P0

**P0-1 HTTP 总线是无鉴权的「任意本地文件读取」原语** —— 已修

`serve()` 现在默认拒绝启动：无 `ARMORY_ALLOWED_ROOTS` 直接退出。启动时强制校验
`X-Armory-Token`（常量时间比较）、`Host` ∈ 回环地址、`Origin` 同源，请求体上限 1MB，
换 `ThreadingHTTPServer`。信任模型分成两档：

| 调用方 | trusted | 路径限制 |
|---|---|---|
| SendTo（用户本人右键） | True | 不做限制 |
| HTTP 网络调用 | False | 必须落在白名单根目录下 |

README 已撤下「随手 `python router.py 8791`」的写法。

**P0-2 evidence 明文留存文件内容并被 git 跟踪** —— 已修

- 默认落盘位置移出仓库 → `%LOCALAPPDATA%\Armory\evidence\`
- `preview` 默认关闭（`ARMORY_CAPTURE_PREVIEW=1` 才开），开了也要过敏感文件黑名单
  并做凭据形状脱敏（`nvapi-` / `sk-` / `-----BEGIN` / `api_key=` …），上限 200 字符
- 已把 18 份历史 evidence 迁出仓库，`git rm -r --cached evidence/`
- `datetime.now()` 合并成一次调用（原来跨秒时文件名与体内时间戳对不上）

> ⚠️ **历史里仍有 15 份含正文片段的 evidence**。当前仓库无 remote，暂无外泄；
> **一旦要加 remote 或打包外发，必须先做 `git filter-repo` 历史清理**，
> 单靠 .gitignore 只防继续恶化。

### P1

| 编号 | 问题 | 修法 |
|---|---|---|
| P1-1 | Permission Gate 是黑名单，`risk` 字段没人读 | 改成默认拒绝：`risk != none` 或列入 `require_confirm` 一律拦下，且 gate 早于上下文抽取 |
| P1-2 | 33MB 输入 → 121MB 峰值内存 | 加 `size_bytes` 闸门（local ≤50MB、model ≤2MB），分块读 |
| P1-3 | 剪贴板失败也报「已写入」 | 查 `returncode`，失败就说失败 |
| P1-4 | PDF/Word 二进制当文本送付费模型 | 发送前用 NUL 采样判据卡住，明确报不支持 |
| P1-5 | 零测试零 CI | 补 `tests/test_channel.py`，19 条断言，0.37 秒跑完不联网 |
| P1-6 | 快捷方式钉死可被外部清理的 Python 路径 | 安装时告警；找不到 `pythonw` 明确报错（不再退回 `python.exe` 闪黑框） |

### P2（11 条）

vision MIME 按真实后缀（不再恒写 `image/png`）+ 只对 PNG/JPEG/WEBP/GIF 开 describe；
HTTP 状态码语义（400/403/501 不再一律 200）；空 paths 不再掐连接；`Content-Length`
校验与上限；install 脚本 PowerShell 注入加固（单引号成对转义 + 标签白名单）；
`--with-stub` 文案改对；临时 ps1 随机名且用完即删；`info` 补可读摘要并删掉
从未实现的 SHA-256 描述；`egress` 字段标注外发动作；动作表与模型配置加缓存；
`lstat` 复用。

---

## 目录

| 文件 | 职责 |
|---|---|
| `detector.py` | 对象类型检测 + 上下文抽取（preview 默认关 + 脱敏） |
| `actions.json` | 动作表 + 高危清单 + `egress` 外发标注 |
| `model.py` | 模型接入层，OpenAI 兼容，零依赖 |
| `model_config.json` | 模型配置（**含 API key，已 gitignore**） |
| `ocr.ps1` | Windows 自带 OCR，本地跑不联网 |
| `executor.py` | 执行层。local / model / stub 三类分明，带大小闸门 |
| `router.py` | 通道核心 `route()` + 加固后的 HTTP 总线 |
| `cli.py` | SendTo 入口，结果三件套 |
| `evidence.py` | 落盘（仓库外）+ SHA-256 + `elapsed_ms` |
| `tests/test_channel.py` | 19 条自检断言 |

## 用法

资源管理器选中对象 → 右键 → **发送到** → `Armory · ...`（10 个动作）

```bash
python install_sendto.py             # 装所有已实现动作
python uninstall_sendto.py           # 卸载，不留注册表
python -m unittest discover -s tests # 自检
```

HTTP 总线（**默认不可用**，必须先设白名单）：

```bash
set ARMORY_ALLOWED_ROOTS=D:\Armory
python router.py 8791                # 启动时打印 token 文件位置
```

## 实测耗时（有留痕，不是自述）

每条 evidence 现在记 `elapsed_ms`，性能断言可复证：

| 动作 | 耗时 | 验证结果 |
|---|---|---|
| 总结 | 约 3–15 秒 | 抓到文档要点，中文干净 |
| 翻译 | 数十秒（长文） | docstring 译英文、代码标识符原样保留 |
| 图片描述 | 约 10 秒 | 认出三档套餐与 `$20/$50/$90`，输出中文 |
| OCR | 数秒 | 本地引擎，英文可用；**精度一般**（`services`→`servlces`） |
| 其余 6 个 | <1 秒 | 纯本地 |

模型选型（NVIDIA NIM 81 个在架模型逐个实测）：
主模型 `openai/gpt-oss-20b`，视觉 `meta/llama-3.2-11b-vision-instruct` + 回译中文。

## 踩过的坑

1. **推理模型的 token 预算陷阱。** `reasoning_content`（思考）会先吃掉几百 token，
   `max_tokens` 给小了 → 思考完了但 `content` 还空。**绝不能拿 `reasoning_content`
   顶替**，否则整段思考过程当成答案端给用户。现在只认 `content`，为空则
   `max_tokens` ×3 重试，仍空就明确报错。
2. **短问题选不出模型。** `gpt-oss-20b` 短问答 3 秒干净，长输入才暴露问题。
   选型必须拿真实长度的输入测。
3. **PowerShell 5.1 只认带 BOM 的 UTF-8**（`utf-8-sig`），否则中文文件名乱码。
4. **配置数据是潜在的注入入口。** 动作标签会被拼进 PowerShell 字符串和文件名，
   必须做白名单，不能假设它永远是良性的。

## 真相边界

**已真机验证：** 上表全部动作；19 条自检断言通过；证据落 `%LOCALAPPDATA%`；
敏感文件（含 `model_config.json`）抽不到 preview；凭据形状会被脱敏；
被拒绝的动作不留正文快照；HTTP 无白名单拒绝启动。

**仍未接线（status=stub）：** `audit`（缺 GOLink 通道）

**Permission Gate：** `rename` 及任何 `risk != none` 的动作一律拒绝。
`egress: true` 只标注不拦截——外发是那几个动作的存在意义，但动作表里如实写明。

**未实机验证：** 系统通知弹窗（GUI 断言不了，脚本确实调用了）。

**未修复（需要用户决策）：** git 历史里 15 份含正文的 evidence。当前无 remote 不急，
外发前必须清理。

## 下一步

1. **等你用顺了再说** —— 现在右键工具真能用，先攒真实使用反馈
2. 接 GOLink 让 `audit` 转正、`rename` 补确认流程
3. **换壳（IExplorerCommand）**：风险未验证——微软只说 `desktop5:Verb` 最低 17763，
   没保证 Win10 19041 的 Explorer 会实例化它。动手前先做最小验证包探路，不赌
4. 剥离非系统右键对象：「选中文本」归 IN 输入法，「网页内容」归 Dory 扩展
