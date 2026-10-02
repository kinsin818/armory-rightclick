# Armory 右键增强 · v0.2（模型已接）

对应文档：`D:\codex\11-Armory-右键增强.md`
建库：2026-10-02 · 模型接入：2026-10-02

## 一句话

文档里 60 多个 AI 动作是下游能力调用，不是工程难点。本仓库建的是中间那条**通道**：

```
入口(SendTo) → Context Extractor → Action Router → Executor → Evidence
```

动作表只是 `actions.json` 的一张配置。将来入口换成注册表 verb 或 IExplorerCommand，
这层代码一行都不用改。

## 目录

| 文件 | 职责 |
|---|---|
| `detector.py` | 对象类型检测 + 上下文抽取 |
| `actions.json` | 动作表 + 高危清单（Permission Gate 策略源） |
| `model.py` | 模型接入层，OpenAI 兼容，零依赖 |
| `model_config.json` | 模型配置（**含 API key，已 gitignore**） |
| `ocr.ps1` | Windows 自带 OCR，本地跑不联网 |
| `executor.py` | 执行层。local / model / stub 三类分明 |
| `router.py` | 通道核心 `route(action, paths)` + 可选 HTTP 常驻服务 |
| `cli.py` | SendTo 入口，结果三件套 |
| `evidence.py` | 每次执行落一条 + SHA-256 |

## 用法

资源管理器选中对象 → 右键 → **发送到** → `Armory · ...`

已装 10 个动作：

| 动作 | 类型 | 实测耗时 | 说明 |
|---|---|---|---|
| 查看信息 / 复制 SHA-256 / 复制路径列表 | local | <1s | 纯本地 |
| 提取代码结构 / 读取图片元信息 / 生成目录索引 | local | <1s | 纯本地 |
| OCR 识别文字 | local | 数秒 | Windows 自带引擎，不花钱 |
| 总结 | model | **约 3 秒** | 超长自动截断 |
| 翻译 | model | 数十秒（长文） | 输入压到 3000 字符 |
| 生成图片描述 | model | 约 10 秒 | 视觉模型出英文再译中文 |

```bash
python install_sendto.py             # 装所有已实现动作
python uninstall_sendto.py           # 卸载，不留注册表
python router.py 8791                # 可选常驻服务，供其他入口接入
```

## 模型配置

`model_config.json`（从 `model_config.example.json` 复制）或环境变量：

```
ARMORY_LLM_BASE_URL / ARMORY_LLM_API_KEY / ARMORY_LLM_MODEL / ARMORY_LLM_VISION_MODEL
```

当前实测选定的组合（NVIDIA NIM，81 个在架模型里逐个测出来的）：

```json
"model":        "openai/gpt-oss-20b",                  // 总结约 3s，翻译
"vision_model": "meta/llama-3.2-11b-vision-instruct"   // 看图约 7s，再译中文
```

## 踩过的坑（值得记住）

**1. 推理模型的 token 预算陷阱。** 货架上多数模型是推理模型，`reasoning_content`
（思考过程）会先吃掉几百 token。给小了 `max_tokens`，模型思考完了但正文没生成，
`content` 就是空的。此时**绝不能拿 `reasoning_content` 顶替**——那会把整段思考过程
当成答案端给用户，看起来就像模型在胡说。
现在的处理：只认 `content`；为空则 `max_tokens` 翻倍重试一次；还空就明确报错。

**2. 光测短问题选不出模型。** `gpt-oss-20b` 短问答 3 秒且干净，长输入才暴露问题。
选型必须拿真实长度的输入测。

**3. 慢模型不能用。** `deepseek-v4.1-flash` 稳定 40-45 秒，右键等不起；
`llama-3.2-90b-vision` 描述一张图超过 60 秒直接超时。图片描述因此改成两步：
小视觉模型（7s）出结果 + 文本模型（3s）译中文，总共 10 秒，比一步到位快 6 倍。

**4. PowerShell 5.1 只认带 BOM 的 UTF-8。** 生成含中文的 ps1 必须 `utf-8-sig`，
否则快捷方式名乱码。

## 真相边界

**已真机验证（2026-10-02，Win10 19041）：**

- `summarize` 总结 `00-Armory生态总规划.md`：3 秒级，准确抓到生态定位与各组件状态
- `translate` 翻译 `detector.py`：docstring 译英文、代码标识符原样保留
- `describe` 描述 Fiverr 定价截图：认出三档套餐与 `$20/$50/$90` 定价，输出中文
- `ocr` 识别同一张图：本地引擎，英文可用；**精度一般**（`services` 识别成 `servlces`）
- 6 个 local 动作、SendTo 端到端、10 个中文快捷方式文件名无乱码
- 每条执行都落 evidence + SHA-256

**仍未接线（返回 status=stub）：** `audit`（缺 GOLink 调度通道）

**Permission Gate：** 高危清单目前只有 `rename`，原型阶段直接拒绝执行
（`risk_policy.prototype_deny`）。确认流程没实现，不做半成品。

**未实机验证：** 系统通知弹窗（脚本已调用，GUI 结果无法在本会话断言）

**安全：** `model_config.json` 含明文 API key，已加入 `.gitignore`。
key 不写日志、不写 evidence。evidence 里只有动作、对象上下文和结果文本。

## 下一步

1. **等你用顺了再说。** 现在右键工具真能用了，先攒真实使用反馈。
2. **接 GOLink** 让 `audit` 转正、`rename` 补确认流程
3. **换壳**（IExplorerCommand）：等 SendTo 版攒够反馈再做。风险未验证——
   微软只说 `desktop5:Verb` 元素最低 17763，没保证 Win10 19041 的 Explorer
   会实例化 `IExplorerCommand`。动手前先做个最小验证包探路，不赌。
4. **剥离非系统右键对象**：「选中文本」归 IN 输入法，「网页内容」归 Dory 扩展。
