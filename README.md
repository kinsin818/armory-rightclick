# Armory 右键增强 · 通道实现

在 Windows 资源管理器里右键任意对象，直接对它下 AI 命令。

> 右键 → 发送到 → 「Armory · 总结」，选中一份文档，几秒后摘要就在剪贴板里。

这是 Armory 生态里的**上下文动作入口**。它不是一个聊天窗口，而是"对当前对象下命令"的系统入口。

---

## 为什么先做通道，而不是先堆动作

右键菜单里能做的 AI 动作可以列出几十上百个：总结、翻译、OCR、代码审计、生成 README……
但它们全是下游能力调用，**不是工程难点**。

真正的难点是中间那条通道：

```
入口 → Permission Gate → Context Extractor → Action Router → Executor → Evidence
```

动作只是 `actions.json` 里的一张配置表。入口从「发送到」换成注册表 verb、
`IExplorerCommand` 或浏览器扩展，中间这层一行都不用改。

## 现在能做什么

资源管理器选中对象 → 右键 → **发送到** → `Armory · ...`

| 动作 | 类型 | 说明 |
|---|---|---|
| 查看信息 / 复制 SHA-256 / 复制路径列表 | 本地 | 不联网，<1 秒 |
| 提取代码结构 / 读取图片元信息 / 生成目录索引 | 本地 | 不联网，<1 秒 |
| OCR 识别文字 | 本地 | 用 Windows 自带 OCR 引擎，不联网不花钱 |
| 总结 / 翻译 | 模型 | 需配置模型端点 |
| 生成图片描述 | 模型 | 需配置视觉模型 |

```bash
python install_sendto.py      # 装进「发送到」菜单
python uninstall_sendto.py    # 卸载，不留注册表
python -m unittest discover -s tests
```

## 安装

**依赖**：Python 3.10+（Windows），**零第三方包**。OCR 用系统自带引擎，
HTTP 用标准库，剪贴板调 PowerShell。

```bash
git clone <this-repo>
cd rightclick
cp model_config.example.json model_config.json   # 填入你的模型端点与 key
python install_sendto.py
```

配置也可以用环境变量，key 就不用落盘：

```
ARMORY_LLM_BASE_URL / ARMORY_LLM_API_KEY / ARMORY_LLM_MODEL / ARMORY_LLM_VISION_MODEL
```

任何 OpenAI 兼容端点都能接（示例文件里给了 8 家 preset，含本地 Ollama / LM Studio）。

## 安全设计

这套东西会读本地文件、会把内容发给第三方模型，所以默认策略是**拒绝优先**：

**外发前的五道闸门。** 「总结」不只是读文件就发，它先过：体积上限 → 敏感文件名
→ 是否纯文本 → 读多少 → 内容脱敏。

- 文件名像凭据或配置（`key` / `secret` / `token` / `.env` / `*config*.json` /
  `.pem` / `id_rsa`）→ **直接拒绝发送**。这类文件往往很小（几 KB），
  体积闸门根本拦不住，只能靠文件名判据。
- 不是敏感文件名、但正文里夹着凭据形状（`sk-` / `-----BEGIN` / `api_key=` …）
  → **抹掉再发**，并告诉你「已抹掉 N 处疑似凭据」。

**Permission Gate 是默认拒绝，不是黑名单。** `risk != none` 的动作一律拦下；
**连 `risk` 字段都没写的动作也拦下**（`meta.get("risk")` 得到 `None`，照样拒绝）。
动作表将来会长到几十条，新增高危动作不会因为"忘了登记"而悄悄放行。
权限判定还早于上下文抽取，被拒绝的动作不留任何正文快照。

**证据不落在仓库里。** 每次执行落一条 JSON 到
`%LOCALAPPDATA%\Armory\evidence\`，带 SHA-256 和耗时。正文预览默认关闭，
开了也要过敏感名单和脱敏。

**HTTP 总线默认不可用。** 可选常驻服务供其他入口接入，但不设
`ARMORY_ALLOWED_ROOTS` 时 `serve()` 直接拒绝启动；运行时强制校验
`X-Armory-Token`（常量时间比较）、`Host` 限回环、`Origin` 同源、请求体 ≤1MB。
信任分两档：本地入口传下来的路径可信，网络调用必须落在白名单根目录内。

## 架构

| 文件 | 职责 |
|---|---|
| `detector.py` | 对象类型检测 + 上下文抽取（`is_sensitive_path` / `redact` 两条路共用） |
| `actions.json` | 动作表 + 高危清单 + `egress` 外发标注 |
| `model.py` | 模型层，OpenAI 兼容，零依赖 |
| `executor.py` | 执行层，五道闸门 |
| `router.py` | 通道核心 `route()` + 加固后的 HTTP 总线 |
| `cli.py` | 入口，结果三件套（落证据 + 剪贴板 + 通知） |
| `evidence.py` | 落盘（仓库外）+ SHA-256 + 耗时 |
| `tests/test_channel.py` | 28 条自检，约 0.5 秒，不联网 |

## 踩过的坑

1. **推理模型的 token 预算陷阱。** 很多模型的 `reasoning_content`（思考过程）会先
   吃掉几百 token。`max_tokens` 给小了，模型想完了但 `content` 还是空的。
   此时**绝不能拿 `reasoning_content` 顶替**——那会把整段思考过程当成答案端给用户，
   看起来就像模型在胡说。正确做法：只认 `content`，为空就加大预算重试，仍空就报错。
2. **短问题选不出模型。** 同一个模型短问答 3 秒干净、长输入才暴露问题。
   选型必须用真实长度的输入测。
3. **配置数据是潜在注入入口。** 动作标签和动作键会被拼进 PowerShell 字符串
   和文件名，两个都要白名单校验，不能假设它永远良性。
4. **"分块读"不等于流式。** 攒 `chunks` 再 `join` 比直接 `read` 还费内存
   （实测 33MB 输入：整文件读 121MB，攒 chunks 反而 153MB）。真流式要逐行迭代，
   实测降到约 0MB。
5. **改一个面要同步检查另一条路。** 这里踩过：本地留存加了敏感防护、外发那条没加，
   结果外发反成了最大漏点。防护要看「路径 × 数据」的全矩阵。
6. **PowerShell 5.1 只认带 BOM 的 UTF-8**（`utf-8-sig`），否则中文文件名乱码。
7. **重写 git 历史前先备份工作树**，且备份要排除 `.git`——否则把要清理的内容
   又复制了一份。

## 真相边界

**仍未接线**（返回 `status: "stub"`，绝不假装成功）：`audit`（需要调度通道）。

**高危动作**：`rename` 一类会改动文件的动作，在确认流程实现前一律拒绝执行。

**未实机验证**：系统通知弹窗（脚本确实调用，但本环境无法断言 GUI 结果）。

**OCR 精度**：用的是 Windows 自带引擎，免费、不联网，但精度一般
（实测把 `services` 识别成 `servlces`）。要高精度需接专业 OCR 服务。

## 路线

- [ ] 接任务调度通道，让 `audit` 转正
- [ ] 高危动作的确认流程
- [ ] 换用 `IExplorerCommand` 做一级右键菜单（**风险未验证**：微软只说明
      `desktop5:Verb` 元素最低支持 1809，未保证 Windows 10 的 Explorer
      会实例化该接口，动手前需先做最小验证包）
- [ ] 剥离非系统右键对象：「选中文本」归输入法侧，「网页内容」归浏览器扩展侧

## 许可

MIT。见 `LICENSE`。
