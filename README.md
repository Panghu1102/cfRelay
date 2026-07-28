# cfRelay

cfRelay 是一个基于 **Cloudflare Workers** 的轻量级 AI API 中继与管理网关。项目以单文件 Worker 的形式提供三份实现：`CN/worker.js`（中文注释版）、`EN/worker.js`（英文注释版）和 `Lite/worker.js`（精简 API 中转版）。`CN` 与 `EN` 的业务逻辑一致，`Lite` 仅保留单上游 API 中转、API Key 校验、模型映射和月度配额。

> 完整版当前代码标注版本：`1.0.0`，内部版本：`v3.2.1`。Lite 当前代码标注版本：`1.0.0`，内部版本：`1.0.0`。



## 快速部署教程（先看这里）

本项目不需要构建步骤。你可以选择部署 **Lite 精简版** 或 **CN/EN 完整版**：

- 如果只需要把一个 OpenAI 兼容 API 通过 Cloudflare Worker 中转给用户使用，优先选择 `Lite/worker.js`。
- 如果需要注册页、管理后台、双上游切换、知识库管理和检索增强，选择 `CN/worker.js` 或 `EN/worker.js`。

### 部署 Lite 精简版

Lite 版本只需要一个 KV Namespace 和一个上游 API，不需要 D1、注册页面、管理后台或邮件验证 Worker。

1. 在 Cloudflare 创建 Worker。
2. 创建 KV Namespace，并绑定到 Worker，绑定名必须是 `USER_KEYS_KV`。
3. 部署入口文件选择 `Lite/worker.js`。
4. 配置环境变量：

| 变量 | 必需 | 说明 | 示例 |
| --- | --- | --- | --- |
| `USER_KEYS_KV` | 是 | KV Namespace 绑定 | Cloudflare 绑定名，不是文本变量 |
| `UPSTREAM_BASE_URL` | 是 | 单个上游 Base URL | `https://api.openai.com` |
| `REAL_API_KEY` | 是 | 上游真实 API Key，建议用 secret | `sk-...` |
| `UPSTREAM_MODEL_ID` | 是 | 转发给上游的真实模型 ID | `gpt-4o-mini` |
| `REQUIRED_MODEL_NAME` | 否 | 客户端必须提交的模型名 | `relay-model` |
| `QUOTA_PER_USER_PER_MONTH` | 否 | 每个 API Key 每月请求额度，默认 `999` | `999` |

Wrangler 配置示例：

```toml
name = "cfrelay-lite"
main = "Lite/worker.js"
compatibility_date = "2026-07-28"

[[kv_namespaces]]
binding = "USER_KEYS_KV"
id = "<your-kv-namespace-id>"

[vars]
UPSTREAM_BASE_URL = "https://api.openai.com"
UPSTREAM_MODEL_ID = "gpt-4o-mini"
REQUIRED_MODEL_NAME = "relay-model"
QUOTA_PER_USER_PER_MONTH = "999"
```

敏感变量使用 secret：

```bash
wrangler secret put REAL_API_KEY
```

为用户创建可用 API Key：

```bash
wrangler kv key put --binding USER_KEYS_KV "userkey:user@example.com" '{"status":"active","createdAt":"2026-07-28T00:00:00.000Z"}'
```

客户端调用示例：

```bash
curl https://<your-lite-worker-domain>/v1/chat/completions \
  -H "Authorization: Bearer user@example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "relay-model",
    "messages": [
      {"role": "user", "content": "你好，请介绍一下 cfRelay Lite。"}
    ]
  }'
```

Lite 会校验 `Authorization`、检查 `userkey:<email>`、累计 `quota:<email>:<yyyy-mm>`，并把请求体中的 `model` 替换为 `UPSTREAM_MODEL_ID` 后转发到 `<UPSTREAM_BASE_URL>/v1/chat/completions`。

### 部署 CN/EN 完整版

1. 在 Cloudflare 创建 Worker。
2. 创建 KV Namespace，绑定名必须是 `USER_KEYS_KV`。
3. 创建 D1 数据库，绑定名必须是 `KNOWLEDGE_D1`。
4. 在 D1 中初始化知识库表：

```sql
CREATE TABLE IF NOT EXISTS knowledge (
  id TEXT PRIMARY KEY,
  name TEXT,
  text TEXT NOT NULL
);
```

5. 部署入口文件选择 `CN/worker.js` 或 `EN/worker.js`。
6. 配置完整变量和 secrets。最小必需项如下：

| 变量 | 说明 | 示例 |
| --- | --- | --- |
| `ADMIN_PASSWORD` | 管理员密码，建议用 secret | `change-me` |
| `UPSTREAM_BASE_URL` | API1 上游 Base URL | `https://api.openai.com` |
| `REAL_API_KEY` | API1 真实 API Key，建议用 secret | `sk-...` |
| `UPSTREAM_MODEL_ID` | API1 真实模型 ID | `gpt-4o-mini` |

Wrangler 配置示例：

```toml
name = "cfrelay"
main = "EN/worker.js"
compatibility_date = "2026-07-28"

[[kv_namespaces]]
binding = "USER_KEYS_KV"
id = "<your-kv-namespace-id>"

[[d1_databases]]
binding = "KNOWLEDGE_D1"
database_name = "cfrelay-knowledge"
database_id = "<your-d1-database-id>"

[vars]
ADMIN_USERNAME = "admin"
UPSTREAM_BASE_URL = "https://api.openai.com"
UPSTREAM_MODEL_ID = "gpt-4o-mini"
REQUIRED_MODEL_NAME = "relay-model"
QUOTA_PER_USER_PER_MONTH = "999"
LIMIT_PER_IP_PER_MONTH = "5"
DAILY_LIMIT = "2500"
```

敏感变量使用 secret：

```bash
wrangler secret put ADMIN_PASSWORD
wrangler secret put REAL_API_KEY
```

如使用 API2、知识库检索上游或邮件验证 Worker，请继续阅读下方的完整配置说明。

## 项目能做什么

cfRelay 将用户注册、API Key 校验、用量配额、上游模型转发、双上游切换、知识库检索和管理员面板整合在一个 Cloudflare Worker 中。它适合希望把真实上游 AI Key 隐藏在 Worker 后方，并给终端用户分配邮箱式 API Key 的场景。

核心能力包括：

- **用户注册页**：`GET /` 或 `GET /index.html` 返回注册页面。
- **激活码注册**：`POST /signup` 校验邮箱、密码、验证码、激活码，并写入 15 分钟待激活记录。
- **邮件激活轮询**：`GET /signup-status?email=...` 查询外部邮件 Worker 是否已创建正式用户 Key。
- **Bearer API Key 鉴权**：代理接口要求 `Authorization: Bearer <用户邮箱>`。
- **月度配额**：按用户和月份统计请求量，到期自动过期。
- **管理后台**：提供登录页、用户列表、封禁/解封/删除、增加额度、知识库管理、上游连通性测试等能力。
- **上游 AI 代理**：将客户端兼容 OpenAI Chat Completions 的请求转发给真实上游服务。
- **模型名映射**：客户端只看到 `REQUIRED_MODEL_NAME` / `REQUIRED_MODEL_NAME_2`，Worker 会替换成真实上游模型 ID。
- **双上游切换**：支持 API1/API2 手动模型选择，也支持管理员开启负载均衡后自动选择。
- **知识库检索增强**：通过 D1 保存知识文本，并可调用配置的检索/Embedding 上游提取相关上下文注入系统提示词。

## 目录结构

```text
cfRelay/
├── CN/
│   └── worker.js      # 中文注释版 Worker
├── EN/
│   └── worker.js      # 英文注释版 Worker
├── Lite/
│   └── worker.js      # 精简 API 中转版 Worker
├── LICENSE            # Apache-2.0 License
└── README.md          # 项目说明文档
```



## Lite 精简版说明

`Lite/worker.js` 是 `EN/worker.js` 的精简版，面向只需要 API 中转的场景。它没有任何 Web 页面、注册流程、管理后台、第二上游、负载均衡或 D1 知识库逻辑。

Lite 保留的核心流程：

1. 处理 `OPTIONS` CORS 预检请求。
2. 校验 `Authorization: Bearer <用户邮箱>`。
3. 从 KV 读取 `userkey:<用户邮箱>`，并拒绝不存在或 `status` 为 `banned` 的用户。
4. 使用 `quota:<用户邮箱>:<yyyy-mm>` 记录月度用量，并按 `QUOTA_PER_USER_PER_MONTH` 限制请求数。
5. 对 `POST` JSON 请求校验客户端模型名必须等于 `REQUIRED_MODEL_NAME`（默认 `example-model`）。
6. 将请求体中的 `model` 替换为 `UPSTREAM_MODEL_ID`。
7. 仅转发到 `UPSTREAM_BASE_URL` 这一套上游，并使用 `REAL_API_KEY` 作为上游 Bearer Token。

Lite 使用 Cloudflare Workers 标准模块入口和 Web API，不依赖 Node.js 专属模块；唯一 Cloudflare 绑定是 `USER_KEYS_KV`。

## 完整版运行逻辑总览

### 1. 路由分发

Worker 的入口是 `export default { async fetch(request, env) { ... } }`。入口函数按路径分发：

| 路径 | 方法 | 功能 |
| --- | --- | --- |
| `/`, `/index.html` | GET | 注册页面 |
| `/signup` | POST | 提交注册申请 |
| `/signup-status` | GET | 查询注册激活状态 |
| `/admin/login` | GET | 管理员登录页 |
| `/admin` | GET/POST | GET 重定向登录页；POST 校验管理员并展示控制台 |
| `/admin/api/users` | GET | 管理员获取用户与配额统计 |
| `/admin/api/knowledge` | GET | 管理员获取知识库列表 |
| `/admin/api/action` | POST | 管理员执行封禁、解封、删除、额度、配置等动作 |
| `/admin/api/add-knowledge` | POST | 添加知识库文本或文件 |
| `/admin/api/test-connection` | POST | 测试上游 API 连通性 |
| 其他路径 | 任意 | 转发到上游 AI API |

### 2. 注册与激活

注册页收集邮箱、密码、验证码和激活码。后端执行以下检查：

1. 请求体必须包含 `email`、`password`、`captcha`、`activationCode`。
2. 激活码必须能在 KV 中找到 `activation:<activationCode>`。
3. 邮箱格式必须合法，密码至少 8 位，验证码至少 4 位。
4. `userkey:<email>` 不存在，避免重复注册。
5. `pending:<email>` 不存在，避免重复提交待激活请求。
6. 按 `signup_ip:<ip>:<yyyy-mm>` 限制同一 IP 每月注册次数。
7. 使用 Web Crypto `crypto.subtle.digest('SHA-256', ...)` 计算密码哈希。
8. 在 KV 中写入 `pending:<email>`，TTL 为 900 秒。

提交成功后，前端每 5 秒请求 `/signup-status`。当外部邮件验证 Worker 创建 `userkey:<email>` 后，页面显示注册完成。

> 注意：本项目的注册流程依赖一个额外的邮件验证 Worker。该外部 Worker 需要读取 `pending:<email>`，完成邮箱验证后写入 `userkey:<email>`，并可按需记录 `createdAt`、`registrationIP`、`activatedWith`、`status` 等元数据。

### 3. API 代理与鉴权

除管理和注册路径外，其余路径都会进入代理逻辑：

1. `OPTIONS` 请求直接返回 CORS 预检响应。
2. 校验 `Authorization` 请求头，格式必须是 `Bearer <用户邮箱>`。
3. 在 KV 中读取 `userkey:<用户邮箱>`，不存在则拒绝。
4. 如果用户元数据 `status` 为 `banned`，拒绝访问。
5. 按 `quota:<用户邮箱>:<yyyy-mm>` 增加当月用量并校验月度上限。
6. POST 请求解析 JSON 请求体，校验客户端提交的模型名。
7. 根据模式选择上游 API：
   - 负载均衡关闭：`REQUIRED_MODEL_NAME` 对应 API1，`REQUIRED_MODEL_NAME_2` 对应 API2。
   - 负载均衡开启：自动在 API1/API2 之间选择，但客户端模型名仍必须是允许的模型名之一。
8. 移除客户端原有 system 消息，注入统一 system prompt。
9. 如配置了知识库检索上游，则读取 D1 中的知识文本，调用检索上游生成相关片段并注入 system prompt。
10. 将 `model` 替换成真实上游模型 ID，并使用真实上游 API Key 转发请求。

### 4. 负载均衡逻辑

负载均衡状态保存在 KV：`config:load_balancing_enabled`。

启用后：

- 若 API2 未完整配置，则自动回退 API1。
- API1 每日调用数保存在 `api1_daily_count:<yyyy-mm-dd>`。
- 当 API1 达到 `DAILY_LIMIT` 后切换到 API2。
- 若两次请求间隔小于 2 秒，则在 API1/API2 间交替，以降低短时集中请求压力。

### 5. 知识库与检索增强

知识库使用 Cloudflare D1，默认查询表名为 `knowledge`，字段为：

- `id`：字符串 ID，当前用 `Date.now().toString()` 生成。
- `name`：可选名称。
- `text`：知识正文。

管理员可在后台上传 `.txt`、`.md`、`.json`、`.csv` 文件或直接粘贴文本。检索流程会读取所有知识文本并调用配置的检索上游 `/v1/chat/completions`，让检索模型从上下文中抽取相关片段。

> 代码中将该能力命名为 Embedding/Retrieval，但实际调用的是 Chat Completions 兼容接口，而不是传统向量 Embeddings 接口。

## Cloudflare Workers 兼容性检查结论

已检查当前 Worker 代码，使用的 API 均属于 Cloudflare Workers 支持的 Web 标准或 Cloudflare 绑定能力：

- `export default { fetch(...) }` 模块化 Worker 入口。
- `Request`、`Response`、`Headers`、`URL`、`FormData`、`fetch` 等 Web API。
- `crypto.subtle.digest` 和 `TextEncoder`。
- KV 绑定：`env.USER_KEYS_KV.get/put/delete/list`。
- D1 绑定：`env.KNOWLEDGE_D1.prepare(...).bind(...).all/run()`。
- 不依赖 Node.js 专属模块，例如 `fs`、`path`、`http`、`Buffer`、`process`。
- 语法通过 `node --check` 检查。

本次检查同时修复了两个实现问题：

1. 非 POST 代理请求此前没有初始化上游配置，会在构造上游 URL 时访问未定义变量；现在默认使用 API1 上游配置。
2. 知识库检索结果此前计算后没有注入 system prompt；现在会在有检索结果时追加到 `SKILL` 区块。

## 完整版部署准备

如果部署 CN/EN 完整版，你需要准备：

1. 一个 Cloudflare 账号。
2. 一个 Workers 服务。
3. 一个 KV Namespace，绑定名必须是 `USER_KEYS_KV`。
4. 一个 D1 数据库，绑定名必须是 `KNOWLEDGE_D1`。
5. 一个兼容 OpenAI Chat Completions 的上游 API。
6. 可选：第二个上游 API。
7. 可选：知识库检索/Embedding 上游 API。
8. 可选：配套邮件验证 Worker，用于完成注册激活。

## 完整版 D1 初始化

在 D1 中创建知识库表：

```sql
CREATE TABLE IF NOT EXISTS knowledge (
  id TEXT PRIMARY KEY,
  name TEXT,
  text TEXT NOT NULL
);
```

## 环境变量与绑定

### 必需绑定

| 名称 | 类型 | 说明 |
| --- | --- | --- |
| `USER_KEYS_KV` | KV Namespace | 保存用户、配额、激活码、配置项 |
| `KNOWLEDGE_D1` | D1 Database | 保存知识库文本 |

### 必需变量

| 变量 | 说明 | 示例 |
| --- | --- | --- |
| `ADMIN_PASSWORD` | 管理员密码。未设置会导致后台不可用 | `change-me` |
| `UPSTREAM_BASE_URL` | API1 上游 Base URL | `https://api.openai.com` |
| `REAL_API_KEY` | API1 真实 API Key | `sk-...` |
| `UPSTREAM_MODEL_ID` | API1 真实模型 ID | `gpt-4o-mini` |

### 推荐变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMIN_USERNAME` | `Panghu1102` | 管理员用户名 |
| `REQUIRED_MODEL_NAME` | `example-model` | 客户端必须提交的 API1 模型名 |
| `REQUIRED_MODEL_NAME_2` | `example-model2` | 客户端必须提交的 API2 模型名 |
| `QUOTA_PER_USER_PER_MONTH` | `999` | 每用户每月请求额度 |
| `LIMIT_PER_IP_PER_MONTH` | `5` | 单 IP 每月注册次数上限 |
| `DAILY_LIMIT` | `2500` | API1 每日调用上限 |

### 可选第二上游

| 变量 | 说明 |
| --- | --- |
| `UPSTREAM_BASE_URL_2` | API2 上游 Base URL |
| `REAL_API_KEY_2` | API2 真实 API Key |
| `UPSTREAM_MODEL_ID_2` | API2 真实模型 ID；未设置时回退 `UPSTREAM_MODEL_ID` |

### 可选知识库检索上游

| 变量 | 说明 |
| --- | --- |
| `UPSTREAM_EMBEDDING_BASE_URL` | 检索上游 1 Base URL |
| `REAL_EMBEDDING_API_KEY` | 检索上游 1 API Key |
| `EMBEDDING_MODEL_ID` | 检索上游 1 模型 ID |
| `UPSTREAM_EMBEDDING_BASE_URL_2` | 检索上游 2 Base URL |
| `REAL_EMBEDDING_API_KEY_2` | 检索上游 2 API Key |
| `EMBEDDING_MODEL_ID_2` | 检索上游 2 模型 ID；未设置时回退 `EMBEDDING_MODEL_ID` |

## 完整版 wrangler 配置示例

项目当前没有内置 `wrangler.toml`。你可以按需创建，例如部署英文版：

```toml
name = "cfrelay"
main = "EN/worker.js"
compatibility_date = "2026-07-28"

[[kv_namespaces]]
binding = "USER_KEYS_KV"
id = "<your-kv-namespace-id>"

[[d1_databases]]
binding = "KNOWLEDGE_D1"
database_name = "cfrelay-knowledge"
database_id = "<your-d1-database-id>"

[vars]
ADMIN_USERNAME = "admin"
UPSTREAM_BASE_URL = "https://api.openai.com"
UPSTREAM_MODEL_ID = "gpt-4o-mini"
REQUIRED_MODEL_NAME = "relay-model"
QUOTA_PER_USER_PER_MONTH = "999"
LIMIT_PER_IP_PER_MONTH = "5"
DAILY_LIMIT = "2500"
```

敏感变量建议使用 Wrangler secrets：

```bash
wrangler secret put ADMIN_PASSWORD
wrangler secret put REAL_API_KEY
```

如果使用 API2 或检索上游，也用 `wrangler secret put` 写入相应 Key。

## KV 数据格式

### 激活码

注册前需要在 KV 中放入激活码：

| Key | Value | 说明 |
| --- | --- | --- |
| `activation:<code>` | 任意非空字符串 | 允许用户用 `<code>` 发起注册 |

示例：

```bash
wrangler kv key put --binding USER_KEYS_KV "activation:demo-code" "1"
```

### 待激活用户

| Key | Value | TTL |
| --- | --- | --- |
| `pending:<email>` | SHA-256 密码哈希 | 900 秒 |

### 正式用户

邮件验证 Worker 应创建：

```json
{
  "createdAt": "2026-07-28T00:00:00.000Z",
  "registrationIP": "203.0.113.10",
  "activatedWith": "email-verification",
  "status": "active"
}
```

Key 为：

```text
userkey:<email>
```

### 配额与配置

| Key | Value | 说明 |
| --- | --- | --- |
| `quota:<email>:<yyyy-mm>` | 数字字符串 | 用户当月已用请求数 |
| `signup_ip:<ip>:<yyyy-mm>` | 数字字符串 | IP 当月注册次数 |
| `api1_daily_count:<yyyy-mm-dd>` | 数字字符串 | API1 当日调用数 |
| `config:load_balancing_enabled` | `true` 或 `false` | 是否启用负载均衡 |
| `config:retrieval_prompt` | 文本 | 自定义检索提示词 |

## 完整版调用示例

客户端请求时使用用户邮箱作为 Bearer Token，模型名使用管理员暴露的 `REQUIRED_MODEL_NAME`：

```bash
curl https://<your-worker-domain>/v1/chat/completions \
  -H "Authorization: Bearer user@example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "relay-model",
    "messages": [
      {"role": "user", "content": "你好，请介绍一下 cfRelay。"}
    ]
  }'
```

Worker 会将请求转发到：

```text
<UPSTREAM_BASE_URL>/v1/chat/completions
```

并将请求体中的 `model` 替换为真实的 `UPSTREAM_MODEL_ID`。

## 管理后台使用

1. 访问 `https://<your-worker-domain>/admin/login`。
2. 输入 `ADMIN_USERNAME` 与 `ADMIN_PASSWORD`。
3. 登录后可查看：
   - 总用户数。
   - 本月总调用数。
   - 本月剩余额度。
   - API1 今日调用数。
   - 用户列表与状态。
   - 知识库列表。
4. 可执行：
   - 封禁/解封用户。
   - 删除用户。
   - 增加用户剩余额度。
   - 添加/删除知识库。
   - 编辑检索提示词。
   - 开启/关闭负载均衡。
   - 测试上游 API 连通性。

## 安全注意事项

- 不要把真实上游 API Key 写入代码仓库，应使用 Cloudflare secrets。
- 管理后台当前使用表单登录后将用户名和密码注入页面脚本，适合个人/小规模场景；公开生产环境建议增加 Cookie Session、CSRF 防护和更严格的认证机制。
- 注册验证码当前只检查长度，不是真实图形或邮件验证码；真正的注册安全依赖激活码和外部邮件验证 Worker。
- `handleSignupStatus` 只按邮箱查询激活状态；如果公开部署，建议按实际需求增加节流或临时 token。
- 管理页面渲染用户和知识库文本时未做完整 HTML 转义；如果允许不可信管理员上传任意内容，建议补充转义函数。
- 知识库检索会把 D1 中的全部知识文本拼接发送给检索上游；知识量较大时建议改为分页、关键词粗筛或真正的向量召回。

## 开发与检查

本项目无需构建步骤。可使用以下命令做基本语法检查：

```bash
node --check CN/worker.js
node --check EN/worker.js
```

如果本地已安装 Wrangler，可运行：

```bash
wrangler dev --local --config wrangler.toml
```

## License

本项目使用 Apache License 2.0。详见 `LICENSE`。
