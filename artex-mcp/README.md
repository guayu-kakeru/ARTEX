# artex-mcp — 让 AI 监控和控制 ARTEX 的 MCP Server

> 把 [ARTEX](https://github.com/Autumn-27/ARTEX)（AI 自主渗透测试系统）的 REST/SSE API
> 包装成标准 MCP server，让任何 MCP 客户端（DSH / Claude Desktop / Cline …）用自然语言
> 监控与控制 ARTEX。完整运维手册见 [使用手册.md](使用手册.md)。
>
> **许可证**：随本仓库采用 AGPL-3.0（与 ARTEX 主项目一致）。

把 [ARTEX](../artex-0.3.15-windows-amd64/README.md)（AI 自主渗透测试系统，默认
`http://127.0.0.1:8787`）包装成一个标准 MCP server。任何支持 MCP 的 AI 客户端
（DeepSeek Harness / Claude Desktop / Cline / Cherry Studio …）挂上它之后，就可以
用自然语言完成：

- **监控**：任务列表与状态、实时活动流（SSE）、漏洞发现、探索图、意图队列、资产、
  后端日志、LLM 配置、审批门挂起项
- **控制**：创建任务、暂停/恢复任务、暂停/恢复/取消单条意图、审批门裁决
  （allowed/denied）、检查并安装新版本

零第三方依赖：只用到 Python 3.9+ 标准库，MCP over stdio 协议手写实现。

## 文件

| 文件 | 说明 |
| --- | --- |
| `artex_mcp.py` | MCP server 本体（stdio） |
| `artex_watchdog.py` | **红线看门狗**：实时监控 agent 指令，命中红线立即暂停任务 |
| `redline.py` + `redline_rules.json` | 红线规则引擎与规则文件（团队可自行增删） |
| `selftest_mock.py` | 自测：内置一个 mock ARTEX API，端到端验证全部工具与错误路径（17 项） |
| `selftest_watchdog.py` | 看门狗自测：mock 一个会发红线指令的任务，验证检出/暂停/否决（8 项） |
| `使用手册.md` | **完整运维手册**：启停、喂资产、建任务参数、危险命令防控、结果输出、FAQ |

## 快速开始

```bash
# 1. 自测（不需要真实 ARTEX）
python selftest_mock.py            # 期望输出 ALL PASS

# 2. 指向真实 ARTEX
set ARTEX_URL=http://127.0.0.1:8787
set ARTEX_PASSWORD=<你的 ARTEX 管理员密码>
python artex_mcp.py               # 等待 stdio 上的 JSON-RPC
```

环境变量：

| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `ARTEX_URL` | ARTEX 服务地址 | `http://127.0.0.1:8787` |
| `ARTEX_PASSWORD` | 管理员密码（用户名恒为 `ARTEX`，后端硬编码） | 无 |
| `ARTEX_TOKEN` | 直接给一个已签发的 JWT（优先于密码登录） | 无 |
| `ARTEX_TIMEOUT` | 单次 HTTP 超时（秒） | `30` |

登录态在进程内缓存；ARTEX 的 JWT 有效期 7 天，过期后下一次调用会自动重新登录。

## 工具清单（20 个）

**监控（只读）**

| 工具 | 对应 API |
| --- | --- |
| `artex_health` | `GET /api/health` |
| `artex_stats` | `GET /api/stats?task=` |
| `artex_list_tasks` | `GET /api/tasks` |
| `artex_get_task` | `GET /api/tasks/{id}` |
| `artex_activity_history` | `GET /api/exploration/activity/history?task=&limit=&before=&session=`（session：main=主对话 / plan=规划者 / intent:&lt;id&gt;=某意图执行过程） |
| `artex_activity_stream` | `GET /api/exploration/activity/stream`（SSE，按秒监听） |
| `artex_activity_redline_check` | 扫最近工具调用，返回红线命中（只读；实时急停用看门狗） |
| `artex_findings` | `GET /api/exploration/findings?task=&page=&limit=` |
| `artex_get_finding` | `GET /api/exploration/findings/{id}` |
| `artex_exploration_graph` | `GET /api/exploration/graph?task=` |
| `artex_frontier` | `GET /api/exploration/frontier?task=` |
| `artex_assets` | `GET /api/assets?type=&company_id=&task_id=&limit=` |
| `artex_logs` | `GET /api/logs/history?limit=` |
| `artex_llm_profiles` | `GET /api/llm/profiles` |
| `artex_intercept_pending` | `GET /api/intercept/pending?task=` |

**控制（写）**

| 工具 | 对应 API | 备注 |
| --- | --- | --- |
| `artex_create_task` | `POST /api/tasks` | 创建即自动启动引擎 |
| `artex_control_task` | `POST /api/tasks/{id}/control` | `pause` / `resume` |
| `artex_control_intent` | `POST /api/tasks/{id}/intents/{iid}/control` | `pause`/`resume`/`cancel`（cancel 需 reason） |
| `artex_intercept_decide` | `POST /api/intercept/pending/{id}/decide` | `allowed` / `denied` |
| `artex_update_check` | `GET /api/update/check` | |
| `artex_update_apply` | `POST /api/update/apply` | 必须显式 `confirm=true`；会重启服务 |

## 接入 DeepSeek Harness（DSH）

DSH 通过 ACP 的 `mcpServers` 挂载 MCP server，stdio 类型要求 `command` 为绝对路径。
在 DSH 的 MCP 设置中加入（路径按实际改）：

```json
{
  "mcpServers": [
    {
      "name": "artex",
      "type": "stdio",
      "command": "C:\\environment\\python312\\python.exe",
      "args": ["/path/to/artex-mcp/artex_mcp.py"],
      "env": [
        { "name": "ARTEX_URL", "value": "http://127.0.0.1:8787" },
        { "name": "ARTEX_PASSWORD", "value": "在这里填 ARTEX 管理员密码" }
      ]
    }
  ]
}
```

> DSH 的 env 是键值对数组（entries），不是对象——写成 `{"ARTEX_URL": "..."}` 会被拒。

## 接入 Claude Desktop / 其他标准 MCP 客户端

`claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "artex": {
      "command": "python",
      "args": ["/path/to/artex-mcp/artex_mcp.py"],
      "env": {
        "ARTEX_URL": "http://127.0.0.1:8787",
        "ARTEX_PASSWORD": "你的密码"
      }
    }
  }
}
```

## 红线看门狗（agent 指令监控 + 自动急停）

`artex_watchdog.py` 独立运行（不占 MCP 通道），订阅 ARTEX 活动流 SSE，
逐条检查 agent 发出的工具调用（Bash 命令、WebFetch URL 等）：

```bash
# 盯所有活动任务（推荐，跟随新任务）
python artex_watchdog.py --all

# 只盯某任务；只告警不暂停（试运行）；命中一次即退出
python artex_watchdog.py --task 12
python artex_watchdog.py --all --dry-run
python artex_watchdog.py --task 12 --once
```

命中后的动作（可配）：写 `redline_alerts.log` → `POST /api/tasks/{id}/control
{action:pause}` 暂停任务 → 把该任务审批门里挂起的 pending 全部判 `denied`。
可选 webhook 推送到群机器人。

规则在 `redline_rules.json`（正则，默认 5 类：破坏性命令 / 凭据窃取横向移动 /
外联回弹数据外传 / 拖库 / 危险提权）+ `domain_blacklist`（生产域名黑名单，
**强烈建议把顺丰生产域名填进去**）。改完重启看门狗生效。

自测：`python selftest_watchdog.py`（8/8 PASS，不需要真实 ARTEX）。

> 第一道防线其实在 ARTEX 自带审批门：页面「系统配置 → 拦截审批 → 工具配置」
> 里把 `Bash` 等危险工具加进审批清单，agent 调这些工具前就会挂起等人工裁决。
> 看门狗是第二道：规则漏网的指令在执行后立即被发现并急停。

## 典型用法（AI 视角）

```
你：现在 ARTEX 上有什么任务在跑？
AI：[artex_list_tasks] → #12 «XX 系统渗透» running，发现 critical×1 high×2

你：盯一下 #12 的执行过程，半分钟
AI：[artex_activity_stream task_id=12 seconds=30]
    → work#1 调 Bash 跑 curl；planner 派了新意图「测 /api/v2/user 越权」…

你：把 #12 暂停，等人工确认
AI：[artex_control_task task_id=12 action=pause] → {"paused": true, "status": "paused"}

你：审批门里挂起的那个 curl 我看了，放行
AI：[artex_intercept_pending] → id=7 Bash curl http://target/
    [artex_intercept_decide pending_id=7 decision=allowed] → {"ok": true}
```

## 安全边界（重要）

- 这个 MCP server 是**对 ARTEX 的完全控制面**：能建任务、能审批、能更新重启。
  只把它挂到你信任的 AI 客户端上；密码走环境变量，别写进会外发的文件。
- `artex_create_task` 会对 `goal` 指向的目标发起真实渗透行为。
  **仅限已授权目标**——ARTEX 本身的许可证也只允许本地/授权环境使用。
- `artex_activity_stream` 会阻塞监听 N 秒（上限 120s）；对长任务建议配合
  `artex_activity_history` 的 `before` 游标翻页，而不是一直挂着流。
- ARTEX 更新（`artex_update_apply`）= 进程重启，运行中的任务会被中断。

## 已知限制 / 后续可扩展

- 只覆盖了最常用的监控+控制面；未包装：ScopeSentry 资产同步、流量检索
  （`/api/traffic`）、会话对话（`/api/chat`）、工作区文件、技能管理、
  通知渠道、自定义工具。按同样模式在 `HANDLERS` 里加一行即可。
- SSE 客户端按"监听 N 秒后返回快照"实现，没有做长连接驻留；如果需要
  "事件驱动推送"，可以在 DSH 侧用定时轮询 `artex_activity_history` 代替。
- 未实现 MCP 的 `resources` 订阅（把任务/发现暴露成资源列表）与 `prompts`。
