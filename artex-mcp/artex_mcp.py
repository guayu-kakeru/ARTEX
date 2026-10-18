#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""artex-mcp — 把 ARTEX（AI 自主渗透测试系统）包装成一个 MCP server。

ARTEX 本身是一个 Go 单体服务（默认 http://127.0.0.1:8787），提供：
  - REST API  /api/*（JWT 鉴权，Authorization: Bearer <token>）
  - SSE       /api/exploration/activity/stream、/api/logs/stream

本文件用 Python 标准库实现 MCP（stdio 传输，newline-delimited JSON-RPC 2.0），
零第三方依赖，可在任何有 Python 3.9+ 的机器上运行。

鉴权：首次调用时用 ARTEX_PASSWORD（配合固定用户名 ARTEX）登录拿 JWT，
进程内缓存；登录态 7 天有效。也可以直接用 ARTEX_TOKEN 提供一个已有 JWT。

环境变量：
  ARTEX_URL       ARTEX 服务地址，默认 http://127.0.0.1:8787
  ARTEX_PASSWORD  管理员密码（对应用户名恒为 ARTEX）
  ARTEX_TOKEN     可选，直接给一个已签发的 JWT（优先级高于密码登录）
  ARTEX_TIMEOUT   单次 HTTP 超时秒数，默认 30

工具分两组：
  监控（只读）：health/stats/list_tasks/get_task/activity_history/
               activity_stream/findings/get_finding/exploration_graph/
               frontier/assets/logs/llm_profiles/intercept_pending
  控制（写）：  create_task/control_task/control_intent/
               intercept_decide/update_check/update_apply
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redline import RedlineEngine, default_rules_path  # noqa: E402

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("ARTEX_URL", "http://127.0.0.1:8787").rstrip("/")
USERNAME = "ARTEX"  # 后端硬编码：authLogin 只接受这个用户名
HTTP_TIMEOUT = float(os.environ.get("ARTEX_TIMEOUT", "30"))

_token = os.environ.get("ARTEX_TOKEN", "").strip()


# ---------------------------------------------------------------------------
# ARTEX HTTP 客户端
# ---------------------------------------------------------------------------

class ArtexError(Exception):
    """带 HTTP 状态码的 ARTEX API 错误。"""

    def __init__(self, status, body):
        self.status = status
        self.body = body
        super().__init__("ARTEX API %s: %s" % (status, body))


def _request(method, path, body=None, timeout=None, auth=True, stream=False):
    """发一次请求。stream=True 时返回原始响应对象（给 SSE 用）。"""
    url = BASE_URL + path
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if auth:
        token = _ensure_token()
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    resp = urllib.request.urlopen(req, timeout=timeout or HTTP_TIMEOUT)
    if stream:
        return resp
    with resp:
        raw = resp.read().decode("utf-8", "replace")
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _ensure_token():
    """返回可用 JWT：环境变量 ARTEX_TOKEN > 已登录缓存 > 密码登录。"""
    global _token
    if _token:
        return _token
    password = os.environ.get("ARTEX_PASSWORD", "")
    if not password:
        raise ArtexError(
            0,
            "未配置凭据：请设置环境变量 ARTEX_PASSWORD（或 ARTEX_TOKEN）。"
            "ARTEX 的登录用户名恒为 ARTEX。",
        )
    url = BASE_URL + "/api/auth/login"
    payload = json.dumps({"username": USERNAME, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            out = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise ArtexError(e.code, "登录失败: " + detail)
    except urllib.error.URLError as e:
        raise ArtexError(0, "连不上 ARTEX（%s）：%s" % (BASE_URL, e))
    _token = out.get("token", "")
    if not _token:
        raise ArtexError(0, "登录响应里没有 token: %r" % (out,))
    return _token


def _api(method, path, body=None, timeout=None, auth=True):
    """带统一错误处理的 API 调用，返回 (ok, payload)。auth=False 用于 /api/health。"""
    try:
        return True, _request(method, path, body=body, timeout=timeout, auth=auth)
    except ArtexError as e:
        return False, {"error": str(e), "status": e.status}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        return False, {"error": detail, "status": e.code}
    except urllib.error.URLError as e:
        return False, {"error": "connection failed: %s" % e, "status": 0}
    except Exception as e:  # 兜底，绝不让 MCP server 挂掉
        return False, {"error": "%s: %s" % (type(e).__name__, e), "status": 0}


def _qs(**kwargs):
    """构造查询串，跳过 None/空串。"""
    parts = []
    for k, v in kwargs.items():
        if v is None or v == "":
            continue
        parts.append("%s=%s" % (urllib.parse.quote(k), urllib.parse.quote(str(v))))
    return ("?" + "&".join(parts)) if parts else ""


# ---------------------------------------------------------------------------
# SSE：活动流 / 日志流
# ---------------------------------------------------------------------------

def _sse_tail(path, seconds, max_events):
    """订阅一条 SSE 流 seconds 秒，收集 data: 行的 JSON，返回事件列表。"""
    events = []
    deadline = time.time() + max(1, seconds)
    resp = _request("GET", path, timeout=max(2.0, seconds + 5), stream=True)
    try:
        resp.fp.raw._sock.settimeout(1.0)  # 让 readline 有机会检查 deadline
    except Exception:
        pass
    buf = b""
    try:
        while time.time() < deadline and len(events) < max_events:
            try:
                line = resp.readline()
            except Exception:
                continue  # 读超时：循环回去看 deadline
            if not line:
                break  # 流关闭
            buf += line
            if buf.endswith(b"\n"):
                _drain_sse_buffer(buf, events)
                buf = b""
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return events


def _drain_sse_buffer(raw, events):
    """解析一段 SSE 字节（可能含多条 data:），抽取 JSON data 行。"""
    try:
        text = raw.decode("utf-8", "replace")
    except Exception:
        return
    for block in text.split("\n\n"):
        for line in block.splitlines():
            if line.startswith("data:"):
                payload = line[5:].strip()
                if not payload or payload == "[keepalive]":
                    continue
                try:
                    events.append(json.loads(payload))
                except json.JSONDecodeError:
                    events.append({"_raw": payload})


# ---------------------------------------------------------------------------
# MCP 工具定义
# ---------------------------------------------------------------------------

def _tool(name, description, schema):
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": schema,
            "additionalProperties": False,
        },
    }


_S = {"type": "string"}
_I = {"type": "integer"}
_B = {"type": "boolean"}

TOOLS = [
    # ---- 连接与自检 ----
    _tool("artex_health", "ARTEX 健康检查（无需登录）。返回 ok/service/version。", {}),
    _tool(
        "artex_stats",
        "全局运行态势：engine_mode、llm_configured、资产总数、流量条数、"
        "指定/活动任务的 token 与漏洞统计。",
        {"task": dict(_S, description="任务 id；省略=当前活动任务")},
    ),
    _tool(
        "artex_llm_profiles",
        "列出 LLM 配置（profile）。create_task 需要其中的 id；也能看出哪些配置了 API Key。",
        {},
    ),
    # ---- 监控 ----
    _tool(
        "artex_list_tasks",
        "任务列表（含状态、目标、漏洞分级计数、token、最近活动时间）。监控总入口。",
        {},
    ),
    _tool(
        "artex_get_task",
        "单个任务详情（生命周期、目标、范围、意图/事实统计）。",
        {"task_id": dict(_S, description="任务 id")},
    ),
    _tool(
        "artex_activity_history",
        "任务活动历史（分页）：planner/worker 的思考、工具调用、写回。"
        "session 不填=主 agent 对话；plan=规划者；intent:<id>=某条意图的执行过程。"
        "before=上一页最后一条的 seq 可实现向上翻页。",
        {
            "task_id": dict(_S, description="任务 id"),
            "limit": dict(_I, description="条数，默认 50，上限 500"),
            "before": dict(_I, description="游标：取小于该 seq 的记录"),
            "session": dict(_S, description="会话过滤：main（默认）| plan | intent:<id>"),
        },
    ),
    _tool(
        "artex_activity_stream",
        "实时订阅任务活动流（SSE），监听 seconds 秒后返回期间收到的事件。"
        "用于盯梢正在跑的任务。",
        {
            "task_id": dict(_S, description="任务 id"),
            "seconds": dict(_I, description="监听秒数，默认 20，上限 120"),
            "max_events": dict(_I, description="最多收集多少条，默认 100"),
            "since": dict(_I, description="游标：只收大于该 seq 的事件"),
        },
    ),
    _tool(
        "artex_findings",
        "漏洞发现列表。带 task_id=该任务；不带=全局发现库（分页）。",
        {
            "task_id": dict(_S, description="可选，任务 id"),
            "limit": dict(_I, description="全局分页时每页条数，默认 20"),
            "page": dict(_I, description="全局分页页码"),
        },
    ),
    _tool(
        "artex_get_finding",
        "漏洞详情（含证据、血缘 lineage 入口信息）。",
        {"finding_id": dict(_S, description="漏洞 id")},
    ),
    _tool(
        "artex_exploration_graph",
        "探索图快照：goal/intent/fact/finding 节点与边（血缘链）。",
        {"task_id": dict(_S, description="任务 id")},
    ),
    _tool(
        "artex_frontier",
        "意图队列（frontier）：待领/运行中的意图及状态。",
        {"task_id": dict(_S, description="任务 id")},
    ),
    _tool(
        "artex_assets",
        "资产图查询：域名/子域/IP/服务/端点。支持 type 过滤与公司/任务过滤。",
        {
            "type": dict(_S, description="资产类型，如 subdomain/service/endpoint"),
            "company_id": dict(_I, description="公司 id"),
            "task_id": dict(_I, description="任务 id"),
            "limit": dict(_I, description="条数，默认 50"),
        },
    ),
    _tool(
        "artex_logs",
        "后端日志（环形缓冲+DB 历史）。",
        {"limit": dict(_I, description="条数，默认 100，上限 500")},
    ),
    _tool(
        "artex_intercept_pending",
        "审批门：当前挂起待人工裁决的工具调用（guard/intercept）。"
        "AI 监控到 pending 后可提醒人或自动调 artex_intercept_decide。",
        {"task_id": dict(_S, description="可选，只看某任务")},
    ),
    _tool(
        "artex_activity_redline_check",
        "红线扫描：用 redline_rules.json 的规则检查某任务（或全局）最近的工具调用，"
        "返回命中列表（只读，不停任务）。要实时监控+自动急停请用 artex_watchdog.py。",
        {
            "task_id": dict(_S, description="可选，不填=扫全局最近活动"),
            "limit": dict(_I, description="检查最近多少条，默认 200"),
        },
    ),
    # ---- 控制 ----
    _tool(
        "artex_create_task",
        "创建并自动启动一个渗透任务。goal 是给 planner 的自然语言目标；"
        "description 是任务描述。llm_profile_ids 可省略（用激活配置）。"
        "⚠️ 只允许对已授权目标使用。",
        {
            "description": dict(_S, description="任务描述（必填）"),
            "goal": dict(_S, description="目标/意图说明，如「探测 example.com 的 API 面」"),
            "name": dict(_S, description="可选任务名"),
            "llm_profile_ids": {
                "type": "array",
                "items": _I,
                "description": "LLM 配置 id 链；省略=激活配置",
            },
            "timeout_seconds": dict(_I, description="任务级超时（秒），0=不限"),
            "seed_first_intent": dict(_B, description="true=跳过首轮 planner 直接派种子意图"),
        },
    ),
    _tool(
        "artex_control_task",
        "任务级控制：pause 暂停 / resume 恢复。",
        {
            "task_id": dict(_S, description="任务 id"),
            "action": dict(_S, description="pause | resume", enum=["pause", "resume"]),
        },
    ),
    _tool(
        "artex_control_intent",
        "意图级控制：pause/resume/cancel（cancel 需给原因，软删保留血缘）。",
        {
            "task_id": dict(_S, description="任务 id"),
            "intent_id": dict(_I, description="意图 id"),
            "action": dict(_S, description="pause | resume | cancel"),
            "mode": dict(_S, description="cancel 时：soft（默认）| hard"),
            "reason": dict(_S, description="cancel 原因（必填）"),
        },
    ),
    _tool(
        "artex_intercept_decide",
        "审批门裁决：allowed 放行 / denied 拒绝一个挂起的工具调用。",
        {
            "pending_id": dict(_I, description="挂起记录 id"),
            "decision": dict(_S, description="allowed | denied", enum=["allowed", "denied"]),
        },
    ),
    _tool(
        "artex_update_check",
        "检查 ARTEX 新版本（连 GitHub Releases）。",
        {},
    ),
    _tool(
        "artex_update_apply",
        "下载并安装新版本（会重启服务，中断运行中的任务）。需确认。",
        {"confirm": dict(_B, description="必须显式传 true 才会执行")},
    ),
]


# ---------------------------------------------------------------------------
# 工具实现
# ---------------------------------------------------------------------------

def _t_health(args):
    ok, data = _api("GET", "/api/health", auth=False)
    return ok, data


def _t_stats(args):
    ok, data = _api("GET", "/api/stats" + _qs(task=args.get("task")))
    return ok, data


def _t_llm_profiles(args):
    ok, data = _api("GET", "/api/llm/profiles")
    return ok, data


def _t_list_tasks(args):
    ok, data = _api("GET", "/api/tasks")
    return ok, data


def _t_get_task(args):
    tid = args.get("task_id")
    if not tid:
        return False, {"error": "task_id 必填"}
    ok, data = _api("GET", "/api/tasks/" + urllib.parse.quote(str(tid)))
    return ok, data


def _t_activity_history(args):
    tid = args.get("task_id")
    if not tid:
        return False, {"error": "task_id 必填"}
    ok, data = _api(
        "GET",
        "/api/exploration/activity/history"
        + _qs(task=tid, limit=args.get("limit"), before=args.get("before"),
              session=args.get("session")),
    )
    return ok, data


def _t_activity_stream(args):
    tid = args.get("task_id")
    if not tid:
        return False, {"error": "task_id 必填"}
    seconds = min(max(int(args.get("seconds") or 20), 1), 120)
    max_events = min(max(int(args.get("max_events") or 100), 1), 1000)
    path = "/api/exploration/activity/stream" + _qs(
        task=tid, since=args.get("since")
    )
    try:
        events = _sse_tail(path, seconds, max_events)
    except ArtexError as e:
        return False, {"error": str(e), "status": e.status}
    except Exception as e:
        return False, {"error": "%s: %s" % (type(e).__name__, e)}
    return True, {
        "task_id": tid,
        "listened_seconds": seconds,
        "events": events,
        "count": len(events),
    }


def _t_findings(args):
    task = args.get("task_id")
    if task:
        ok, data = _api("GET", "/api/exploration/findings" + _qs(task=task))
    else:
        ok, data = _api(
            "GET",
            "/api/exploration/findings"
            + _qs(limit=args.get("limit") or 20, page=args.get("page") or 1),
        )
    return ok, data


def _t_get_finding(args):
    fid = args.get("finding_id")
    if not fid:
        return False, {"error": "finding_id 必填"}
    ok, data = _api(
        "GET", "/api/exploration/findings/" + urllib.parse.quote(str(fid))
    )
    return ok, data


def _t_exploration_graph(args):
    tid = args.get("task_id")
    if not tid:
        return False, {"error": "task_id 必填"}
    ok, data = _api("GET", "/api/exploration/graph" + _qs(task=tid))
    return ok, data


def _t_frontier(args):
    tid = args.get("task_id")
    if not tid:
        return False, {"error": "task_id 必填"}
    ok, data = _api("GET", "/api/exploration/frontier" + _qs(task=tid))
    return ok, data


def _t_assets(args):
    ok, data = _api(
        "GET",
        "/api/assets"
        + _qs(
            type=args.get("type"),
            company_id=args.get("company_id"),
            task_id=args.get("task_id"),
            limit=args.get("limit") or 50,
        ),
    )
    return ok, data


def _t_logs(args):
    ok, data = _api("GET", "/api/logs/history" + _qs(limit=args.get("limit") or 100))
    return ok, data


def _t_intercept_pending(args):
    ok, data = _api(
        "GET", "/api/intercept/pending" + _qs(task=args.get("task_id"))
    )
    return ok, data


def _t_activity_redline_check(args):
    """扫描最近活动里的工具调用，返回红线命中（只读）。

    带 task_id 只扫该任务；不带则先拉任务列表，逐任务扫描（activity/history
    接口本身要求 task 参数，没有全局入口）。
    """
    engine = RedlineEngine(default_rules_path())
    limit = min(max(int(args.get("limit") or 200), 1), 500)
    task = args.get("task_id")
    task_ids = [task] if task else []
    if not task_ids:
        ok, data = _api("GET", "/api/tasks")
        if not ok:
            return False, data
        task_ids = [str(t.get("id")) for t in (data or {}).get("tasks", []) if t.get("id")]
    hits, checked, scanned = [], 0, 0
    for tid in task_ids:
        ok, data = _api("GET", "/api/exploration/activity/history"
                        + _qs(task=tid, limit=limit))
        if not ok:
            continue
        items = data.get("items", []) if isinstance(data, dict) else []
        checked += len(items)
        for ev in items:
            if not engine.is_tool_use(ev):
                continue
            scanned += 1
            for h in engine.match(ev):
                hits.append({
                    "task_id": tid,
                    "seq": ev.get("seq"), "worker": ev.get("worker"),
                    "tool": ev.get("tool"), "summary": (ev.get("summary") or "")[:120],
                    "rule": h["rule"], "excerpt": h["excerpt"],
                })
    return True, {
        "tasks_scanned": len(task_ids),
        "checked": checked,
        "scanned_tool_calls": scanned,
        "rules_loaded": len(engine._compiled),
        "hits": hits,
        "note": "只读扫描；实时监控+自动急停用 artex-mcp/artex_watchdog.py",
    }


def _t_create_task(args):
    desc = (args.get("description") or "").strip()
    if not desc:
        return False, {"error": "description 必填"}
    body = {"description": desc, "goal": args.get("goal") or desc}
    for key in ("name", "llm_profile_ids", "timeout_seconds", "seed_first_intent"):
        if args.get(key) not in (None, ""):
            body[key] = args[key]
    ok, data = _api("POST", "/api/tasks", body=body)
    return ok, data


def _t_control_task(args):
    tid = args.get("task_id")
    action = args.get("action")
    if not tid:
        return False, {"error": "task_id 必填"}
    if action not in ("pause", "resume"):
        return False, {"error": "action 必须是 pause 或 resume"}
    ok, data = _api(
        "POST",
        "/api/tasks/" + urllib.parse.quote(str(tid)) + "/control",
        body={"action": action},
    )
    return ok, data


def _t_control_intent(args):
    tid = args.get("task_id")
    iid = args.get("intent_id")
    action = args.get("action")
    if not tid or not iid:
        return False, {"error": "task_id 与 intent_id 必填"}
    if action not in ("pause", "resume", "cancel"):
        return False, {"error": "action 必须是 pause/resume/cancel"}
    body = {"action": action}
    if action == "cancel":
        mode = args.get("mode") or "soft"
        reason = (args.get("reason") or "").strip()
        if not reason:
            return False, {"error": "cancel 必须提供 reason"}
        body["mode"] = mode
        body["reason"] = reason
    ok, data = _api(
        "POST",
        "/api/tasks/%s/intents/%s/control" % (urllib.parse.quote(str(tid)), iid),
        body=body,
    )
    return ok, data


def _t_intercept_decide(args):
    pid = args.get("pending_id")
    decision = args.get("decision")
    if not pid:
        return False, {"error": "pending_id 必填"}
    if decision not in ("allowed", "denied"):
        return False, {"error": "decision 必须是 allowed 或 denied"}
    ok, data = _api(
        "POST",
        "/api/intercept/pending/%s/decide" % pid,
        body={"decision": decision},
    )
    return ok, data


def _t_update_check(args):
    ok, data = _api("GET", "/api/update/check", timeout=60)
    return ok, data


def _t_update_apply(args):
    if args.get("confirm") is not True:
        return False, {
            "error": "更新会重启 ARTEX 并中断运行中的任务。确认请传 confirm=true。"
        }
    ok, data = _api("POST", "/api/update/apply", body={}, timeout=120)
    return ok, data


HANDLERS = {
    "artex_health": _t_health,
    "artex_stats": _t_stats,
    "artex_llm_profiles": _t_llm_profiles,
    "artex_list_tasks": _t_list_tasks,
    "artex_get_task": _t_get_task,
    "artex_activity_history": _t_activity_history,
    "artex_activity_stream": _t_activity_stream,
    "artex_findings": _t_findings,
    "artex_get_finding": _t_get_finding,
    "artex_exploration_graph": _t_exploration_graph,
    "artex_frontier": _t_frontier,
    "artex_assets": _t_assets,
    "artex_logs": _t_logs,
    "artex_intercept_pending": _t_intercept_pending,
    "artex_activity_redline_check": _t_activity_redline_check,
    "artex_create_task": _t_create_task,
    "artex_control_task": _t_control_task,
    "artex_control_intent": _t_control_intent,
    "artex_intercept_decide": _t_intercept_decide,
    "artex_update_check": _t_update_check,
    "artex_update_apply": _t_update_apply,
}


# ---------------------------------------------------------------------------
# MCP stdio 协议（newline-delimited JSON-RPC 2.0）
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "artex-mcp", "version": "0.3.15"}


def _send(msg):
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _result(msg_id, result):
    _send({"jsonrpc": "2.0", "id": msg_id, "result": result})


def _error(msg_id, code, message):
    _send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})


def _tool_result(msg_id, ok, payload):
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if isinstance(payload, str):
        text = payload
    _result(
        msg_id,
        {
            "content": [{"type": "text", "text": text}],
            "isError": not ok,
        },
    )


def _handle(msg):
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        _result(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        )
        return

    if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return  # 通知，无需响应

    if method == "ping":
        _result(msg_id, {})
        return

    if method == "tools/list":
        _result(msg_id, {"tools": TOOLS})
        return

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if handler is None:
            _error(msg_id, -32602, "unknown tool: %s" % name)
            return
        try:
            ok, payload = handler(args)
        except Exception as e:  # 工具异常不当掉 server
            ok, payload = False, {"error": "%s: %s" % (type(e).__name__, e)}
        _tool_result(msg_id, ok, payload)
        return

    if msg_id is not None:
        _error(msg_id, -32601, "method not found: %s" % method)


def main():
    # Windows 下强制 stdout 用 UTF-8，避免中文工具描述在 GBK 控制台乱码/报错
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
    except Exception:
        pass
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _error(None, -32700, "parse error")
            continue
        try:
            _handle(msg)
        except Exception as e:
            if msg.get("id") is not None:
                _error(msg.get("id"), -32603, "internal error: %s" % e)


if __name__ == "__main__":
    main()
