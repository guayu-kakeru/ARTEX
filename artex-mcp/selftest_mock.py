#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest_mock.py — 用本地 mock 的 ARTEX API 端到端自测 artex_mcp.py。

不起真实 ARTEX（那需要 PostgreSQL），而是起一个实现了关键端点的假服务，
再以 MCP 客户端身份通过 stdio 驱动 artex_mcp.py，验证：
  1. initialize / tools/list 协议握手
  2. 每个工具的调用链路（含登录拿 JWT、Bearer 传递、SSE 监听）
  3. 错误路径（未知工具、缺参、401/404 透传）

用法：python selftest_mock.py
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
MCP_SCRIPT = os.path.join(HERE, "artex_mcp.py")

TOKEN = "mock-jwt-token"
STATE = {"tasks": [], "pending": [{"id": 7, "task": "12", "tool": "Bash", "command": "curl http://target/"}]}


class MockArtex(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静音
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return self.headers.get("Authorization") == "Bearer " + TOKEN

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/health":
            return self._json({"ok": True, "service": "artex", "version": "0.3.15-mock"})
        if not self._authed():
            return self._json({"error": "未授权"}, 401)
        if path == "/api/stats":
            return self._json({"engine_mode": "idle", "llm_configured": True, "assets": 42})
        if path == "/api/llm/profiles":
            return self._json({"profiles": [{"id": 1, "name": "claude", "active": True}]})
        if path == "/api/tasks":
            return self._json({
                "tasks": [
                    {"id": "12", "description": "mock 任务", "goal": "探测 example.com",
                     "status": "running", "findings": {"critical": 1, "high": 2, "medium": 0, "low": 0}}
                ],
                "active": "12",
            })
        if path.startswith("/api/tasks/"):
            tid = path.split("/")[3]
            if tid != "12":
                return self._json({"error": "task not found"}, 404)
            return self._json({"id": tid, "status": "running", "goal": "探测 example.com"})
        if path == "/api/exploration/activity/history":
            return self._json({"items": [
                {"seq": 4, "worker": "work#1", "kind": "tool_use", "tool": "Bash",
                 "summary": "mimikatz.exe privilege::debug", "detail": "mimikatz # sekurlsa::logonpasswords"},
                {"seq": 3, "worker": "planner", "kind": "tool_use", "tool": "graph_overview"},
                {"seq": 2, "worker": "work#1", "kind": "text", "summary": "发现登录页"},
                {"seq": 1, "worker": "system", "kind": "text", "summary": "任务启动"},
            ], "has_more": False})
        if path == "/api/exploration/activity/stream":
            return self._sse()
        if path == "/api/exploration/findings":
            return self._json({"items": [
                {"id": "88", "title": "SQL 注入", "severity": "high", "status": "open"}
            ], "total": 1, "page": 1, "page_size": 20})
        if path.startswith("/api/exploration/findings/"):
            return self._json({"id": path.split("/")[-1], "title": "SQL 注入", "severity": "high"})
        if path == "/api/exploration/graph":
            return self._json({"nodes": [{"id": "g1", "kind": "goal"}, {"id": "i1", "kind": "intent"}],
                               "edges": [{"from": "g1", "to": "i1", "rel": "spawns"}]})
        if path == "/api/exploration/frontier":
            return self._json({"intents": [{"id": 5, "state": "open", "summary": "测登录接口"}]})
        if path == "/api/assets":
            return self._json({"assets": [{"id": 1, "type": "subdomain", "value": "www.example.com"}], "total": 1})
        if path == "/api/logs/history":
            return self._json({"items": [{"id": 1, "level": "info", "msg": "engine started"}], "has_more": False})
        if path == "/api/intercept/pending":
            return self._json({"pending": STATE["pending"]})
        if path == "/api/update/check":
            return self._json({"current": "0.3.15", "latest": "0.3.15", "update_available": False})
        return self._json({"error": "not found: " + path}, 404)

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for seq in (10, 11):
            payload = json.dumps({"seq": seq, "worker": "work#1", "kind": "tool_use",
                                  "tool": "Bash", "summary": "curl http://target/"}, ensure_ascii=False)
            self.wfile.write(("id: %d\ndata: %s\n\n" % (seq, payload)).encode("utf-8"))
            self.wfile.flush()
        time.sleep(3)  # 保持流打开，迫使客户端按秒数收尾

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        body = json.loads(raw.decode("utf-8") or "{}")
        if path == "/api/auth/login":
            if body.get("username") == "ARTEX" and body.get("password") == "mock-pass":
                return self._json({"token": TOKEN})
            return self._json({"error": "用户名或密码错误"}, 401)
        if not self._authed():
            return self._json({"error": "未授权"}, 401)
        if path == "/api/tasks":
            STATE["tasks"].append(body)
            return self._json({"id": "13", "status": "created", "goal": body.get("goal")}, 201)
        if path.startswith("/api/tasks/") and path.endswith("/control"):
            return self._json({"id": path.split("/")[3], "paused": body.get("action") == "pause",
                               "status": "paused" if body.get("action") == "pause" else "running"})
        if "/intents/" in path and path.endswith("/control"):
            return self._json({"id": int(path.split("/")[-2]), "state": body.get("action")})
        if path.startswith("/api/intercept/pending/") and path.endswith("/decide"):
            return self._json({"ok": True, "decision": body.get("decision")})
        if path == "/api/update/apply":
            return self._json({"ok": True, "message": "staged artex.new, restarting"})
        return self._json({"error": "not found: " + path}, 404)


# ---------------------------------------------------------------------------
# MCP stdio 客户端
# ---------------------------------------------------------------------------

class McpClient:
    def __init__(self, env):
        self.proc = subprocess.Popen(
            [sys.executable, MCP_SCRIPT],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, encoding="utf-8", bufsize=1,
        )
        self._id = 0

    def call(self, method, params=None, timeout=30):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("MCP server 关闭了 stdout")
            line = line.strip()
            if not line:
                continue
            resp = json.loads(line)
            if resp.get("id") == self._id:
                return resp
        raise TimeoutError("等待 %s 响应超时" % method)

    def notify(self, method):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print("  [%s] %s%s" % (status, name, (" — " + str(detail)[:200]) if detail and not cond else ""))
    return cond


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockArtex)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("mock ARTEX listening on 127.0.0.1:%d" % port)

    env = dict(os.environ)
    env["ARTEX_URL"] = "http://127.0.0.1:%d" % port
    env["ARTEX_PASSWORD"] = "mock-pass"
    env.pop("ARTEX_TOKEN", None)

    client = McpClient(env)
    ok_all = True
    try:
        # 1. 握手
        r = client.call("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "selftest", "version": "0"},
        })
        ok_all &= check("initialize 返回 serverInfo", r["result"]["serverInfo"]["name"] == "artex-mcp")
        client.notify("notifications/initialized")

        r = client.call("tools/list")
        names = {t["name"] for t in r["result"]["tools"]}
        ok_all &= check("tools/list 返回 21 个工具", len(names) == 21, sorted(names))

        # 2. 监控类
        r = client.call("tools/call", {"name": "artex_health", "arguments": {}})
        ok_all &= check("artex_health", not r["result"]["isError"] and "artex" in r["result"]["content"][0]["text"])

        r = client.call("tools/call", {"name": "artex_list_tasks", "arguments": {}})
        ok_all &= check("artex_list_tasks（触发自动登录）", not r["result"]["isError"] and "mock 任务" in r["result"]["content"][0]["text"])

        r = client.call("tools/call", {"name": "artex_activity_stream", "arguments": {"task_id": "12", "seconds": 2, "max_events": 10}})
        text = r["result"]["content"][0]["text"]
        ok_all &= check("artex_activity_stream 收到 SSE 事件", not r["result"]["isError"] and '"seq": 10' in text and '"seq": 11' in text, text[:120])

        r = client.call("tools/call", {"name": "artex_findings", "arguments": {"task_id": "12"}})
        ok_all &= check("artex_findings(task)", not r["result"]["isError"] and "SQL 注入" in r["result"]["content"][0]["text"])

        r = client.call("tools/call", {"name": "artex_intercept_pending", "arguments": {}})
        ok_all &= check("artex_intercept_pending", not r["result"]["isError"] and "Bash" in r["result"]["content"][0]["text"])

        r = client.call("tools/call", {"name": "artex_activity_redline_check", "arguments": {"task_id": "12", "limit": 50}})
        text = r["result"]["content"][0]["text"]
        ok_all &= check("artex_activity_redline_check 命中注入样例", not r["result"]["isError"] and "凭据窃取" in text, text[:200])

        # 3. 控制类
        r = client.call("tools/call", {"name": "artex_create_task", "arguments": {
            "description": "自测任务", "goal": "探测 mock.local", "llm_profile_ids": [1]}})
        ok_all &= check("artex_create_task", not r["result"]["isError"] and '"id": "13"' in r["result"]["content"][0]["text"])

        r = client.call("tools/call", {"name": "artex_control_task", "arguments": {"task_id": "12", "action": "pause"}})
        ok_all &= check("artex_control_task(pause)", not r["result"]["isError"] and "paused" in r["result"]["content"][0]["text"])

        r = client.call("tools/call", {"name": "artex_intercept_decide", "arguments": {"pending_id": 7, "decision": "denied"}})
        ok_all &= check("artex_intercept_decide(denied)", not r["result"]["isError"])

        r = client.call("tools/call", {"name": "artex_update_apply", "arguments": {"confirm": True}})
        ok_all &= check("artex_update_apply", not r["result"]["isError"])

        # 4. 错误路径
        r = client.call("tools/call", {"name": "artex_no_such_tool", "arguments": {}})
        ok_all &= check("未知工具返回 JSON-RPC error", "error" in r)

        r = client.call("tools/call", {"name": "artex_create_task", "arguments": {}})
        ok_all &= check("缺 description 被拒", r["result"]["isError"])

        r = client.call("tools/call", {"name": "artex_update_apply", "arguments": {}})
        ok_all &= check("update_apply 无 confirm 被拒", r["result"]["isError"])

        r = client.call("tools/call", {"name": "artex_get_task", "arguments": {"task_id": "404"}})
        ok_all &= check("404 透传为 isError", r["result"]["isError"])

        # 5. 坏密码 → 401 路径
        client.close()
        env2 = dict(env); env2["ARTEX_PASSWORD"] = "wrong"
        client2 = McpClient(env2)
        r = client2.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "clientInfo": {"name": "t", "version": "0"}})
        r = client2.call("tools/call", {"name": "artex_list_tasks", "arguments": {}})
        ok_all &= check("错误密码登录失败被捕获", r["result"]["isError"] and "401" in r["result"]["content"][0]["text"])
        client2.close()
    finally:
        client.close()
        server.shutdown()

    print("\n%s" % ("ALL PASS" if ok_all else "SOME FAILED"))
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
