#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest_watchdog.py — 看门狗端到端自测。

起一个 mock ARTEX：任务 #12 正在跑，活动流里先发正常工具调用，再发一条
红线命令（mimikatz），审批门里有一条挂起。然后：
  1. dry-run 跑看门狗 → 应检出红线但【不】暂停、不否决
  2. 实跑看门狗 → 应检出红线、暂停任务 #12、否决挂起审批
两条都验证通过才算 ALL PASS。
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
WATCHDOG = os.path.join(HERE, "artex_watchdog.py")
RULES = os.path.join(HERE, "redline_rules.json")

STATE = {"paused": [], "denied": [], "control_calls": []}

EVENTS = [
    # 正常事件：不该命中
    {"seq": 1, "worker": "work#1", "kind": "tool_use", "tool": "Bash",
     "summary": "curl -s http://target/ | head -50", "detail": "curl -sI http://target/"},
    {"seq": 2, "worker": "work#1", "kind": "text", "summary": "首页 200，发现登录表单"},
    # 红线事件：凭据窃取 → 必须命中
    {"seq": 3, "worker": "work#1", "kind": "tool_use", "tool": "Bash",
     "summary": "mimikatz.exe privilege::debug", "detail": "mimikatz # sekurlsa::logonpasswords"},
]


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return self.headers.get("Authorization", "").startswith("Bearer ")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/tasks":
            return self._json({"tasks": [{"id": "12", "status": "running"}], "active": "12"})
        if path == "/api/exploration/activity/stream":
            if not self._authed():
                return self._json({"error": "未授权"}, 401)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for ev in EVENTS:
                self.wfile.write(("id: %d\ndata: %s\n\n" % (
                    ev["seq"], json.dumps(ev, ensure_ascii=False))).encode("utf-8"))
                self.wfile.flush()
                time.sleep(0.3)
            time.sleep(4)  # 保持流打开
            return
        if path == "/api/intercept/pending":
            return self._json({"pending": [{"id": 7, "task": "12", "tool": "Bash",
                                            "command": "mimikatz.exe"}]})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        if path == "/api/auth/login":
            return self._json({"token": "mock-token"})
        if path == "/api/tasks/12/control":
            STATE["control_calls"].append(body)
            if body.get("action") == "pause":
                STATE["paused"].append("12")
            return self._json({"id": "12", "paused": True, "status": "paused"})
        if path == "/api/intercept/pending/7/decide":
            STATE["denied"].append(body.get("decision"))
            return self._json({"ok": True})
        return self._json({"error": "not found"}, 404)


def run_watchdog(url, extra_args, timeout=40):
    env = dict(os.environ)
    env["ARTEX_URL"] = url
    env["ARTEX_PASSWORD"] = "mock-pass"
    env.pop("ARTEX_TOKEN", None)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, WATCHDOG, "--task", "12", "--rules", RULES,
         "--window", "3", "--once"] + extra_args,
        env=env, capture_output=True, text=True, encoding="utf-8", timeout=timeout,
    )


def check(name, cond, detail=""):
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name,
                           (" — " + str(detail)[:300]) if (detail and not cond) else ""))
    return cond


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    port = srv.server_address[1]
    url = "http://127.0.0.1:%d" % port
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    alert_log = os.path.join(HERE, "redline_alerts.log")
    if os.path.exists(alert_log):
        os.remove(alert_log)
    ok_all = True

    # ① dry-run：检出但不暂停
    STATE["paused"].clear(); STATE["denied"].clear(); STATE["control_calls"].clear()
    r = run_watchdog(url, ["--dry-run"])
    out = r.stdout + r.stderr
    ok_all &= check("dry-run 检出红线", "红线命中" in out and "凭据窃取" in out, out[:300])
    ok_all &= check("dry-run 未暂停", STATE["paused"] == [] and STATE["control_calls"] == [])
    ok_all &= check("dry-run 未否决审批", STATE["denied"] == [])
    ok_all &= check("告警已落盘", os.path.exists(alert_log))

    # ② 实跑：检出 + 暂停 + 否决
    STATE["paused"].clear(); STATE["denied"].clear(); STATE["control_calls"].clear()
    r = run_watchdog(url, [])
    out = r.stdout + r.stderr
    ok_all &= check("实跑检出红线", "红线命中" in out, out[:300])
    ok_all &= check("已调用暂停", STATE["paused"] == ["12"], STATE["control_calls"])
    ok_all &= check("已否决挂起审批", STATE["denied"] == ["denied"], STATE["denied"])
    ok_all &= check("退出码 0", r.returncode == 0, r.returncode)

    srv.shutdown()
    print("\n%s" % ("ALL PASS" if ok_all else "SOME FAILED"))
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
