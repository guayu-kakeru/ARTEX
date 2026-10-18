#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""artex_watchdog.py — ARTEX 红线看门狗：实时监控 agent 执行的每条指令，
命中红线规则立即暂停任务（并否决审批门里挂起的同类调用）。

原理：订阅 ARTEX 的活动流 SSE（/api/exploration/activity/stream），
逐条检查 kind=tool_use 事件里的命令/URL（summary + detail + metadata），
用 redline.py 的规则引擎匹配。命中后：
  1. 写告警（redline_alerts.log，可选 webhook）
  2. POST /api/tasks/{id}/control {"action":"pause"} 暂停任务
  3. 可选：把该任务审批门里挂起的 pending 项全部判 denied
  4. 继续监控（或 --once 命中一次就退出）

用法：
  # 盯所有正在跑的任务（推荐）
  python artex_watchdog.py --all

  # 只盯某个任务
  python artex_watchdog.py --task 12

  # 只告警不暂停（试运行）
  python artex_watchdog.py --all --dry-run

  # 自定义规则文件
  python artex_watchdog.py --all --rules my_rules.json

环境变量同 artex_mcp.py：ARTEX_URL / ARTEX_PASSWORD / ARTEX_TOKEN。
"""

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redline import RedlineEngine, write_alert, default_rules_path  # noqa: E402

BASE_URL = os.environ.get("ARTEX_URL", "http://127.0.0.1:8787").rstrip("/")
HTTP_TIMEOUT = float(os.environ.get("ARTEX_TIMEOUT", "30"))
_token = ""


# ---------------------------------------------------------------- API 客户端

def _login(password):
    global _token
    payload = json.dumps({"username": "ARTEX", "password": password}).encode("utf-8")
    req = urllib.request.Request(
        BASE_URL + "/api/auth/login", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        _token = json.loads(r.read().decode("utf-8"))["token"]


def _api(method, path, body=None, timeout=None):
    url = BASE_URL + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if data:
        headers["Content-Type"] = "application/json"
    if _token:
        headers["Authorization"] = "Bearer " + _token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout or HTTP_TIMEOUT) as r:
        raw = r.read().decode("utf-8", "replace")
    return json.loads(raw) if raw.strip() else None


def _sse_events(path, seconds, since):
    """订阅 SSE seconds 秒，yield 事件 dict。断线/超时后由调用方重订阅。"""
    url = BASE_URL + path + (("&since=%d" % since) if since else "")
    req = urllib.request.Request(url, method="GET")
    if _token:
        req.add_header("Authorization", "Bearer " + _token)
    resp = urllib.request.urlopen(req, timeout=max(5.0, seconds + 10))
    buf = b""
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            try:
                line = resp.readline()
            except Exception:
                return
            if not line:
                return
            buf += line
            if buf.endswith(b"\n"):
                text = buf.decode("utf-8", "replace")
                buf = b""
                for block in text.split("\n\n"):
                    ev_id, data = None, None
                    for ln in block.splitlines():
                        if ln.startswith("id:"):
                            try:
                                ev_id = int(ln[3:].strip())
                            except ValueError:
                                pass
                        elif ln.startswith("data:"):
                            data = ln[5:].strip()
                    if data:
                        try:
                            ev = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        if ev_id:
                            ev["_sse_id"] = ev_id
                        yield ev
    finally:
        try:
            resp.close()
        except Exception:
            pass


# ---------------------------------------------------------------- 监控逻辑

class TaskWatcher(threading.Thread):
    """盯一个任务的活动流，命中红线就暂停。"""

    def __init__(self, task_id, engine, args, stop_event):
        super().__init__(daemon=True, name="watch-%s" % task_id)
        self.task_id = str(task_id)
        self.engine = engine
        self.args = args
        self.stop_event = stop_event
        self.since = 0
        self.hits = 0

    def log(self, msg):
        print("[%s] [task %s] %s" % (time.strftime("%H:%M:%S"), self.task_id, msg), flush=True)

    def handle_hit(self, ev, hit):
        self.hits += 1
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "task_id": self.task_id,
            "rule": hit["rule"],
            "action": "dry-run" if self.args.dry_run else hit["action"],
            "worker": ev.get("worker"),
            "tool": ev.get("tool"),
            "seq": ev.get("seq"),
            "summary": ev.get("summary"),
            "excerpt": hit["excerpt"],
        }
        write_alert(self.engine.cfg, record)
        self.log("!!! 红线命中 [%s] tool=%s seq=%s :: %s" % (
            hit["rule"], ev.get("tool"), ev.get("seq"), hit["excerpt"][:120]))
        if self.args.dry_run:
            self.log("(dry-run) 未执行暂停")
            return
        if hit["action"] == "pause":
            try:
                _api("POST", "/api/tasks/%s/control" % urllib.parse.quote(self.task_id),
                     body={"action": "pause"})
                self.log("已暂停任务 %s" % self.task_id)
            except urllib.error.HTTPError as e:
                self.log("暂停失败 HTTP %s: %s" % (e.code, e.read().decode("utf-8", "replace")[:200]))
            except Exception as e:
                self.log("暂停失败: %s" % e)
            if self.engine.cfg.get("deny_pending_on_match"):
                self.deny_pending()

    def deny_pending(self):
        """把该任务审批门里挂起的项全部判 denied（慢一点执行的操作就地否决）。"""
        try:
            pend = _api("GET", "/api/intercept/pending" + ("?task=%s" % self.task_id))
        except Exception as e:
            self.log("读取审批门失败: %s" % e)
            return
        items = pend.get("pending", pend) if isinstance(pend, dict) else pend
        if not isinstance(items, list):
            return
        for p in items:
            pid = p.get("id") if isinstance(p, dict) else None
            if not pid:
                continue
            try:
                _api("POST", "/api/intercept/pending/%s/decide" % pid, body={"decision": "denied"})
                self.log("已否决挂起审批 #%s（%s）" % (pid, p.get("tool", "")))
            except Exception as e:
                self.log("否决审批 #%s 失败: %s" % (pid, e))

    def run(self):
        backoff = 2
        while not self.stop_event.is_set():
            try:
                path = "/api/exploration/activity/stream?task=%s" % urllib.parse.quote(self.task_id)
                for ev in _sse_events(path, self.args.window, self.since):
                    if self.stop_event.is_set():
                        return
                    if ev.get("_sse_id"):
                        self.since = max(self.since, ev["_sse_id"])
                    elif ev.get("seq"):
                        self.since = max(self.since, int(ev["seq"]))
                    if not self.engine.is_tool_use(ev):
                        continue
                    hits = self.engine.match(ev)
                    for hit in hits:
                        self.handle_hit(ev, hit)
                        if self.args.once:
                            self.stop_event.set()
                            return
                backoff = 2  # 正常结束（窗口到）→ 立即重订阅
            except Exception as e:
                self.log("活动流出错（%s），%ds 后重连" % (e, backoff))
                self.stop_event.wait(backoff)
                backoff = min(backoff * 2, 60)


def running_tasks():
    """返回正在运行/排队的任务 id 列表。"""
    data = _api("GET", "/api/tasks")
    tasks = (data or {}).get("tasks", [])
    out = []
    for t in tasks:
        if t.get("status") in ("running", "queued", "paused", "created"):
            out.append(str(t.get("id")))
    return out


def main():
    ap = argparse.ArgumentParser(description="ARTEX 红线看门狗")
    ap.add_argument("--task", action="append", default=[], help="监控指定任务 id（可多次）")
    ap.add_argument("--all", action="store_true", help="监控所有活动任务（并跟随新任务）")
    ap.add_argument("--rules", default=default_rules_path(), help="规则文件路径")
    ap.add_argument("--window", type=int, default=55, help="单次 SSE 订阅时长（秒），默认 55")
    ap.add_argument("--dry-run", action="store_true", help="只告警，不暂停")
    ap.add_argument("--once", action="store_true", help="命中一次即退出")
    ap.add_argument("--poll", type=int, default=10, help="--all 模式下扫描新任务的间隔（秒）")
    args = ap.parse_args()

    if not args.task and not args.all:
        ap.error("请指定 --task <id> 或 --all")

    password = os.environ.get("ARTEX_PASSWORD", "")
    if not _token and not os.environ.get("ARTEX_TOKEN"):
        if not password:
            print("错误：未配置 ARTEX_PASSWORD / ARTEX_TOKEN", file=sys.stderr)
            return 2
        try:
            _login(password)
        except Exception as e:
            print("登录失败: %s" % e, file=sys.stderr)
            return 2
    elif os.environ.get("ARTEX_TOKEN"):
        globals()["_token"] = os.environ["ARTEX_TOKEN"]

    engine = RedlineEngine(args.rules)
    print("看门狗启动 | ARTEX=%s | 规则=%d 条 | 黑名单域名=%d | 模式=%s" % (
        BASE_URL, len(engine._compiled), len(engine.cfg.get("domain_blacklist", [])),
        "dry-run" if args.dry_run else "命中即暂停"), flush=True)

    stop_event = threading.Event()
    watchers = {}

    def ensure(task_id):
        if task_id not in watchers or not watchers[task_id].is_alive():
            w = TaskWatcher(task_id, engine, args, stop_event)
            watchers[task_id] = w
            w.start()

    for tid in args.task:
        ensure(str(tid))

    if args.all:
        print("--all 模式：持续扫描活动任务（Ctrl-C 退出）", flush=True)
        try:
            while not stop_event.is_set():
                try:
                    for tid in running_tasks():
                        ensure(tid)
                except Exception as e:
                    print("扫描任务列表失败: %s" % e, flush=True)
                stop_event.wait(args.poll)
        except KeyboardInterrupt:
            print("\n收到 Ctrl-C，停止看门狗", flush=True)
            stop_event.set()
    else:
        try:
            while not stop_event.is_set() and any(w.is_alive() for w in watchers.values()):
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n收到 Ctrl-C，停止看门狗", flush=True)
            stop_event.set()

    total = sum(w.hits for w in watchers.values())
    print("看门狗退出 | 共命中 %d 次 | 告警在 %s" % (
        total, engine.cfg.get("alert_log", "redline_alerts.log")), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
