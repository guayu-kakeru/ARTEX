#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""redline.py — ARTEX 红线规则引擎（被 artex_watchdog.py 与 artex_mcp.py 共用）。

规则文件 redline_rules.json 结构：
{
  "rules": [
    {"name": "破坏性命令", "pattern": "(?i)(rm\\s+-rf|mkfs|format\\s+)", "action": "pause"},
    ...
  ],
  "domain_blacklist": ["example.com"],
  "domain_action": "pause",       // 命中黑名单域名的动作
  "on_match": "pause",            // 规则未单独指定 action 时的默认动作
  "deny_pending_on_match": true,  // 同时把审批门里挂起的调用判 denied
  "alert_log": "redline_alerts.log",
  "webhook": ""                   // 可选，命中时 POST 一段 JSON
}

匹配是大小写不敏感的正表达式（规则里也可自带 (?i)）。对每条活动记录，
把 summary + detail + metadata 拼成一段文本逐条规则匹配。
"""

import json
import os
import re
import time

DEFAULT_RULES = {
    "rules": [
        {
            "name": "破坏性命令",
            "pattern": r"(?i)(rm\s+-rf|rm\s+-fr|rmdir\s+/s|del\s+/[fq]\b|format\s+[a-z]:|mkfs\.|mkfs\s|dd\s+if=|>\s*/dev/sd|diskpart|shutdown\s+|reboot|init\s+0|halt\b)",
        },
        {
            "name": "凭据窃取/横向移动",
            "pattern": r"(?i)(mimikatz|sekurlsa|lsass|procdump|psexec|wmiexec|smbexec|atexec|impacket|hashdump|/etc/shadow|sam\s+hive|reg\s+save\s+hklm\\sam|net\s+user\s+.*\/add)",
        },
        {
            "name": "外联回弹/数据外传",
            "pattern": r"(?i)(nc\s+-e|ncat\s+-e|/dev/tcp/|bash\s+-i|powershell\s+-e\s|base64\s+-d\s*\|\s*(nc|bash)|curl\s+.*-T\s|scp\s+.*@|rsync\s+.*@|wget\s+.*--post-file)",
        },
        {
            "name": "数据库直接拖库",
            "pattern": r"(?i)(mysqldump|pg_dump|mongodump|into\s+outfile|select\s+.*\s+from\s+.*information_schema)",
        },
        {
            "name": "危险提权",
            "pattern": r"(?i)(chmod\s+777|setuid|sudo\s+su\b|runas\s+/user:administrator|icacls.*\/grant.*everyone)",
        },
    ],
    "domain_blacklist": [],
    "domain_action": "pause",
    "on_match": "pause",
    "deny_pending_on_match": True,
    "alert_log": "redline_alerts.log",
    "webhook": "",
}


class RedlineEngine:
    """加载规则文件，提供 match(activity_dict) -> [hit, ...]。"""

    def __init__(self, rules_path=None):
        self.cfg = dict(DEFAULT_RULES)
        self.rules_path = rules_path
        if rules_path and os.path.exists(rules_path):
            with open(rules_path, "r", encoding="utf-8") as f:
                user = json.load(f)
            for k, v in user.items():
                if v not in (None, "", []):
                    self.cfg[k] = v
        self._compiled = []
        for r in self.cfg.get("rules", []):
            pat = r.get("pattern", "")
            if not pat:
                continue
            try:
                self._compiled.append(
                    (r.get("name", "未命名规则"), re.compile(pat), r.get("action") or self.cfg.get("on_match", "pause"))
                )
            except re.error:
                continue  # 坏正则跳过，不让看门狗挂掉

    def _text_of(self, ev):
        parts = [str(ev.get("summary") or ""), str(ev.get("detail") or "")]
        md = ev.get("metadata")
        if md:
            parts.append(md if isinstance(md, str) else json.dumps(md, ensure_ascii=False))
        return " ".join(parts)

    def match(self, ev):
        """返回命中列表：[{rule, action, excerpt}]；空列表=干净。"""
        text = self._text_of(ev)
        if not text.strip():
            return []
        hits = []
        for name, rx, action in self._compiled:
            m = rx.search(text)
            if m:
                s = max(0, m.start() - 40)
                hits.append(
                    {
                        "rule": name,
                        "action": action,
                        "excerpt": text[s : m.end() + 60].replace("\n", " ")[:200],
                    }
                )
        # 域名黑名单：区分「分析中发现/提及」与「实际访问构造」
        # - 仅提及（如 JS 分析输出里列出内网域 URL）→ domain_mention_action（默认 alert，不停任务）
        # - 附近出现访问构造（curl/requests.get/urlopen/socket 等）→ domain_action（默认 pause）
        access_rx = None
        acp = self.cfg.get("domain_access_pattern")
        if acp:
            try:
                access_rx = re.compile(acp, re.I)
            except re.error:
                access_rx = None
        for dom in self.cfg.get("domain_blacklist", []):
            if dom and dom.lower() in text.lower():
                is_access = False
                if access_rx:
                    for m in re.finditer(re.escape(dom), text, re.I):
                        window = text[max(0, m.start() - 250):m.end() + 250]
                        if access_rx.search(window):
                            is_access = True
                            break
                if is_access:
                    action = self.cfg.get("domain_action", "pause")
                    rule_name = "域名黑名单(实际访问): %s" % dom
                else:
                    action = self.cfg.get("domain_mention_action", "alert")
                    rule_name = "域名黑名单(仅提及): %s" % dom
                hits.append(
                    {
                        "rule": rule_name,
                        "action": action,
                        "excerpt": dom,
                    }
                )
                break
        return hits

    def is_tool_use(self, ev):
        """只审工具调用事件；thinking/text 不审（没有可执行面）。"""
        return ev.get("kind") == "tool_use" and bool(ev.get("tool"))


def write_alert(cfg, record):
    """落一条告警到 alert_log（JSONL），可选 webhook。"""
    line = json.dumps(record, ensure_ascii=False)
    try:
        with open(cfg.get("alert_log", "redline_alerts.log"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    url = (cfg.get("webhook") or "").strip()
    if url:
        try:
            import urllib.request

            req = urllib.request.Request(
                url,
                data=json.dumps(record, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# 供 artex_mcp.py 复用：默认规则文件路径
def default_rules_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "redline_rules.json")
