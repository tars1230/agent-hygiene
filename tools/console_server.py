#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
console_server.py —— 本地控制台（纯标准库 HTTP 服务）

定位
  用户的需求：**不想问 AI**，想在自己电脑上点开一个入口，
  看状态 / 跑体检 / 看建议 / 管定时任务 / 看历史管控图表。
  这个服务就是那个入口的后端。

🔴 安全边界（不可绕过）
  · 只监听 127.0.0.1，**不对外暴露**——局域网也访问不到。
  · 所有「会动系统」的动作一律**不在 HTTP 层直接执行**：
    本服务只**展示**命令与代价，真正执行由用户在本机终端手动跑，
    或由界面上明确的「复制命令」按钮交给用户决定。
    理由：浏览器里的一个 POST 就能杀进程 = 一个 CSRF 就能杀进程。
  · 唯一允许 HTTP 写入的是**计划任务的触发器/参数**，
    且改 `--kill-handle-leak` 需要额外确认位（见 console_tasks 的安全规则）。

用法
  python tools/console_server.py [--port 8765] [--open]
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import console_backend as cb  # noqa: E402
import nowin  # noqa: E402

WEB_DIR = os.path.join(HERE, "console_web")

# CPU 差分需要跨请求保持上一次采样
_cpu_state = {}
_lock = threading.Lock()


def _say(*args):
    """安全打印。pythonw.exe 下 sys.stdout 是 None，直接 print 会抛异常。"""
    try:
        print(*args)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "ProcessRefresh/1.0"

    def log_message(self, fmt, *args):
        pass  # 静默，避免刷屏

    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except Exception as e:
            self._send_json({"error": str(e)}, 404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            return self._send_file(os.path.join(WEB_DIR, "index.html"),
                                   "text/html; charset=utf-8")
        if path == "/app.js":
            return self._send_file(os.path.join(WEB_DIR, "app.js"),
                                   "application/javascript; charset=utf-8")
        if path == "/style.css":
            return self._send_file(os.path.join(WEB_DIR, "style.css"),
                                   "text/css; charset=utf-8")
        if path == "/api/status":
            with _lock:
                st = cb.status(_cpu_state)
            return self._send_json(st)
        if path == "/api/recipes":
            with _lock:
                st = cb.status(_cpu_state)
            return self._send_json({"recipes": cb.recipes(st), "status": st})
        if path == "/api/tasks":
            return self._send_json(cb.tasks())
        if path == "/api/history":
            return self._send_json(cb.history())
        if path == "/api/snapshot":
            with _lock:
                st = cb.status(_cpu_state)
            p = cb.save_snapshot(st)
            return self._send_json({"ok": bool(p), "path": p})
        return self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            data = {}

        if path == "/api/task/trigger":
            r = cb.subprocess.run(
                [nowin.py_exe(), cb.TASK_SCRIPT, "set-trigger",
                 data.get("name", ""), data.get("kind", ""),
                 data.get("at", "")],
                capture_output=True, timeout=60,
                creationflags=nowin.no_window())
            cb.tasks(force=True)   # 改完立刻失效缓存，下次读是新的
            try:
                return self._send_json(json.loads(r.stdout.decode("utf-8", "replace")))
            except Exception:
                return self._send_json({"error": "任务管理返回异常"}, 500)

        if path == "/api/task/args":
            # 🔴 这个开关会真的杀进程 -> 必须前端传显式确认位
            allow = bool(data.get("allow_kill_switch"))
            r = cb.subprocess.run(
                [nowin.py_exe(), cb.TASK_SCRIPT, "set-args",
                 data.get("name", ""), data.get("args", "")]
                + (["--allow-kill-switch"] if allow else []),
                capture_output=True, timeout=60,
                creationflags=nowin.no_window())
            cb.tasks(force=True)
            try:
                return self._send_json(json.loads(r.stdout.decode("utf-8", "replace")))
            except Exception:
                return self._send_json({"error": "任务管理返回异常"}, 500)

        return self._send_json({"error": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    ap.add_argument("--bg", action="store_true",
                    help="后台运行（不阻塞当前终端）")
    ap.add_argument("--serve", action="store_true",
                    help=argparse.SUPPRESS)  # 内部用：真正的服务进程
    ap.add_argument("--check", action="store_true",
                    help="只检查端口是否已被占用（不启动）")
    a = ap.parse_args()

    if a.check:
        import socket
        s = socket.socket()
        s.settimeout(1.5)
        try:
            s.connect((a.host, a.port))
            _say("已在运行: http://%s:%d/" % (a.host, a.port))
            return
        except Exception:
            _say("未运行（端口 %d 空闲）" % a.port)
            return
        finally:
            s.close()

    url = "http://%s:%d/" % (a.host, a.port)

    if a.bg and not a.serve:
        # 🔴 端口已被占用 = 服务已在运行。
        #    这时**不要**再派生一个（会 OSError 崩掉），
        #    直接开浏览器指向已有服务即可 —— 双击快捷方式的常见路径。
        import socket
        _s = socket.socket()
        _s.settimeout(1.5)
        try:
            _s.connect((a.host, a.port))
            _s.close()
            _say("服务已在运行，直接打开浏览器。")
            if a.open:
                try:
                    webbrowser.open(url)
                except Exception:
                    pass
            return
        except Exception:
            try:
                _s.close()
            except Exception:
                pass

        # 🔴 真正脱离当前终端的做法：**派生子进程**并用 DETACHED_PROCESS。
        #    不能用 os._exit(0)——那会把整个进程连同服务线程一起杀掉，
        #    服务反而停了（实测踩过）。
        #    也不能只是 while True: sleep(3600)——那会让启动命令永远不返回，
        #    双击/计划任务场景下表现为「点了没反应」。
        flags = 0
        if os.name == "nt":
            flags = (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                     | 0x08000000)  # 0x08000000 = CREATE_NO_WINDOW
        # 🔴 用 pythonw.exe 启动服务本体：python.exe 一定会分配一个控制台，
        #    即使加了 CREATE_NO_WINDOW 也只是**子进程**不受影响，
        #    python.exe 自己仍会占一个控制台（Session 1 下 = 用户可见窗口）。
        #    服务本体不需要 stdout（只写日志文件），所以可以换 pythonw。
        subprocess.Popen(
            [nowin.pyw_exe(), os.path.abspath(__file__),
             "--serve", "--port", str(a.port), "--host", a.host]
            + (["--open"] if a.open else []),
            creationflags=flags,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True)
        _say("进程刷新 · 本地控制台")
        _say("  地址: %s" % url)
        _say("  已后台启动（无控制台窗口）")
        return

    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    _say("进程刷新 · 本地控制台")
    _say("  地址: %s" % url)
    _say("  只监听本机，局域网访问不到")
    if a.open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    _say("  Ctrl+C 退出")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        _say("\n已退出")


if __name__ == "__main__":
    main()
