"""A two-field Windows front end. All system work stays off the Tk thread."""

import ctypes
from ctypes import wintypes as w
import ntpath
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .engine import Engine
from . import __version__
from .errors import DirectoryRenameError, ManualRenameRequired, OperationError, RenProfileError
from .host import Host
from .native import Native
from .registry import Registry
from .simple import SimpleService, new_folder_path


def friendly_error(error):
    if isinstance(error, ManualRenameRequired):
        return str(error)
    text = str(error)
    cause, seen = error, set()
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, DirectoryRenameError):
            if "自动恢复未完成" in text:
                suffix = "\n自动恢复未完成，恢复资料已保留。请保持原用户注销，点击“恢复”。"
            else:
                suffix = "\n本次已恢复之前记录的改动。" if "已回滚" in text else ""
            return str(cause) + suffix
        if isinstance(cause, OperationError):
            if "自动恢复未完成" in text:
                suffix = "\n自动恢复未完成，恢复资料已保留。请保持原用户注销，查看本次详情。"
            elif "已回滚" in text:
                suffix = "\n软件改动已回滚，恢复资料已保留。"
            else:
                suffix = "\n已有恢复资料会保留，可查看本次详情。"
            return str(cause) + suffix
        cause = cause.__cause__
    if "正在运行本工具的用户" in text:
        return "这个用户正在使用电脑。请注销它，登录另一个管理员账户后再迁移。"
    if "仍已加载" in text or "进程运行" in text:
        return "这个用户还没有完全退出。请先注销它；仍有提示时，重启后只登录另一个管理员账户。"
    if "自动恢复未完成" in text or "无法卸载" in text:
        return "操作没有完成，恢复资料已保留。请重启后只登录另一个管理员账户，再点击“恢复”。"
    if "已回滚" in text:
        if "失败步骤：" in text:
            return text
        if "手动改名" in text:
            return "迁移没有完成，已恢复软件修改的设置。手动改好的文件夹和旧路径兼容入口保留，可查看本次详情后重试。"
        return "改名没有完成，已自动恢复之前的改动。可查看本次详情后重新尝试。"
    if isinstance(error, PermissionError):
        return "Windows 拒绝了访问。迁移未完成，已有恢复资料会保留。"
    return text


class App:
    def __init__(self, root, service):
        self.root, self.service = root, service
        self.events = queue.Queue()
        self.busy = False
        self.profiles, self.records, self.logs = [], [], []
        self.manual_window, self.manual_request = None, None
        self.root.title(f"用户文件夹改名 {__version__}")
        self.root.geometry("730x560")
        self.root.minsize(680, 560)
        self.root.configure(bg="#F4F6FA")
        self.root.option_add("*Font", ("Microsoft YaHei UI", 10))
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background="#F4F6FA")
        style.configure("TLabel", background="#F4F6FA", foreground="#253247")
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 22, "bold"))
        style.configure("Hint.TLabel", foreground="#66758A", font=("Microsoft YaHei UI", 9))
        style.configure("TButton", padding=(15, 8))
        style.configure("Primary.TButton", background="#2563EB", foreground="white", font=("Microsoft YaHei UI", 11, "bold"))
        style.map("Primary.TButton", background=[("disabled", "#CBD5E1"), ("active", "#1D4ED8")])
        style.configure("TEntry", padding=8)
        style.configure("TCombobox", padding=7)
        body = ttk.Frame(root, padding=28)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        ttk.Label(body, text="用户文件夹改名", style="Title.TLabel").grid(row=0, sticky="w")
        ttk.Label(body, text="自动清理占用并改名；仍受阻时，可手动改名后继续。", style="Hint.TLabel").grid(row=1, sticky="w", pady=(4, 20))
        ttk.Label(body, text="使用前：保存文件，注销要改名的用户，登录另一个管理员账户。\n开始后会强制结束占用目标文件夹的相关程序；迁移完成前请保持原用户注销。", wraplength=650).grid(row=2, sticky="w", pady=(0, 18))
        ttk.Label(body, text="1. 选择要改名的用户").grid(row=3, sticky="w", pady=(0, 6))
        self.selected = tk.StringVar()
        user_row = ttk.Frame(body)
        user_row.grid(row=4, sticky="ew")
        user_row.columnconfigure(0, weight=1)
        self.user_box = ttk.Combobox(user_row, textvariable=self.selected, state="readonly")
        self.user_box.grid(row=0, column=0, sticky="ew")
        self.refresh_button = ttk.Button(user_row, text="刷新", command=self.refresh)
        self.refresh_button.grid(row=0, column=1, padx=(10, 0))
        self.user_box.bind("<<ComboboxSelected>>", self.update_preview)
        ttk.Label(body, text="2. 输入新的文件夹名称").grid(row=5, sticky="w", pady=(18, 6))
        self.name = tk.StringVar()
        self.entry = ttk.Entry(body, textvariable=self.name)
        self.entry.grid(row=6, sticky="ew")
        self.name.trace_add("write", self.update_preview)
        self.preview = tk.StringVar(value="例如：把“亿洋”改成“YiYang”，这里填写 YiYang")
        ttk.Label(body, textvariable=self.preview, style="Hint.TLabel", wraplength=650).grid(row=7, sticky="w", pady=(7, 16))
        actions = ttk.Frame(body)
        actions.grid(row=8, sticky="ew")
        self.start_button = ttk.Button(actions, text="开始改名", style="Primary.TButton", command=self.start, state="disabled")
        self.start_button.pack(side="left")
        self.restore_button = ttk.Button(actions, text="恢复", command=self.show_recovery)
        self.restore_button.pack(side="left", padx=(12, 0))
        self.detail_button = ttk.Button(actions, text="本次详情", command=self.show_details)
        self.detail_button.pack(side="right")
        self.progress = ttk.Progressbar(body, mode="indeterminate")
        self.progress.grid(row=9, sticky="ew", pady=(18, 8))
        self.status = tk.StringVar(value="准备就绪")
        ttk.Label(body, textvariable=self.status, wraplength=650).grid(row=10, sticky="w")
        ttk.Label(body, text="成功后自动删除备份和日志；失败才保留恢复资料。\n旧名称会保留为兼容入口，方便原来的软件继续使用。",
                  style="Hint.TLabel", wraplength=650).grid(row=11, sticky="w", pady=(14, 0))
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()
        self.root.update_idletasks()
        required_height = max(560, self.root.winfo_reqheight() + 10)
        self.root.geometry(f"730x{required_height}")
        self.root.minsize(680, required_height)
        self.root.after(100, self.poll)

    def refresh(self):
        if self.busy:
            return
        try:
            index = self.user_box.current()
            selected_sid = self.profiles[index]["sid"] if 0 <= index < len(self.profiles) else None
            self.profiles = self.service.profiles()
            self.user_box["values"] = [f"{ntpath.basename(p['path'])}    ·    {p['path']}" for p in self.profiles]
            if self.profiles:
                self.user_box.current(next((i for i, p in enumerate(self.profiles) if p["sid"] == selected_sid), 0))
                self.status.set("选择用户，输入新名称，即可开始改名。")
            else:
                self.selected.set("")
                self.status.set("没有找到其他用户。请登录另一个管理员账户后再打开本工具。")
        except Exception as error:
            self.logs.append(str(error))
            self.status.set(friendly_error(error))
        self.update_preview()

    def update_preview(self, *args):
        index = self.user_box.current()
        valid = False
        if 0 <= index < len(self.profiles) and self.name.get().strip():
            try:
                self.preview.set("将改为：" + new_folder_path(self.profiles[index]["path"], self.name.get()))
                valid = True
            except RenProfileError as error:
                self.preview.set(str(error))
        else:
            self.preview.set("例如：把“亿洋”改成“YiYang”，这里填写 YiYang")
        self.start_button["state"] = "normal" if valid and not self.busy else "disabled"

    def start(self):
        index = self.user_box.current()
        if not 0 <= index < len(self.profiles) or self.busy:
            return
        profile, name = self.profiles[index], self.name.get()
        self.run_task(lambda: self.service.migrate(profile, name, lambda text: self.events.put(("progress", text))), "migrate")

    def run_task(self, action, kind):
        self.logs = [f"RenProfile {__version__}｜本次操作"]
        self.busy = True
        self.user_box["state"] = "disabled"
        self.entry["state"] = "disabled"
        for widget in (self.start_button, self.restore_button, self.refresh_button):
            widget["state"] = "disabled"
        if self.manual_window is not None:
            for widget in (self.manual_button, self.manual_open_button, self.manual_close_button):
                widget["state"] = "disabled"
            self.manual_hint.set("正在核对文件夹并重新读取设置，请稍等……")
        self.progress.start(14)
        self.status.set("正在处理，请稍等……")

        def worker():
            try:
                self.events.put((kind, action()))
            except Exception as error:
                self.events.put(("error", error))

        threading.Thread(target=worker, daemon=False).start()

    def poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "detail":
                    self.logs.append(value)
                    if value.startswith(("1/3", "2/3", "3/3")):
                        self.status.set(value)
                    continue
                if kind == "progress":
                    self.status.set(value)
                    self.logs.append(value)
                    continue
                self.busy = False
                self.progress.stop()
                self.user_box["state"] = "readonly"
                self.entry["state"] = "normal"
                for widget in (self.restore_button, self.refresh_button):
                    widget["state"] = "normal"
                self.refresh()
                if kind in ("migrate", "manual_migrate"):
                    if self.manual_window is not None:
                        self.manual_window.destroy()
                        self.manual_window, self.manual_request = None, None
                    self.name.set("")
                    text = f"已迁移到：{value.new}\n"
                    if value.cleaned:
                        text += "本次备份和日志已自动删除。"
                    else:
                        text += "迁移已完成，备份暂未清理。可在“恢复”中重试清理。"
                        self.logs.append(value.cleanup_error + "\n" + value.job)
                    if value.skipped:
                        text += "\n部分设置保留原值，旧路径兼容入口已保留。"
                    text += "\n请重启电脑，再登录原来的用户。"
                    self.status.set("迁移完成，请重启电脑。")
                    messagebox.showinfo("迁移完成", text, parent=self.root)
                elif kind == "restore":
                    self.status.set(value)
                    messagebox.showinfo("处理完成", value, parent=self.root)
                else:
                    self.logs.append(str(value))
                    if isinstance(value, ManualRenameRequired):
                        self.show_manual_rename(value)
                    elif self.manual_window is not None:
                        self.status.set("等待手动改名后继续；详情见提示窗口。")
                        self.manual_hint.set(friendly_error(value))
                        for widget in (self.manual_button, self.manual_open_button, self.manual_close_button):
                            widget["state"] = "normal"
                    else:
                        self.status.set(friendly_error(value))
                        messagebox.showerror("未完成", friendly_error(value), parent=self.root)
                self.update_preview()
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def show_manual_rename(self, request):
        self.manual_request = request
        self.status.set("自动改名被 Windows 阻止，请手动改名后继续。")
        if self.manual_window is not None:
            self.manual_window.lift()
            return
        window = tk.Toplevel(self.root)
        self.manual_window = window
        window.title(f"手动改名后继续 · {__version__}")
        window.geometry("760x350")
        frame = ttk.Frame(window, padding=24)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Windows 阻止了自动改名，请按下面两步继续。", font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w")
        ttk.Label(frame, text="1. 在资源管理器中，将原文件夹重命名为下面的新名称：", wraplength=700).pack(anchor="w", pady=(15, 7))
        for label, path in (("原文件夹", request.old), ("改名后", request.new)):
            row = ttk.Frame(frame)
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=label, width=9).pack(side="left")
            entry = ttk.Entry(row)
            entry.insert(0, path)
            entry["state"] = "readonly"
            entry.pack(side="left", fill="x", expand=True)
        ttk.Label(frame, text="2. 改好后点击“我已改名，继续迁移”。请保持原用户注销。", wraplength=700).pack(anchor="w", pady=(12, 7))
        self.manual_hint = tk.StringVar(value="本次尚未写入账户路径和软件设置。你可以保持此窗口打开，先去改名。")
        ttk.Label(frame, textvariable=self.manual_hint, style="Hint.TLabel", wraplength=700).pack(anchor="w", fill="x")
        actions = ttk.Frame(frame)
        actions.pack(side="bottom", fill="x", pady=(12, 0))

        def open_parent():
            try:
                os.startfile(ntpath.dirname(request.old))
            except OSError as error:
                self.manual_hint.set("无法打开资源管理器，请自行打开原文件夹所在位置。\n" + str(error))

        def continue_manual():
            if not self.busy:
                self.run_task(lambda: self.service.continue_manual(
                    request.job, lambda text: self.events.put(("progress", text))), "manual_migrate")

        def later():
            if not self.busy:
                window.destroy()
                self.manual_window, self.manual_request = None, None
                self.status.set("手动改名后，可选择相同用户和新名称继续迁移。")

        self.manual_open_button = ttk.Button(actions, text="打开所在文件夹", command=open_parent)
        self.manual_open_button.pack(side="left")
        self.manual_button = ttk.Button(actions, text="我已改名，继续迁移", command=continue_manual, style="Primary.TButton")
        self.manual_button.pack(side="right")
        self.manual_close_button = ttk.Button(actions, text="稍后处理", command=later)
        self.manual_close_button.pack(side="right", padx=8)
        window.protocol("WM_DELETE_WINDOW", later)
        window.transient(self.root)
        window.grab_set()
        window.update_idletasks()
        height = max(350, window.winfo_reqheight() + 10)
        window.geometry(f"760x{height}")
        window.minsize(700, height)

    def show_recovery(self):
        if self.busy:
            return
        try:
            self.records = self.service.pending()
        except Exception as error:
            self.logs.append(str(error))
            messagebox.showerror("无法读取恢复资料", friendly_error(error), parent=self.root)
            return
        if not self.records:
            if messagebox.askyesno("没有待恢复的操作", "本工具没有保留的恢复记录。\n要选择旧版程序生成的恢复文件夹吗？", parent=self.root):
                job = filedialog.askdirectory(title="选择旧版恢复文件夹", parent=self.root)
                if job:
                    self.run_task(lambda: self.service.restore(job), "restore")
            return
        window = tk.Toplevel(self.root)
        window.title("恢复")
        window.geometry("720x260")
        frame = ttk.Frame(window, padding=22)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="选择需要恢复或清理的记录：").pack(anchor="w")
        items = [f"{Path(r['job']).name}  [{r['state']}]" for r in self.records]
        box = ttk.Combobox(frame, values=items, state="readonly", width=65)
        box.pack(fill="x", pady=14)
        box.current(0)
        ttk.Label(frame, text="恢复该次记录中的改动；旧版手动改名记录仍保留其手动改名。", style="Hint.TLabel").pack(anchor="w", pady=(0, 12))

        def restore():
            job = self.records[box.current()]["job"]
            window.destroy()
            self.run_task(lambda: self.service.restore(job), "restore")

        def old_details():
            record = self.records[box.current()]
            content = f"历史恢复记录：{record['job']}\n状态：{record['state']}\n" + record.get("diagnostic", record.get("error", "无错误详情"))
            self.show_details(content)

        ttk.Button(frame, text="查看选中记录", command=old_details).pack(side="left")
        ttk.Button(frame, text="恢复选中操作", command=restore).pack(side="right")
        window.transient(self.root)
        window.grab_set()

    def show_details(self, content=None):
        previous_grab = self.root.grab_current()
        window = tk.Toplevel(self.root)
        window.title("历史恢复详情" if content is not None else "本次操作详情")
        window.geometry("840x430")
        content = content if content is not None else ("\n\n".join(self.logs) or "尚未开始本次操作。历史记录请点击“恢复”查看。")
        actions = ttk.Frame(window, padding=8)
        actions.pack(side="bottom", fill="x")

        def copy_details():
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            copy_button["text"] = "已复制"

        copy_button = ttk.Button(actions, text="复制详情", command=copy_details)
        copy_button.pack(side="right")
        text = tk.Text(window, wrap="word", padx=14, pady=14)
        text.pack(fill="both", expand=True)
        text.insert("1.0", content)
        text["state"] = "disabled"
        window.transient(self.root)
        if previous_grab is not None:
            window.grab_set()

        def close_details():
            window.destroy()
            if previous_grab is not None and previous_grab.winfo_exists():
                previous_grab.grab_set()

        window.protocol("WM_DELETE_WINDOW", close_details)

    def close(self):
        if self.busy:
            messagebox.showinfo("请稍等", "正在处理，请等待完成后再关闭。", parent=self.root)
        else:
            self.root.destroy()


def elevate(native):
    if native.elevated():
        return False
    shell = ctypes.WinDLL("shell32", use_last_error=True).ShellExecuteW
    shell.argtypes = [w.HWND, w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, ctypes.c_int]
    shell.restype = ctypes.c_void_p
    frozen = getattr(sys, "frozen", False)
    arguments = "" if frozen else subprocess.list2cmdline(["-B", "-m", "renprofile"])
    working = str(Path(sys.executable).parent if frozen else Path(__file__).resolve().parent.parent)
    previous_reset = os.environ.get("PYINSTALLER_RESET_ENVIRONMENT")
    if frozen:
        os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    try:
        result = shell(None, "runas", sys.executable, arguments, working, 1)
    finally:
        if frozen:
            if previous_reset is None:
                os.environ.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
            else:
                os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = previous_reset
    if not result or result <= 32:
        raise RenProfileError("需要管理员权限。请重新打开工具，并在 Windows 提示中点击“是”。")
    return True


def self_check():
    """Packaging smoke check: hidden window and read-only native calls only."""
    root = tk.Tk()
    root.withdraw()
    try:
        if not root.tk.call("info", "patchlevel") or not Native().current_sid().startswith("S-1-"):
            raise RenProfileError("运行环境检查未通过。")
        root.update_idletasks()
    finally:
        root.destroy()
    return 0


def main(portable=False):
    root = tk.Tk()
    root.withdraw()
    try:
        native = Native()
        if elevate(native):
            root.destroy()
            return 0
        if getattr(sys, "frozen", False):
            from .bootstrap import launch_external, validate_runtime
            if not portable:
                launch_external(native)
                root.destroy()
                return 0
            validate_runtime(native)
        # Neither the UI nor its worker holds a cwd inside a target profile.
        os.chdir(os.environ["SystemRoot"])
        registry = Registry(native)
        engine = Engine(Host(native, registry), registry, emit=lambda text: None)
        app = App(root, SimpleService(engine))
        engine.emit = lambda text: app.events.put(("detail", str(text)))
        root.deiconify()
        root.mainloop()
        return 0
    except Exception as error:
        messagebox.showerror("无法打开工具", friendly_error(error), parent=root)
        root.destroy()
        return 1
