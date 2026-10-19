"""Optional CLI. Normal users open the two-field GUI."""
import argparse
import json
import sqlite3
import sys

from . import __version__
from .engine import Engine
from .errors import RenProfileError
from .host import Host
from .native import Native
from .registry import Registry
from .simple import SimpleService
from .status import collect_status, format_status


def parser():
    result = argparse.ArgumentParser(prog="renprofile", description="用户文件夹自动改名")
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="只读列出用户")
    inspect.add_argument("--all", action="store_true")
    rename = commands.add_parser("rename", help="重新扫描、自动改名并更新设置")
    rename.add_argument("--sid", required=True)
    rename.add_argument("--name", required=True)
    for name in ("recover", "rollback", "status", "continue"):
        command = commands.add_parser(name, help="恢复或查看已有记录")
        command.add_argument("--work-dir", required=True)
        if name == "status":
            command.add_argument("--show-gaps", action="store_true")
            command.add_argument("--json", action="store_true")
    return result


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv == ["--gui"]:
        from .gui import main as gui_main
        return gui_main()
    if argv == ["--portable"]:
        from .gui import main as gui_main
        return gui_main(portable=True)
    if argv in (["--self-check"], ["--portable-check"]):
        try:
            if argv == ["--portable-check"]:
                from .bootstrap import validate_runtime
                validate_runtime(Native())
            from .gui import self_check
            return self_check()
        except Exception:
            return 1
    if argv == ["--launch-check"] and getattr(sys, "frozen", False):
        from .bootstrap import launch_external
        launch_external(Native(), smoke=True)
        return 0
    args = parser().parse_args(argv)
    try:
        native = Native()
        registry = Registry(native)
        host = Host(native, registry)
        engine = Engine(host, registry)
        service = SimpleService(engine)
        if args.command != "inspect" and not native.elevated():
            raise RenProfileError("请以管理员身份运行。")
        if args.command == "inspect":
            sid = native.current_sid()
            entries = registry.profiles()
            if not args.all:
                entries = [p for p in entries if p["sid"] == sid]
            print(json.dumps({"current_sid": sid, "profiles": entries}, ensure_ascii=False, indent=2))
        elif args.command == "rename":
            profile = next((p for p in registry.profiles() if p["sid"] == args.sid), None)
            if profile is None:
                raise RenProfileError("找不到此用户。")
            result = service.migrate(profile, args.name, print)
            print("已完成：" + result.new)
            if not result.cleaned:
                print("备份尚未清理：" + result.job + "\n" + result.cleanup_error)
        elif args.command in ("recover", "rollback"):
            print(service.restore(args.work_dir))
        elif args.command == "continue":
            result = service.continue_manual(args.work_dir, print)
            print("已完成：" + result.new)
            if not result.cleaned:
                print("备份尚未清理：" + result.job + "\n" + result.cleanup_error)
        elif args.command == "status":
            job, plan = engine.load(args.work_dir)
            print(format_status(collect_status(job, plan), show_gaps=args.show_gaps, as_json=args.json))
        return 0
    except KeyboardInterrupt:
        print("操作被中断；请保持目标用户注销，使用恢复功能。", file=sys.stderr)
        return 130
    except (RenProfileError, OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 1
