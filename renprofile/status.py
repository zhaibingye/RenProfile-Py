"""Present saved plan diagnostics separately from command execution failures."""

from collections import Counter
import json

from .journal import Journal


def gap_summary(gaps):
    roots = Counter(gap["root"] for gap in gaps)
    machine = roots["SOFTWARE"] + roots["SYSTEM"]
    user = roots["USER"] + roots["CLASSES"]
    return {"total": len(gaps), "machine": machine, "user": user,
            "other": len(gaps) - machine - user, "by_root": dict(sorted(roots.items()))}


def collect_status(job, plan):
    saved = Journal.read_status(job)
    gaps = saved.get("preserved", []) if plan.get("format") == 4 else plan["gaps"]
    return {"sid": plan["sid"], "old": plan["old"], "new": plan["new"],
            **saved, "keep_junction": plan["keep_junction"],
            "manual_rename": plan.get("manual_rename", False), "simple": plan.get("simple", False),
            "registry_actions": saved.get("written_values", 0) if plan.get("format") == 4 else len(plan["actions"]),
            "scan_gaps": gaps, "scan_gap_summary": gap_summary(gaps)}


def failure_details(report):
    lines = []
    for key, label in (("failure_context", "失败步骤"), ("last_error", "上次执行错误"),
                       ("recovery_error", "上次恢复错误")):
        if report.get(key):
            lines.append(f"{label}：{report[key]}")
    if not report.get("failure_context") and report.get("last_recorded_action"):
        last = report["last_recorded_action"]
        lines.append(f"旧版日志最后记录的操作（定位线索）：第 {last['sequence']} 项，{last['description']}")
        lines.append("旧版未记录具体失败步骤；以上操作可能失败，也可能在其后的加载、卸载或校验时失败。")
    return "\n".join(lines)


def format_status(report, show_gaps=False, as_json=False):
    if as_json:
        return json.dumps(report, ensure_ascii=False, indent=2)
    state = report["status"]
    descriptions = {"planned": "仅生成记录，尚未执行改名", "scanning": "扫描中或扫描被中断", "applying": "执行中或曾被中断",
                    "completed": "执行日志显示已完成", "rolling_back": "恢复中或恢复曾被中断",
                    "rolled_back": "执行日志显示已回滚", "recovery_required": "需要继续恢复",
                    "unknown": "无法从日志确定状态"}
    if report.get("manual_rename"):
        descriptions["planned"] = "仅生成计划，尚未迁移设置"
        descriptions["rolled_back"] = "已恢复工具修改的设置，手动改名保留"
    summary = report["scan_gap_summary"]
    lines = [f"状态：{state}（{descriptions.get(state, '无法识别的日志状态')}）",
             f"目标 SID：{report['sid']}", f"原目录：{report['old']}", f"新目录：{report['new']}",
             f"注册表动作：{report['registry_actions']} 项",
             "旧路径兼容链接：" + ("保留" if report["keep_junction"] else "不保留"),
             f"扫描缺口：{summary['total']} 项（机器注册表 {summary['machine']}，用户 hive {summary['user']}，其他 {summary['other']}）"]
    if summary["total"]:
        lines.append("扫描缺口是当时未能读取或保留原值的位置记录，不表示本次 status 命令执行失败。")
    if state in ("scanning", "applying", "rolling_back", "recovery_required"):
        lines.append("如果原操作进程已停止，请保持目标用户注销，点击“恢复”处理此记录。")
    elif state in ("planned", "rolled_back"):
        lines.append("此记录仅用于查看或恢复。再次点击“开始改名”会重新扫描并建立新任务。")
    elif state == "completed":
        lines.append("工具已完成改名校验；常用应用仍需登录后检查。")
    details = failure_details(report)
    if details:
        lines.append(details)
    gaps = report["scan_gaps"] if show_gaps else report["scan_gaps"][:3]
    if gaps:
        lines.append("扫描缺口详情：" if show_gaps else "扫描缺口示例（最多 3 项，完整列表使用 --show-gaps）：")
        lines.extend(f"  {gap['root']}\\{gap['key']}：{gap['error']}" for gap in gaps)
    return "\n".join(lines)
