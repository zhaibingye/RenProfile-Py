class RenProfileError(Exception):
    """A condition that must stop the operation."""


class ConflictError(RenProfileError):
    """State changed since planning; never overwrite it automatically."""


class ManualRenameRequired(RenProfileError):
    """Automatic rename was rolled back; no worker or hive stays open waiting."""

    def __init__(self, sid, old, new, job):
        self.sid, self.old, self.new, self.job = sid, str(old), str(new), str(job)
        super().__init__(
            "自动改名未完成，已回滚。本次尚未写入账户路径和软件设置。\n"
            f"请在资源管理器中手动改名：\n{old}\n改为：{new}\n"
            "改好后点击“我已改名，继续迁移”。请保持原用户注销。\n"
            f"记录：{job}")


class OperationError(RenProfileError):
    """Keep the failing operation and location alongside the Windows error."""

    def __init__(self, operation, target, error):
        self.operation, self.target = operation, target
        self.winerror = getattr(error, "winerror", None)
        super().__init__(f"{operation}失败\n位置：{target}\n原因：{error}")


class DirectoryRenameError(RenProfileError):
    """A directory rename failure with usable diagnostics instead of a bare code."""

    def __init__(self, old, new, code, users=(), diagnostic=""):
        self.old, self.new, self.winerror = str(old), str(new), code
        self.users, self.diagnostic = list(users), diagnostic
        if code in (32, 33):
            reason = "文件夹被程序占用，管理员权限也无法解除这个占用。"
        elif code == 5:
            reason = "Windows 拒绝文件夹改名，可能仍有占用或目录权限限制。"
        elif code in (80, 183):
            reason = "新的文件夹名称已被占用，请换一个名称。"
        else:
            reason = f"文件夹改名失败，Windows 错误代码：{code}。"
        lines = [reason, f"原文件夹：{old}", f"新文件夹：{new}"]
        if users:
            lines.append("检测到相关文件的占用者：" + "、".join(
                f"{p['name'] or '未知程序'}（PID {p['pid']}）" for p in users))
        if code in (5, 32, 33):
            lines.append("请重启电脑，只登录维护管理员，不要先登录目标用户，然后直接打开工具重试。")
            lines.append("若仍失败，查看详情中的 Windows 错误代码及占用信息。")
        lines.append(f"诊断：WinError {code}；" + (diagnostic or "未确定具体占用者，其他文件或系统服务仍可能占用目录。"))
        super().__init__("\n".join(lines))
