"""Fresh, bounded value scan. Never enumerate the machine registry wholesale."""

from .model import Action, snapshot

MACHINE_SCOPES = (
    ("SYSTEM", r"Control\Session Manager\Environment", False),
    ("SOFTWARE", r"Microsoft\Windows\CurrentVersion\App Paths", True),
    ("SOFTWARE", r"Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths", True),
)
USER_MANAGED = (
    r"Software\Microsoft\Windows\CurrentVersion\AppModel",
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel",
    r"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel",
    r"ActivatableClasses",
)


def managed_user_key(path):
    path = path.casefold()
    return any(path == branch.casefold() or path.startswith(branch.casefold() + "\\")
               for branch in USER_MANAGED)


def scan(registry, rewrite, hive_files):
    actions, preserved = [], []
    scopes = [(root, "", True) for root in hive_files] + list(MACHINE_SCOPES)
    for root, base, recursive in scopes:
        stack = [base]
        while stack:
            path = stack.pop()
            if root in hive_files and managed_user_key(path):
                preserved.append({"root": root, "key": path, "error": "系统维护的数据保留原值"})
                continue
            try:
                with registry.open(root, path) as handle:
                    subcount, count, _ = registry.w.QueryInfoKey(handle)
                    values = [registry.w.EnumValue(handle, i) for i in range(count)]
                    children = [registry.w.EnumKey(handle, i) for i in range(subcount)] if recursive else []
                if any(kind == 6 for _, _, kind in values):
                    preserved.append({"root": root, "key": path, "error": "注册表链接保留原值"})
                    continue
                # Names can be internal indexes; retain them and use the junction.
                for name, data, kind in values:
                    updated = rewrite.data(data, kind)
                    if updated != data:
                        actions.append(Action("value", root, path, name,
                                              snapshot((kind, data)), snapshot((kind, updated))))
                stack.extend(path + "\\" + name if path else name for name in children)
            except FileNotFoundError:
                continue
            except OSError as error:
                preserved.append({"root": root, "key": path, "error": str(error)})
    return actions, preserved
