import base64
from dataclasses import asdict, dataclass


def pack(value):
    if isinstance(value, bytes):
        return {"bytes": base64.b64encode(value).decode("ascii")}
    return value


def unpack(value):
    if isinstance(value, dict) and set(value) == {"bytes"}:
        return base64.b64decode(value["bytes"], validate=True)
    return value


def snapshot(value):
    """None means value missing; (type, data) includes empty/default values."""
    return None if value is None else {"kind": value[0], "data": pack(value[1])}


def registry_path(root, key, system_path=r"SYSTEM\CurrentControlSet"):
    prefix = {"SOFTWARE": r"HKLM\SOFTWARE", "SYSTEM": "HKLM\\" + system_path,
              "USER": "离线 NTUSER.DAT", "CLASSES": "离线 UsrClass.dat"}.get(root, root)
    return prefix + ("\\" + key if key else "")


def describe_action(action, system_path=r"SYSTEM\CurrentControlSet"):
    """A diagnostic locator only: never include saved registry value contents."""
    if action.kind == "value":
        verb = "删除注册表值" if action.after is None else "写入注册表值"
        return f"{verb}：{registry_path(action.root, action.key, system_path)} [值：{action.name or '(默认)'}]"
    if action.kind == "key":
        return f"注册表子项改名：{registry_path(action.root, action.key, system_path)}\\{action.before} → {action.after}"
    if action.kind == "junction":
        return f"建立旧路径兼容入口：{action.name} → {action.after}"
    if action.kind == "directory":
        return f"文件夹改名：{action.before} → {action.after}"
    return f"未知操作：{action.kind}"


@dataclass(frozen=True)
class Action:
    kind: str
    root: str = ""
    key: str = ""
    name: str = ""
    before: object = None
    after: object = None

    def json(self):
        return asdict(self)

    @classmethod
    def from_json(cls, value):
        return cls(**value)
