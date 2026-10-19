"""Pure path validation/replacement; safe to test without Windows access."""

import ntpath
import re
from urllib.parse import quote

from .errors import RenProfileError

_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.I)


def normalize(path: str) -> str:
    if not isinstance(path, str) or not re.match(r"^[A-Za-z]:[\\/]", path):
        raise RenProfileError("必须使用本地磁盘的绝对路径，例如 C:\\Users\\Old。")
    if any(ord(c) < 32 or c in '<>"|?*' for c in path) or ":" in path[2:]:
        raise RenProfileError("路径包含非法字符、设备路径或备用数据流。")
    parts = path.replace("/", "\\").split("\\")[1:]
    for part in parts:
        if part in (".", "..") or (part and (part.endswith((" ", ".")) or _RESERVED.match(part))):
            raise RenProfileError("路径不能包含 .、..、保留设备名、末尾空格或点。")
    return ntpath.normpath(path)


def validate_pair(old: str, new: str) -> tuple[str, str]:
    old, new = normalize(old), normalize(new)
    if old.casefold() == new.casefold():
        raise RenProfileError("新旧路径相同；不支持仅修改大小写。")
    if ntpath.dirname(old).casefold() != ntpath.dirname(new).casefold():
        raise RenProfileError("只允许在同一父目录中改名，不允许跨目录或跨磁盘迁移。")
    if not ntpath.basename(old) or not ntpath.basename(new):
        raise RenProfileError("不能重命名磁盘根目录。")
    if len(ntpath.basename(new)) > 255:
        raise RenProfileError("文件夹名称过长，不能超过 255 个字符。")
    return old, new


def within(path: str, parent: str) -> bool:
    try:
        return ntpath.commonpath([ntpath.abspath(path), parent]).casefold() == parent.casefold()
    except ValueError:
        return False


class PathRewriter:
    """Literal substitutions with path boundaries, never regex replacement syntax."""

    def __init__(self, old: str, new: str, short_old: str = ""):
        mappings = {}
        for source in {old, short_old} - {""}:
            for before, after in ((source, new), (source.replace("\\", "/"), new.replace("\\", "/")),
                                  (source.replace("\\", "\\\\"), new.replace("\\", "\\\\")),
                                  ("\\\\?\\" + source, "\\\\?\\" + new),
                                  ("\\??\\" + source, "\\??\\" + new),
                                  (quote(source, safe=""), quote(new, safe="")),
                                  (source.replace("\\", "%5C"), new.replace("\\", "%5C")),
                                  ("file:///" + quote(source.replace("\\", "/"), safe="/:"),
                                   "file:///" + quote(new.replace("\\", "/"), safe="/:"))):
                mappings[before.casefold()] = after
        self.mappings = mappings
        alternatives = "|".join(re.escape(s) for s in sorted(mappings, key=len, reverse=True))
        self.pattern = re.compile(
            r"(?<![\w/\\:%])(?:" + alternatives + r")(?=$|[\\/\"';,\)\]\}\x00]|%5c|%2f)", re.I)

    def __call__(self, text: str) -> str:
        return self.pattern.sub(lambda m: self.mappings.get(m.group().casefold(), m.group()), text)

    def data(self, data, kind: int):
        if kind in (1, 2) and isinstance(data, str):  # REG_SZ / REG_EXPAND_SZ
            return self(data)
        if kind == 7 and isinstance(data, list):  # REG_MULTI_SZ
            return [self(item) for item in data]
        return data
