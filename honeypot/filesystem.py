from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Dict, List, Optional

from .utils import load_json


class FilesystemError(Exception):
    pass


class NodeNotFound(FilesystemError):
    pass


class Node:
    def __init__(self, name: str, spec: Dict, parent: Optional["Node"] = None):
        self.name = name
        self.parent = parent
        self.type = spec.get("type", "file")
        if self.type not in {"file", "directory"}:
            raise ValueError(f"Unsupported node type '{self.type}' for {name}")
        self.mode = spec.get("mode", "0755" if self.is_dir else "0644")
        self.owner = spec.get("owner", "root")
        self.group = spec.get("group", "root")
        self.modified = parse_timestamp(spec.get("modified"))
        if self.is_dir:
            children_spec = spec.get("children", {})
            if not isinstance(children_spec, dict):
                raise ValueError(f"Directory '{name}' children must be a dict")
            self.children: Dict[str, Node] = {
                child_name: Node(child_name, child_spec, parent=self)
                for child_name, child_spec in children_spec.items()
            }
        else:
            content = spec.get("content", "")
            if not isinstance(content, str):
                raise ValueError(f"File '{name}' content must be string")
            self.content = content
            self.size_override = spec.get("size")

    @property
    def is_dir(self) -> bool:
        return self.type == "directory"

    @property
    def size(self) -> int:
        if self.is_dir:
            return sum(child.size for child in self.children.values())
        if self.size_override is not None:
            return int(self.size_override)
        return len(self.content.encode("utf-8"))

    def child(self, name: str) -> "Node":
        if not self.is_dir:
            raise FilesystemError(f"{self.name} is not a directory")
        try:
            return self.children[name]
        except KeyError as exc:
            raise NodeNotFound(name) from exc

    def get_path(self) -> str:
        parts = []
        current: Optional[Node] = self
        while current and current.name:
            parts.append(current.name)
            current = current.parent
        return "/" + "/".join(reversed(parts))


class FakeFilesystem:
    """Minimal virtual filesystem shared by multiple honeypot services."""

    def __init__(self, config_path: Path):
        data = load_json(config_path)
        root_spec = data.get("root")
        if not root_spec:
            raise ValueError("filesystem.json must contain a 'root' node")
        self.root = Node("", root_spec, parent=None)

    def resolve(self, path: str, cwd: str = "/") -> Node:
        normalized = self.normalize(path, cwd=cwd)
        if normalized == "/":
            return self.root
        parts = [part for part in normalized.strip("/").split("/") if part]
        current = self.root
        for part in parts:
            current = current.child(part)
        return current

    def normalize(self, path: str, cwd: str = "/") -> str:
        if not path:
            path = "."
        if path.startswith("/"):
            base_parts: List[str] = []
        else:
            base_parts = [part for part in cwd.strip("/").split("/") if part]
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if base_parts:
                    base_parts.pop()
                continue
            base_parts.append(part)
        return "/" + "/".join(base_parts)

    def list_directory(self, path: str, cwd: str = "/", include_hidden: bool = False) -> List[Node]:
        node = self.resolve(path, cwd=cwd)
        if not node.is_dir:
            raise FilesystemError(f"{node.get_path()} is not a directory")
        entries = []
        for name, child in sorted(node.children.items()):
            if not include_hidden and name.startswith("."):
                continue
            entries.append(child)
        return entries

    def format_ls(self, path: str, cwd: str, detailed: bool, include_hidden: bool) -> str:
        target = self.resolve(path, cwd=cwd)
        if target.is_dir:
            nodes = self.list_directory(path, cwd=cwd, include_hidden=include_hidden)
            lines: List[str] = []
            if detailed:
                lines.append("total {}".format(sum(max(1, node.size // 1024) for node in nodes)))
            if include_hidden:
                lines.append(self.describe_special(target, detailed, "."))
                parent = target.parent if target.parent else target
                lines.append(self.describe_special(parent, detailed, ".."))
            for node in nodes:
                lines.append(self.describe_node(node, detailed))
            return "\n".join(lines)
        return self.describe_node(target, detailed)

    def describe_node(self, node: Node, detailed: bool) -> str:
        if not detailed:
            return node.name or "/"
        type_char = "d" if node.is_dir else "-"
        mode_text = to_unix_mode(type_char, node.mode)
        owner = node.owner
        group = node.group
        size = node.size
        when = format_ls_time(node.modified)
        name = node.name or "/"
        return f"{mode_text} 1 {owner} {group} {size:>6} {when} {name}"

    def describe_special(self, node: Node, detailed: bool, name: str) -> str:
        if not detailed:
            return name
        type_char = "d"
        mode_text = to_unix_mode(type_char, node.mode)
        owner = node.owner
        group = node.group
        size = node.size
        when = format_ls_time(node.modified)
        return f"{mode_text} 1 {owner} {group} {size:>6} {when} {name}"

    def read_file(self, path: str, cwd: str = "/") -> str:
        node = self.resolve(path, cwd=cwd)
        if node.is_dir:
            raise FilesystemError(f"{node.get_path()} is a directory")
        return node.content

    def format_ftp_list(self, path: str, cwd: str) -> List[str]:
        target = self.resolve(path, cwd=cwd)
        lines: List[str] = []
        if target.is_dir:
            nodes = self.list_directory(path, cwd=cwd, include_hidden=False)
        else:
            nodes = [target]
        for node in nodes:
            type_char = "d" if node.is_dir else "-"
            mode_text = to_unix_mode(type_char, node.mode)
            size = node.size
            when = format_ls_time(node.modified)
            lines.append(f"{mode_text} 1 {node.owner:<8} {node.group:<8} {size:>8} {when} {node.name}")
        return lines


def parse_timestamp(value: Optional[str]) -> dt.datetime:
    if not value:
        return dt.datetime.utcnow()
    try:
        # Accept both date-only and full ISO strings
        if len(value) == 10:
            return dt.datetime.fromisoformat(value)
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return dt.datetime.utcnow()


def to_unix_mode(prefix: str, mode: str) -> str:
    mode = mode[-3:].rjust(3, "7")
    perms = ""
    table = {"0": "---", "1": "--x", "2": "-w-", "3": "-wx", "4": "r--", "5": "r-x", "6": "rw-", "7": "rwx"}
    for digit in mode:
        perms += table.get(digit, "rwx")
    return prefix + perms


def format_ls_time(value: dt.datetime) -> str:
    month = value.strftime("%b")
    day = value.day
    time_part = value.strftime("%H:%M")
    return f"{month} {day:>2} {time_part}"
