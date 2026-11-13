#!/usr/bin/env python3
"""PreToolUse hook that enforces the project permissions.

Reads docs/agents/antigravity-permissions.json and enforces allow/ask/deny
rules (with priority Deny > Ask > Allow) across Antigravity sessions on any PC.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

RULE_PATTERN = re.compile(r"^([a-z_]+)\((.*)\)$", re.DOTALL)
SHELL_SPLIT_PATTERN = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")


def get_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def load_permissions(repo_root: Path) -> dict[str, list[tuple[str, str, str]]]:
    perm_file = repo_root / "docs" / "agents" / "antigravity-permissions.json"
    if not perm_file.is_file():
        return {"allow": [], "ask": [], "deny": []}

    data = json.loads(perm_file.read_text(encoding="utf-8"))
    raw_perms = data.get("permissions", {})
    parsed: dict[str, list[tuple[str, str, str]]] = {"allow": [], "ask": [], "deny": []}

    for bucket in ("deny", "ask", "allow"):
        for entry in raw_perms.get(bucket, []):
            if not isinstance(entry, str):
                continue
            match = RULE_PATTERN.match(entry.strip())
            if match:
                action, target = match.group(1), match.group(2).strip()
                parsed[bucket].append((action, target, entry.strip()))
    return parsed


def match_command_target(target: str, cmd: str) -> bool:
    cmd_stripped = cmd.strip()
    if not cmd_stripped:
        return False
    if target == "*":
        return True
    if target.startswith("regex:"):
        pattern = target[len("regex:") :]
        return re.search(pattern, cmd_stripped) is not None
    return cmd_stripped == target or cmd_stripped.startswith(target + " ")


def normalize_rel_path(raw_path: str, cwd: Path, repo_root: Path) -> tuple[str, Path]:
    p = Path(raw_path)
    if not p.is_absolute():
        p = (cwd / p).resolve()
    else:
        p = p.resolve()
    try:
        rel = p.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        rel = p.as_posix()
    return rel, p


def match_file_target(target: str, rel_path: str) -> bool:
    if target == "*":
        return True
    if target.startswith("regex:"):
        pattern = target[len("regex:") :]
        return re.search(pattern, rel_path) is not None
    # Remove only a leading "./" prefix. str.lstrip("./") would also strip the
    # leading dot of names such as ".env" or ".agents/".
    norm_target = target[2:] if target.startswith("./") else target
    if norm_target.endswith("/"):
        prefix = norm_target.rstrip("/")
        return rel_path == prefix or rel_path.startswith(norm_target)
    if "/" not in norm_target and Path(rel_path).name == norm_target:
        return True
    return rel_path == norm_target


def match_url_target(target: str, url_or_domain: str) -> bool:
    if target == "*":
        return True
    if target.startswith("regex:"):
        return re.search(target[len("regex:") :], url_or_domain) is not None
    return target.lower() in url_or_domain.lower()


def evaluate_command(
    cmd: str, perms: dict[str, list[tuple[str, str, str]]]
) -> dict[str, Any]:
    subcommands = [s.strip() for s in SHELL_SPLIT_PATTERN.split(cmd) if s.strip()]
    candidates = [cmd.strip(), *subcommands] if subcommands else [cmd.strip()]

    for action, target, raw_rule in perms["deny"]:
        if action == "command" and any(match_command_target(target, c) for c in candidates):
            return {
                "decision": "deny",
                "reason": f"Command blocked by project policy: {raw_rule}",
            }

    for action, target, raw_rule in perms["ask"]:
        if action == "command" and any(match_command_target(target, c) for c in candidates):
            return {
                "decision": "ask",
                "reason": f"Command requires confirmation per project policy: {raw_rule}",
            }

    check_units = subcommands if subcommands else [cmd.strip()]
    if check_units and all(
        any(
            action == "command" and match_command_target(target, unit)
            for action, target, _ in perms["allow"]
        )
        for unit in check_units
    ):
        return {"decision": "allow"}

    return {
        "decision": "ask",
        "reason": "Command is not in the project allowlist (docs/agents/antigravity-permissions.json).",
    }


def evaluate_file(
    raw_path: str,
    allowed_actions: tuple[str, ...],
    cwd: Path,
    repo_root: Path,
    artifact_dir: str,
    perms: dict[str, list[tuple[str, str, str]]],
) -> dict[str, Any]:
    if not raw_path:
        return {
            "decision": "ask",
            "reason": "Could not determine the file path of this tool call.",
        }

    rel_path, abs_path = normalize_rel_path(raw_path, cwd, repo_root)

    for action, target, raw_rule in perms["deny"]:
        if action in allowed_actions and match_file_target(target, rel_path):
            return {
                "decision": "deny",
                "reason": f"File access blocked by project policy: {raw_rule}",
            }

    for action, target, raw_rule in perms["ask"]:
        if action in allowed_actions and match_file_target(target, rel_path):
            return {
                "decision": "ask",
                "reason": f"File modification requires confirmation per project policy: {raw_rule}",
            }

    for action, target, _ in perms["allow"]:
        if action in allowed_actions and match_file_target(target, rel_path):
            return {"decision": "allow"}

    # Allow files inside workspace or conversation artifact directory unless denied/asked above
    try:
        abs_path.relative_to(repo_root.resolve())
        return {"decision": "allow"}
    except ValueError:
        pass

    if artifact_dir:
        try:
            abs_path.relative_to(Path(artifact_dir).resolve())
            return {"decision": "allow"}
        except ValueError:
            pass

    return {
        "decision": "ask",
        "reason": f"File '{raw_path}' is outside the project workspace.",
    }


def evaluate_url(
    target_val: str,
    action_name: str,
    perms: dict[str, list[tuple[str, str, str]]],
) -> dict[str, Any]:
    for action, target, raw_rule in perms["deny"]:
        if action == action_name and match_url_target(target, target_val):
            return {
                "decision": "deny",
                "reason": f"URL access blocked by project policy: {raw_rule}",
            }

    for action, target, raw_rule in perms["ask"]:
        if action == action_name and match_url_target(target, target_val):
            return {
                "decision": "ask",
                "reason": f"URL access requires confirmation per project policy: {raw_rule}",
            }

    for action, target, _ in perms["allow"]:
        if action == action_name and match_url_target(target, target_val):
            return {"decision": "allow"}

    return {"decision": "ask", "reason": "External URL access requires confirmation."}


def main() -> int:
    repo_root = get_repo_root()

    raw_input = sys.stdin.read().strip()
    if not raw_input:
        print(json.dumps({"decision": "deny", "reason": "Permission hook received no input."}))
        return 0

    try:
        payload = json.loads(raw_input)
    except json.JSONDecodeError:
        print(json.dumps({"decision": "deny", "reason": "Permission hook received invalid input."}))
        return 0

    perms = load_permissions(repo_root)
    tool_call = payload.get("toolCall", {}) or {}
    tool_name = tool_call.get("name", "")
    args = tool_call.get("args", {}) or {}
    cwd = Path(payload.get("cwd") or os.getcwd())
    artifact_dir = payload.get("artifactDirectoryPath") or ""

    if tool_name == "run_command":
        cmd = (
            args.get("CommandLine")
            or args.get("commandLine")
            or args.get("command")
            or ""
        )
        result = evaluate_command(str(cmd), perms)
    elif tool_name in (
        "write_file",
        "edit_file",
        "replace_file_content",
        "multi_replace_file_content",
    ):
        raw_path = (
            args.get("Path") or args.get("path") or args.get("TargetFile") or ""
        )
        result = evaluate_file(
            str(raw_path),
            ("write_file", "edit_file"),
            cwd,
            repo_root,
            artifact_dir,
            perms,
        )
    elif tool_name in (
        "read_file",
        "view_file",
        "view_file_outline",
        "view_code_item",
    ):
        raw_path = (
            args.get("Path")
            or args.get("path")
            or args.get("AbsolutePath")
            or args.get("File")
            or ""
        )
        result = evaluate_file(
            str(raw_path), ("read_file",), cwd, repo_root, artifact_dir, perms
        )
    elif tool_name in ("search_web", "read_url_content"):
        target_val = str(
            args.get("Url")
            or args.get("url")
            or args.get("domain")
            or args.get("query")
            or "*"
        )
        result = evaluate_url(target_val, "read_url", perms)
    elif tool_name.startswith("browser_"):
        target_val = str(args.get("Url") or args.get("url") or "*")
        result = evaluate_url(target_val, "execute_url", perms)
    else:
        result = {
            "decision": "ask",
            "reason": f"Tool '{tool_name}' is not covered by the project policy.",
        }

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
