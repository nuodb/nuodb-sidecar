import http
import os
from pathlib import Path
from typing import Any
from werkzeug.security import safe_join
from handler_common import HttpError, UserError


CORES_DIR = os.environ.get("NUODB_CORES_DIR", "/mnt/log")


def cores_handlers() -> list[tuple[str, str, callable]]:
    "Get /cores handlers"
    return [
        ("GET", "cores", [list_cores, get_core]),
        ("DELETE", "cores", [delete_core]),
    ]


def list_cores(query: dict[str:Any]) -> list[str]:
    "List available cores"
    try:
        after = int(query.get("after", -1))
    except ValueError as e:
        raise UserError(
            f"Query parameter after must be an integer, got {query.get("after")}"
        ) from e

    if not os.path.isdir(CORES_DIR):
        return []
    cores = []
    for core in Path(CORES_DIR).glob("crash*/core*"):
        if after >= 0 and after >= core.stat().st_mtime:
            continue
        cores.append(str(core.relative_to(CORES_DIR)))
    return cores


def get_core(file_dir: str, file_name: str) -> Path:
    "Get a core"
    if not (
        file_dir
        and file_dir.startswith("crash")
        and file_name
        and file_name.startswith("core")
    ):
        raise UserError("Invalid core")
    path = safe_join(CORES_DIR, file_dir, file_name)
    if path and os.path.isfile(path):
        return Path(path)
    raise HttpError(http.HTTPStatus.NOT_FOUND, "File not found")


def delete_core(file_dir: str, file_name: str) -> None:
    "Delete a core"
    core = get_core(file_dir, file_name)
    core.unlink()
