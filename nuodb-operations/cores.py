import hashlib
import http
from operator import itemgetter
import os
from pathlib import Path
import re
from typing import Any
from werkzeug.security import safe_join
from handler_common import HttpError, UserError


NUODB_LOGDIR = os.environ.get("NUODB_LOGDIR", "/mnt/log")
CORE_FILE_PREFIX = "core.nuodb"
CORES_DIR = "crash"
CORE_BACKUP_DIR_PREFIX = CORES_DIR + "-"


def cores_handlers() -> list[tuple[str, str, callable]]:
    """Get /cores handlers"""
    return [
        ("GET", "cores", [list_cores, get_core]),
        ("HEAD", "cores", [get_core]),
        ("DELETE", "cores", [delete_core]),
    ]


def list_cores(query: dict[str:Any]) -> list[dict[str, Any]]:
    """List available cores

    query parameters:
        modifiedAfterEpochSec: only list cores modified after this epoch time
    """

    after_query_param = "modifiedAfterEpochSec"
    try:
        after = int(query.get(after_query_param, -1))
    except ValueError as e:
        raise UserError(
            f'Query parameter "{after_query_param}" must be an integer, '
            f"got {query.get(after_query_param)}"
        ) from e

    if not os.path.isdir(NUODB_LOGDIR):
        return []
    cores = []
    for core in Path(NUODB_LOGDIR).glob(f"{CORES_DIR}*/{CORE_FILE_PREFIX}*"):
        name = path_to_core_name(core)

        timestamp = core.stat().st_mtime
        if after >= 0 and after >= timestamp:
            continue
        with open(core, "rb") as f:
            checksum = hashlib.file_digest(f, hashlib.sha1).hexdigest()
        entry = {"name": name, "timestamp": int(timestamp), "checksum": checksum}
        cores.append(entry)
    cores.sort(key=itemgetter("name"))
    return cores


def path_to_core_name(path: Path) -> str:
    """Convert a file path to a core name"""
    core_dir = str(path.relative_to(NUODB_LOGDIR).parent)
    if core_dir.startswith(CORE_BACKUP_DIR_PREFIX):
        prefix = f"{core_dir.strip(CORE_BACKUP_DIR_PREFIX)}-"
    else:
        prefix = ""
    name = path.name
    return prefix + name


core_name_regex = re.compile(
    f"(?P<timestamp>\\d+T\\d+)-(?P<filename>{CORE_FILE_PREFIX}.+)"
)


def core_name_to_path(name: str) -> tuple[str, str]:
    """Convert a core name to a file path"""
    parsed = core_name_regex.fullmatch(name)
    if parsed:
        return CORE_BACKUP_DIR_PREFIX + parsed["timestamp"], parsed["filename"]
    return CORES_DIR, name


def get_core(core_name: str) -> Path:
    """Get a core"""
    file_dir, file_name = core_name_to_path(core_name)
    if not (
        file_name
        and file_name.startswith(CORE_FILE_PREFIX)
        and not os.sep in file_name
        and not (os.altsep and os.altsep in file_name)
    ):
        raise UserError("Invalid core")
    path = safe_join(NUODB_LOGDIR, file_dir, file_name)
    if path and os.path.isfile(path):
        return Path(path)
    raise HttpError(http.HTTPStatus.NOT_FOUND, "File not found")


def delete_core(core_name: str) -> None:
    """Delete a core"""
    core = get_core(core_name)
    core.unlink()
