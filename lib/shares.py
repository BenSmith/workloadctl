#!/usr/bin/env python3
"""Named shares: a host directory two or more workloads use, one writing.

A share is declared once, in /etc/workloads.d/shares.toml:

    [shares.downloads]
    path = "/var/mnt/downloads"

and joined by each workload that uses it:

    [[shares]]
    name = "downloads"
    target = "/downloads"
    access = "write"            # or "read"
    subpath = "complete"        # optional: a directory inside the share
    containers = ["client"]     # optional: which containers mount it

The share's files carry an MCS category of its own, which its members'
processes hold beside their workload's pair, so a workload outside the
share is refused them by SELinux whatever their modes (audit F3). A file a
writer creates takes the directory's level, so new files keep the
category. Writers are in the share's group, which owns the tree; readers
are in its read group, which has a read ACL, and their mount is read-only,
so a reader cannot plant a file in it (audit F14). Groups, not users: a
process keeps its supplementary groups whatever uid it runs as in the
container, so a reader serving files as container root is still let in.

Shares are for container workloads. Every container of the workload mounts
a share unless its membership names the containers that do; the category
and the groups are the workload's either way (a pod has one user namespace
and one label), so the mount is what keeps the others out.

Installed to /usr/libexec/workloadctl/shares.py.
"""

import copy
import hashlib
import tomllib
from pathlib import Path
from typing import NamedTuple

from config_parser import WORKLOADS_BASE
from workload_lib import EGRESS_PKI_BASE, NAME_PATTERN, workload_config_dir
from workload_mcs import CATEGORIES, WORKLOAD_CATEGORIES

SHARES_FILE_NAME = "shares.toml"
ACCESS = ("read", "write")
GROUP_PREFIX = "wl-share-"
READ_GROUP_SUFFIX = "-ro"
# A group name is at most 32 characters.
MAX_SHARE_NAME = 32 - len(GROUP_PREFIX) - len(READ_GROUP_SUFFIX)


class Share(NamedTuple):
    name: str
    path: str
    category: int


class Membership(NamedTuple):
    name: str
    target: str
    access: str
    subpath: str
    containers: tuple[str, ...] = ()


def shares_file() -> Path:
    return workload_config_dir() / SHARES_FILE_NAME


def share_group(name: str) -> str:
    return f"{GROUP_PREFIX}{name}"


def share_read_group(name: str) -> str:
    return f"{share_group(name)}{READ_GROUP_SUFFIX}"


def derived_category(name: str) -> int:
    """A category above the workload pairs', from the name."""
    span = CATEGORIES - WORKLOAD_CATEGORIES
    digest = hashlib.sha256(name.encode()).digest()
    return WORKLOAD_CATEGORIES + int.from_bytes(digest[:4], "big") % span


def parse_shares(doc: dict) -> tuple[dict[str, Share], list[str]]:
    """The shares a shares.toml declares, and what is wrong with it."""
    shares, errors = {}, []
    table = doc.get("shares", {})
    if not isinstance(table, dict):
        return {}, ["[shares] must be a table of shares"]
    for name, entry in table.items():
        where = f"[shares.{name}]"
        if (not isinstance(name, str) or len(name) > MAX_SHARE_NAME
                or not NAME_PATTERN.match(name)):
            errors.append(f"{where}: a share name is a workload-style name "
                          f"of at most {MAX_SHARE_NAME} characters")
            continue
        if not isinstance(entry, dict):
            errors.append(f"{where} must be a table")
            continue
        unknown = sorted(set(entry) - {"path", "category"})
        if unknown:
            errors.append(f"{where}: unknown key(s) {', '.join(unknown)}")
        path = entry.get("path")
        if (not isinstance(path, str) or not path.startswith("/")
                or ".." in Path(path).parts or path.rstrip("/") == ""):
            errors.append(f"{where}: path must be an absolute directory")
            continue
        # Each workload's tree is stamped with its own level at setup, which
        # would take a share inside one off the share's category.
        if any(Path(path).is_relative_to(tree)
               for tree in (WORKLOADS_BASE, EGRESS_PKI_BASE)):
            errors.append(f"{where}: path must not be under {WORKLOADS_BASE} "
                          f"or {EGRESS_PKI_BASE}")
            continue
        category = entry.get("category", derived_category(name))
        if (not isinstance(category, int) or isinstance(category, bool)
                or not WORKLOAD_CATEGORIES <= category < CATEGORIES):
            errors.append(f"{where}: category must be from "
                          f"{WORKLOAD_CATEGORIES} to {CATEGORIES - 1}")
            continue
        shares[name] = Share(name, path.rstrip("/"), category)
    by_category = {}
    for share in shares.values():
        by_category.setdefault(share.category, []).append(share.name)
    for category, names in sorted(by_category.items()):
        if len(names) > 1:
            errors.append(f"shares {', '.join(sorted(names))} have one "
                          f"category, c{category}: give one a `category`")
    paths = sorted(shares.values(), key=lambda s: s.path)
    for a, b in zip(paths, paths[1:]):
        if b.path == a.path or b.path.startswith(a.path + "/"):
            errors.append(f"shares {a.name} and {b.name} overlap "
                          f"({a.path}, {b.path})")
    return shares, errors


def load_shares(path: Path | None = None) -> tuple[dict[str, Share], list[str]]:
    """shares.toml, or no shares if there is none."""
    path = path or shares_file()
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
    except FileNotFoundError:
        return {}, []
    except (OSError, tomllib.TOMLDecodeError) as e:
        return {}, [f"{path}: {e}"]
    return parse_shares(doc)


def validate_memberships(config: dict) -> list[str]:
    """What is wrong with a workload's [[shares]], on its own."""
    entries = config.get("shares", [])
    if not entries:
        return []
    if "vm" in config:
        return ["[[shares]] is for container workloads"]
    if not isinstance(entries, list):
        return ["[[shares]] must be an array of tables"]
    errors, seen = [], set()
    for i, entry in enumerate(entries):
        where = f"[[shares]][{i}]"
        if not isinstance(entry, dict):
            errors.append(f"{where} must be a table")
            continue
        unknown = sorted(set(entry) - {"name", "target", "access", "subpath",
                                       "containers"})
        if unknown:
            errors.append(f"{where}: unknown key(s) {', '.join(unknown)}")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"{where}: name is required")
        target = entry.get("target")
        if not isinstance(target, str) or not target.startswith("/"):
            errors.append(f"{where}: target must be an absolute path in the "
                          f"container")
        elif target in seen:
            errors.append(f"{where}: target {target} is used twice")
        else:
            seen.add(target)
        if entry.get("access") not in ACCESS:
            errors.append(f"{where}: access must be \"read\" or \"write\"")
        subpath = entry.get("subpath", "")
        if (not isinstance(subpath, str) or subpath.startswith("/")
                or ".." in Path(subpath).parts):
            errors.append(f"{where}: subpath must be relative, inside the "
                          f"share")
        if "containers" in entry:
            errors.extend(_container_errors(where, entry["containers"],
                                            config))
    return errors


def _container_errors(where, named, config) -> list[str]:
    if "containers" not in config:
        return [f"{where}: containers is for a workload with "
                f"[[containers]]"]
    if (not isinstance(named, list) or not named
            or not all(isinstance(n, str) for n in named)):
        return [f"{where}: containers must be a list of container names"]
    present = {c.get("name") for c in config.get("containers") or []
               if isinstance(c, dict)}
    return [f"{where}: no container named {n!r}"
            for n in named if n not in present]


def memberships(config: dict) -> list[Membership]:
    """A validated workload's [[shares]]."""
    return [Membership(e["name"], e["target"], e["access"],
                       e.get("subpath", "").strip("/"),
                       tuple(e.get("containers", ())))
            for e in config.get("shares", [])]


def membership_source(share: Share, membership: Membership) -> str:
    if membership.subpath:
        return f"{share.path}/{membership.subpath}"
    return share.path


def share_categories(config: dict, shares: dict[str, Share]) -> list[int]:
    return sorted({shares[m.name].category for m in memberships(config)
                   if m.name in shares})


def resolve(config: dict, shares: dict[str, Share], warn=None) -> dict:
    """The workload as its units run it: each share mounted in every
    container, or in those its membership names (read-only for a reader),
    the share's group or read group added, and the share categories
    recorded for its label (security.share_categories). A share shares.toml
    does not declare is left out, with a warning."""
    joined = memberships(config)
    if not joined:
        return config
    config = copy.deepcopy(config)
    holders = (config.get("containers") or []) if "containers" in config \
        else [config]
    for holder in holders:
        storage = holder.setdefault("storage", {})
        storage["volumes"] = list(storage.get("volumes", []))
    groups = []
    for m in joined:
        share = shares.get(m.name)
        if share is None:
            if warn:
                warn(f"share {m.name!r} is not declared in {shares_file()}; "
                     f"not mounted")
            continue
        suffix = ":ro" if m.access == "read" else ""
        volume = f"{membership_source(share, m)}:{m.target}{suffix}"
        for holder in holders:
            if not m.containers or holder.get("name") in m.containers:
                holder["storage"]["volumes"].append(volume)
        groups.append(share_group(m.name) if m.access == "write"
                      else share_read_group(m.name))
    security = config.setdefault("security", {})
    extra = list(security.get("extra_groups", []))
    security["extra_groups"] = extra + [g for g in groups if g not in extra]
    security["share_categories"] = share_categories(config, shares)
    return config


def readers_and_writers(share_name: str, configs: dict[str, dict]
                        ) -> tuple[list[str], list[str]]:
    """The workloads reading and writing a share, by name, of `configs`."""
    readers, writers = set(), set()
    for workload, config in configs.items():
        for m in memberships(config):
            if m.name == share_name:
                (writers if m.access == "write" else readers).add(workload)
    return sorted(readers), sorted(writers)
