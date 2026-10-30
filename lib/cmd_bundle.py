"""
cmd_bundle — add, update and remove bundles in the local bundle root from a
signed OCI artifact or a directory, recording where each came from.

A bundle carries files host root runs (`[host] setup`, `[build] script`,
`policy.cil`), so an OCI bundle is trusted like a package: it must pass
/etc/workloadctl/bundle-policy.json, and its root-run files need
`--allow-host-setup` when they're new or changed. See
docs/manual/04-containers.md "Bundles from a registry or a directory".
"""

import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

import bundle_store
from bundle_fetch import BundleFetchError, fetch, parse_ref, ref_name
from bundle_store import BundleError
from validation import validate_workload_name
from workload_lib import (bundle_roots, instances_by_bundle, workload_config_dir,
                          workload_config_path)
from workloadctl_core import WorkloadManager, require_root

_FETCH_TMP = "/var/tmp"


def _die(msg: str):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def _parse_source(arg: str) -> tuple[str, str]:
    """("dir", abs path) for an existing path, else ("oci", ref)."""
    p = Path(arg)
    if p.exists():
        if not p.is_dir():
            raise BundleError(f"{arg} is not a directory")
        return "dir", str(p.resolve())
    return "oci", parse_ref(arg)


def _stage(kind: str, value: str, name: str) -> tuple[Path, str, dict]:
    """Unpack or copy into a fresh staging dir: (staged, digest, files)."""
    staged = bundle_store.new_staging(name)
    try:
        if kind == "oci":
            with tempfile.TemporaryDirectory(prefix="workloadctl-bundle-", dir=_FETCH_TMP) as work:
                fetched = fetch(value, Path(work))
                bundle_store.extract_tar(fetched.tar, staged)
            digest = fetched.digest
        else:
            if not Path(value).is_dir():
                raise BundleError(f"source directory {value} is gone")
            bundle_store.copy_dir(Path(value), staged)
        bundle_store.relabel(staged)
        if not (staged / "workload.toml").is_file():
            raise BundleError("the bundle has no top-level workload.toml")
        files = bundle_store.tree_hashes(staged)
        if kind == "dir":
            digest = bundle_store.dir_digest(files)
        return staged, digest, files
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        raise


def _instance_refs(instances: list[str]) -> set[str]:
    refs = set()
    for inst in instances:
        try:
            refs |= bundle_store.root_run_refs(
                tomllib.loads(workload_config_path(inst).read_text()))
        except (OSError, tomllib.TOMLDecodeError):
            continue
    return refs


def _report_files(staged: Path, root_run: dict) -> None:
    if root_run:
        print("  Run as host root (setup at enable/disable, script at build, "
              "policy.cil loaded at enable): " + ", ".join(root_run))
    cfs = bundle_store.containerfiles(staged)
    if cfs:
        print("  Built in a rootful container at `workloadctl build`: " + ", ".join(cfs))


def _gate(kind: str, refs: list[str], allow: bool) -> None:
    if kind == "oci" and refs and not allow:
        raise BundleError(
            "the bundle has new or changed files that run as host root: "
            f"{', '.join(refs)}; read them, then pass --allow-host-setup")


def _add(args) -> None:
    kind, value = _parse_source(args.source)
    name = args.name or (ref_name(value) if kind == "oci" else Path(value).name)
    validate_workload_name(name)
    shipped, local = bundle_roots()
    if (shipped / name).is_dir():
        raise BundleError(f"a shipped bundle is named '{name}'; pass --name")
    if (local / name).exists() or bundle_store.record_path(name).exists():
        raise BundleError(f"{local / name} already exists; use `workloadctl bundle "
                          f"update {name}`, or pass --name")
    staged, digest, files = _stage(kind, value, name)
    try:
        root_run = bundle_store.root_run_files(staged)
        _report_files(staged, root_run)
        _gate(kind, sorted(root_run), args.allow_host_setup)
        bundle_store.swap_in(staged, name)
        bundle_store.write_record(name, bundle_store.make_record(
            f"{kind}:{value}", digest, files, root_run))
    finally:
        shutil.rmtree(staged, ignore_errors=True)
    print(f"✓ Added bundle '{name}' from {kind} {value} ({digest})")
    print(f"  workloadctl init {name} [--as <name>]")


def _require_recorded(name: str) -> dict:
    validate_workload_name(name)
    record = bundle_store.read_record(name)
    if record is None:
        local = bundle_roots()[1] / name
        if local.exists():
            raise BundleError(f"{local} wasn't added with `workloadctl bundle add`; "
                              "it's the admin's to edit")
        raise BundleError(f"no bundle '{name}' was added with `workloadctl bundle add`")
    return record


def _update(args) -> None:
    name = args.bundle
    record = _require_recorded(name)
    shipped, local = bundle_roots()
    if (shipped / name).is_dir():
        raise BundleError(
            f"a shipped bundle is now named '{name}', so this one would only "
            f"overlay it; `workloadctl bundle rm {name}` and add it under another --name")
    changed = bundle_store.drift(local / name, record)
    if changed and not args.force:
        raise BundleError(f"{local / name} was edited since it was installed: "
                          f"{', '.join(changed)}; pass --force to overwrite")
    kind, value = _parse_source(args.source) if args.source else bundle_store.recorded_source(record)
    if kind == "dir" and not Path(value).is_dir():
        raise BundleError(f"source directory {value} is gone; name a source")
    staged, digest, files = _stage(kind, value, name)
    try:
        if digest == record.get("digest") and not changed:
            print(f"Bundle '{name}' is current ({digest})")
            return
        instances = instances_by_bundle().get(name, [])
        root_run = bundle_store.root_run_files(staged, _instance_refs(instances))
        _report_files(staged, root_run)
        _gate(kind, bundle_store.changed_root_run(root_run, record.get("root_run", {})),
              args.allow_host_setup)
        bundle_store.swap_in(staged, name)
        bundle_store.write_record(name, bundle_store.make_record(
            f"{kind}:{value}", digest, files, root_run))
    finally:
        shutil.rmtree(staged, ignore_errors=True)
    if digest == record.get("digest"):
        print(f"✓ Restored bundle '{name}' ({digest})")
    else:
        print(f"✓ Updated bundle '{name}': {record.get('digest')} → {digest}")
    if instances:
        print(f"  Instances using it: {', '.join(instances)}. Units pick it up at "
              "their next restart; a self-built image needs `build`, then `update`; "
              "a setup or policy.cil change needs `enable` again; a VM's seed "
              "applies only on first boot.")


def _rm(args) -> None:
    name = args.bundle
    _require_recorded(name)
    using = instances_by_bundle().get(name, [])
    if using:
        raise BundleError(
            f"instances use '{name}': {', '.join(using)}; `workloadctl disable --purge` "
            f"each, then remove its directory in {workload_config_dir()}, which "
            "disable never touches")
    bundle_store.remove_bundle(name)
    print(f"✓ Removed bundle '{name}'")


def cmd_bundle(args, manager: WorkloadManager):
    """Manage bundles in /etc/workloadctl/bundles from an OCI artifact or a dir."""
    require_root()
    verb = {"add": _add, "update": _update, "rm": _rm}[args.subcommand]
    try:
        with bundle_store.bundle_lock():
            bundle_store.sweep_staging()
            try:
                verb(args)
            finally:
                bundle_store.drop_empty_staging()
    except (BundleError, BundleFetchError, ValueError) as e:
        _die(str(e))
