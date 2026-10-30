"""Fixtures for the bundle tests: OCI layouts, bundle tars and a stub skopeo."""

import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

from bundle_fetch import ARTIFACT_TYPE, LAYER_TYPE


def bundle_tar(files: dict[str, bytes | str], modes: dict[str, int] | None = None) -> bytes:
    """A tar of `files` {relpath: content}; parent dirs are implied."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for rel, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(rel)
            info.size = len(data)
            info.mode = (modes or {}).get(rel, 0o644)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _put(layout: Path, data: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    blobs = layout / "blobs" / "sha256"
    blobs.mkdir(parents=True, exist_ok=True)
    (blobs / digest.split(":")[1]).write_bytes(data)
    return digest


def make_layout(layout: Path, tar: bytes = b"", *, artifact_type=ARTIFACT_TYPE,
                layer_types=(LAYER_TYPE,)) -> str:
    """Write a one-manifest OCI layout; returns the manifest digest. Each
    layer type gets the same `tar` blob."""
    layout.mkdir(parents=True, exist_ok=True)
    empty = _put(layout, b"{}")
    tar_digest = _put(layout, tar)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                   "digest": empty, "size": 2},
        "layers": [{"mediaType": t, "digest": tar_digest, "size": len(tar)}
                   for t in layer_types],
    }
    if artifact_type is not None:
        manifest["artifactType"] = artifact_type
    mbytes = json.dumps(manifest).encode()
    digest = _put(layout, mbytes)
    (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    (layout / "index.json").write_text(json.dumps({
        "schemaVersion": 2,
        "manifests": [{"mediaType": manifest["mediaType"], "digest": digest,
                       "size": len(mbytes),
                       "annotations": {"org.opencontainers.image.ref.name": "b"}}],
    }))
    return digest


STUB_SKOPEO = """#!/bin/sh
# Records its argv; copies $STUB_LAYOUT to the oci: destination, or fails.
printf '%s\\n' "$@" > "$STUB_ARGV"
if [ -n "$STUB_FAIL" ]; then echo "$STUB_FAIL" >&2; exit 1; fi
for a in "$@"; do case "$a" in oci:*) dest="${a#oci:}"; dest="${dest%:*}";; esac; done
mkdir -p "$dest" && cp -r "$STUB_LAYOUT"/. "$dest"/
"""


def install_stub_skopeo(bindir: Path) -> None:
    bindir.mkdir(parents=True, exist_ok=True)
    stub = bindir / "skopeo"
    stub.write_text(STUB_SKOPEO)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)


def stub_env(bindir: Path, layout: Path, argv: Path, fail: str = "") -> dict:
    return {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "STUB_LAYOUT": str(layout), "STUB_ARGV": str(argv), "STUB_FAIL": fail}
