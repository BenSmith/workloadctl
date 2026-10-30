"""Fetch a bundle published as a signed OCI artifact.

skopeo copies the artifact into an `oci:` layout under the bundle trust
policy, dropping signatures on the way (an `oci:` destination can't store
them; the policy check runs before the drop). The layout is then read back:
one manifest of the bundle artifact type, holding one tar layer.

Publishing is documented in docs/manual, not a verb.
"""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import NamedTuple

ARTIFACT_TYPE = "application/vnd.workloadctl.bundle.v1"
LAYER_TYPE = ARTIFACT_TYPE + ".tar"

# Separate from /etc/containers/policy.json, which accepts unsigned images
# from public registries on purpose.
BUNDLE_POLICY = Path(os.environ.get("WORKLOADCTL_BUNDLE_POLICY",
                                    "/etc/workloadctl/bundle-policy.json"))

FETCH_TIMEOUT = 600

_LAYOUT_TAG = "b"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class BundleFetchError(Exception):
    pass


class Fetched(NamedTuple):
    digest: str     # the manifest digest, which signatures attach to
    tar: Path


def parse_ref(ref: str) -> str:
    """The ref if it's fully qualified with a tag or digest, else ValueError.

    Short names are refused before any network call, so a mistyped `forgejo`
    never becomes `docker.io/library/forgejo`."""
    if "/" not in ref:
        raise ValueError(f"{ref!r} is not a registry reference "
                         "(expected <registry>/<repo>:<tag>)")
    host = ref.split("/", 1)[0]
    if not ("." in host or ":" in host or host == "localhost"):
        raise ValueError(f"{ref!r} doesn't name a registry: "
                         f"{host!r} has no '.' or ':' and isn't localhost")
    name, _, digest = ref.partition("@")
    if digest:
        if not _DIGEST_RE.match(digest):
            raise ValueError(f"{ref!r}: bad digest {digest!r}")
        return ref
    if ":" not in name.rsplit("/", 1)[1]:
        raise ValueError(f"{ref!r} has no tag or digest")
    return ref


def ref_name(ref: str) -> str:
    """The last repository component: `registry.local/b/vm-base:1` -> `vm-base`."""
    repo = ref.partition("@")[0].rsplit("/", 1)[1]
    return repo.partition(":")[0]


def skopeo_copy(ref: str, layout: Path, policy: Path = BUNDLE_POLICY,
                timeout: int = FETCH_TIMEOUT) -> None:
    if not policy.is_file():
        raise BundleFetchError(
            f"no bundle trust policy at {policy}; OCI bundles are refused "
            "until the admin writes one (see docs/manual)")
    cmd = ["skopeo", "--policy", str(policy), "copy", "--remove-signatures",
           f"docker://{ref}", f"oci:{layout}:{_LAYOUT_TAG}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise BundleFetchError("skopeo is not installed") from None
    except subprocess.TimeoutExpired:
        raise BundleFetchError(f"skopeo copy of {ref} timed out after {timeout}s") from None
    if r.returncode != 0:
        raise BundleFetchError(f"skopeo refused {ref}: {r.stderr.strip()}")


def _blob(layout: Path, digest: str) -> Path:
    if not _DIGEST_RE.match(digest or ""):
        raise BundleFetchError(f"bad digest in layout: {digest!r}")
    return layout / "blobs" / "sha256" / digest.split(":", 1)[1]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def read_layout(layout: Path) -> Fetched:
    """The manifest digest and the verified tar blob of a one-bundle layout."""
    try:
        index = json.loads((layout / "index.json").read_text())
        manifests = index.get("manifests") or []
        if len(manifests) != 1:
            raise BundleFetchError(f"expected one manifest, found {len(manifests)}")
        digest = manifests[0].get("digest")
        mpath = _blob(layout, digest)
        if _sha256(mpath) != digest:
            raise BundleFetchError(f"manifest {digest} doesn't match its content")
        manifest = json.loads(mpath.read_text())
    except BundleFetchError:
        raise
    except (OSError, ValueError, AttributeError) as e:
        raise BundleFetchError(f"unreadable OCI layout: {e}") from None

    if manifest.get("artifactType") != ARTIFACT_TYPE:
        raise BundleFetchError(
            f"not a workloadctl bundle: artifactType "
            f"{manifest.get('artifactType')!r}, expected {ARTIFACT_TYPE!r}")
    layers = manifest.get("layers") or []
    if len(layers) != 1 or layers[0].get("mediaType") != LAYER_TYPE:
        types = [layer.get("mediaType") for layer in layers]
        raise BundleFetchError(
            f"a bundle has exactly one layer of type {LAYER_TYPE}; found {types}")
    layer = layers[0]
    tar = _blob(layout, layer.get("digest"))
    try:
        size = tar.stat().st_size
        actual = _sha256(tar)
    except OSError as e:
        raise BundleFetchError(f"bundle layer missing: {e}") from None
    if actual != layer["digest"] or size != layer.get("size"):
        raise BundleFetchError(f"bundle layer doesn't match its descriptor {layer['digest']}")
    return Fetched(digest, tar)


def fetch(ref: str, workdir: Path, policy: Path = BUNDLE_POLICY) -> Fetched:
    """Copy `ref` into `workdir` (the caller's temp dir; a refused copy leaves
    a partial layout there) and return its digest and tar."""
    layout = workdir / "layout"
    skopeo_copy(ref, layout, policy)
    return read_layout(layout)
