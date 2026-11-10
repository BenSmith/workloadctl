"""The half of a filtered workload's image fetch that touches the network.

It runs as a throwaway `DynamicUser=` uid in a transient unit
(image_fetch.run_worker), which puts it outside every workload's egress
filter: that filter matches only the `_wl-<name>` uid. It writes only into
the unit's cache directory, and root reads the results from there, since a
start step can't take the unit's output through `systemd-run --pipe`.

    workload-image-fetch-worker inspect <image>
        inspect.json: the tag's manifest digest and its layers' sizes
    workload-image-fetch-worker copy <source> <name>
        image.tar: an oci-archive of <source>, named <name>

On failure both write `error`, the reason root shows the operator.
"""
import json
import os
import subprocess

SKOPEO = "/usr/bin/skopeo"
INSPECT_NAME = "inspect.json"
ARCHIVE_NAME = "image.tar"
ERROR_NAME = "error"
AUTH_NAME = "auth.json"
ERROR_LIMIT = 2000


class WorkerError(Exception):
    pass


# No credentials, said twice. --no-creds covers only the registry the image
# names; a mirror of it (registries.conf.d) is still looked up in the
# dynamic uid's /run/containers/<uid>/auth.json, which it may not read, and
# skopeo then skips the mirror and goes upstream. An empty authfile of its
# own leaves nothing to look up.
EMPTY_AUTH = "{}\n"


def inspect_argv(cache: str, image: str) -> list[str]:
    # No tags: the listing pages through every tag in the repository, which
    # for a large one takes minutes.
    return [SKOPEO, "inspect", "--no-creds", "--no-tags",
            "--authfile", os.path.join(cache, AUTH_NAME), f"docker://{image}"]


def copy_argv(cache: str, source: str, name: str) -> list[str]:
    # --tmpdir: the oci-archive layout is built in the big-file temp
    # directory, which is /var/tmp unless named here (TMPDIR is ignored).
    # --remove-signatures: an OCI layout can't store them; they are still
    # checked during the copy, as policy.json requires.
    return [SKOPEO, "--tmpdir", cache, "copy", "--quiet", "--src-no-creds",
            "--src-authfile", os.path.join(cache, AUTH_NAME),
            "--remove-signatures", f"docker://{source}",
            f"oci-archive:{os.path.join(cache, ARCHIVE_NAME)}:{name}"]


def summarize(inspect_json: str) -> dict:
    """The digest and the compressed size from `skopeo inspect`'s output.

    `size` is None when a layer's size is unknown: root then can't check
    free space, and says so."""
    data = json.loads(inspect_json)
    digest = data.get("Digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise WorkerError(f"skopeo inspect gave no manifest digest: {digest!r}")
    size = 0
    for layer in data.get("LayersData") or [None]:
        layer_size = layer.get("Size") if isinstance(layer, dict) else None
        if not isinstance(layer_size, int) or layer_size < 0:
            size = None
            break
        size += layer_size
    return {"digest": digest, "size": size}


def _skopeo(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise WorkerError(result.stderr.strip() or
                          f"skopeo exited {result.returncode}")
    return result.stdout


def _write(cache: str, name: str, text: str) -> None:
    with open(os.path.join(cache, name), "w") as f:
        f.write(text)


def run(argv: list[str], cache: str) -> None:
    _write(cache, AUTH_NAME, EMPTY_AUTH)
    if len(argv) == 3 and argv[1] == "inspect":
        summary = summarize(_skopeo(inspect_argv(cache, argv[2])))
        _write(cache, INSPECT_NAME, json.dumps(summary))
    elif len(argv) == 4 and argv[1] == "copy":
        _skopeo(copy_argv(cache, argv[2], argv[3]))
    else:
        raise WorkerError(f"usage: {argv[0]} inspect <image> | "
                          f"copy <source> <name>")


def main(argv: list[str]) -> int:
    cache = os.environ.get("CACHE_DIRECTORY", "")
    if not cache:
        print("ERROR: no CACHE_DIRECTORY; run only by workload-image-fetch",
              flush=True)
        return 2
    try:
        run(argv, cache)
    except (WorkerError, OSError, ValueError) as e:
        reason = str(e)[-ERROR_LIMIT:]
        print(f"ERROR: {reason}", flush=True)
        try:
            _write(cache, ERROR_NAME, reason)
        except OSError:
            pass
        return 1
    return 0
