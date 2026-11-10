"""Image references, as far as a filtered workload's fetch needs them."""


def split_reference(image: str) -> tuple[str, str, str]:
    """(repository, tag, digest) of an image reference; tag and digest may
    be empty."""
    repo, _, digest = image.partition("@")
    last = repo.rsplit("/", 1)[-1]
    tag = ""
    if ":" in last:
        repo, _, tag = repo.rpartition(":")
    return repo, tag, digest


def names_registry(image: str) -> bool:
    """Whether the reference's first component is a registry host.

    skopeo and podman expand short names differently, so a filtered image
    must name its registry."""
    first, sep, _ = image.partition("/")
    return bool(sep) and ("." in first or ":" in first or first == "localhost")


def source_reference(image: str, digest: str) -> str:
    """The image pinned to the digest that was inspected, so the copy gets
    what the decision was made on even if the tag moves in between."""
    repo, _, _ = split_reference(image)
    return f"{repo}@{digest}"
