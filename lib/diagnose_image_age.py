#!/usr/bin/env python3
"""Whether a workload's images are older than an image should get.

An image stays as it was pulled or built until someone refreshes it, and
the known vulnerabilities in it grow while it sits (audit F26). Nothing
refreshes it unattended: a host takes a newer one on `update` or `build`,
so diagnose says when one is due.

Installed to /usr/libexec/workloadctl/diagnose_image_age.py.
"""

from datetime import datetime, timezone

# Past this, an image is reported stale. The self-built images are rebuilt
# weekly in CI, so one this old has newer builds waiting.
IMAGE_STALE_DAYS = 30


def image_created(info: dict) -> datetime | None:
    """When podman says the image was built, or None if it does not."""
    created = info.get("Created") if isinstance(info, dict) else None
    if not isinstance(created, str) or not created:
        return None
    # podman writes nanoseconds; fromisoformat takes up to microseconds.
    stamp = created.replace("Z", "+00:00")
    head, dot, rest = stamp.partition(".")
    if dot:
        digits = rest[:len(rest) - len(rest.lstrip("0123456789"))]
        zone = rest[len(digits):]
        stamp = f"{head}.{digits[:6]}{zone}"
    try:
        when = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def image_age_check(name, check_name, image, pull, info, now=None):
    """(check, passed, message, fix) for one image's age, or None when
    podman gives no build time to judge it by."""
    created = image_created(info)
    if created is None:
        return None
    now = now or datetime.now(timezone.utc)
    days = (now - created).days
    when = created.date().isoformat()
    if days <= IMAGE_STALE_DAYS:
        return (check_name, True, f"Image {image} built {days} days ago ({when})",
                None)
    if pull == "never":
        fix = (f"Rebuild it: workloadctl build {name}, "
               f"then workloadctl recreate {name}")
    else:
        fix = f"Pull a newer one: workloadctl update {name}"
    return (check_name, False,
            f"Image {image} built {days} days ago ({when}), past "
            f"{IMAGE_STALE_DAYS}", fix)
