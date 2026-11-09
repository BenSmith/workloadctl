"""
diagnose_subid — is a workload's subordinate id range the one it should have?

Pure verdicts over what the battery read out of /etc/subuid and /etc/subgid;
the range arithmetic they compare against lives in lib/workload_uid.py.
subid_derived_check is the load-bearing one and subid_overlap_check its
corroboration — each docstring says why. subgid_delegation_check reads the
single-gid lines a workload's delegated groups put in /etc/subgid.
"""

import re

_MANUAL = 'See 08-security.md, "When a delegated group changes".'


def subid_derived_check(
    entries: list[tuple[str, tuple[int, int] | None]],
    expected: tuple[int, int],
    uid: int,
) -> tuple[bool, str, str | None]:
    """Verdict: does each subid file's main range equal the derived one?

    `entries` is [(file, (start, count) | None), …]; a None (no entry at all) is
    subid_configured's business, not this one.

    Why this can't self-heal: `configure_subuid_subgid` grandfathers any
    existing entry — deliberately, because shifting a UID mapping under a
    running container corrupts its namespace. Correct behaviour, but it makes
    drift permanent *and* invisible: every later enable leaves the old range
    alone and reports success. Nothing else in the tree compares the two, which
    is why three of six workload users on a lab host sat on pre-derivation
    ranges for months.

    This is the load-bearing half of the pair, for a reason worth stating
    because it is not the one originally filed. `useradd` refuses to allocate
    over an entry it can see in /etc/subuid (measured — see
    subid_overlap_check), but `append_subid_entries` has no such courtesy: it
    writes the derived range without consulting anything. Collision safety
    therefore comes entirely from the derivation putting workload ranges above
    the territory `useradd` allocates in. A range off the formula is a range
    that has left the only guarantee there is.

    It also predicts (per claim_uid) a re-created workload adopting the old UID
    and grandfathering the wrong range straight back in.
    """
    off = [(f, e) for f, e in entries if e is not None and e != expected]
    if not off:
        return (True,
                f"Subid ranges match the derived range "
                f"({expected[0]}:{expected[1]})", None)
    detail = ", ".join(f"{f} has {s}:{c}" for f, (s, c) in off)
    return (False,
            f"Subid range is not the derived range for UID {uid}: expected "
            f"{expected[0]}:{expected[1]}, {detail}",
            "Remapping is manual and must be done with the workload stopped: "
            "rewrite the entry in /etc/subuid and /etc/subgid, then chown "
            "state/ from the old range to the new one. Scope the chown to "
            "state/ — every file in data/ is owned by the workload UID itself, "
            "so only the reconstructible graphroot needs remapping")


def subid_overlap_check(
    entries: list[tuple[str, tuple[int, int] | None]],
    window: tuple[int, int],
) -> tuple[bool, str, str | None]:
    """Verdict: does any main range sit inside `useradd`'s allocation window?

    **`useradd` is not the naive allocator this was originally filed against.**
    Measured on Fedora 44: park `_wl-caddy:589824:65536` in /etc/subuid where
    the next allocation would land, and successive `useradd`s take 524288 and
    then *655360* — they skip the parked range rather than overlapping it. Fill
    the window so the only candidate would straddle an existing entry and
    `useradd` refuses outright ("Can't get unique subordinate UID range"). So a
    range inside the window is not, on its own, the two-namespaces-in-one
    hazard this check was first justified by; that framing was wrong and this
    docstring is the correction.

    What it still catches is an **ordering** hazard, because the protection is
    one-directional. `useradd` defends itself against entries it can see in
    /etc/subuid. Nothing defends *us*: `append_subid_entries` writes the derived
    range without consulting existing entries, so a workload provisioned after
    a colliding human range would write straight over it. Living above the
    window is what makes that unreachable — which is why subid_derived is the
    load-bearing one and this check is its corroboration, not the reverse.

    And `useradd` can only skip what it can see. /etc is per-deployment on a
    bootc host while /etc/subuid entries accrue at runtime, so a rollback can
    boot a deployment whose /etc/subuid never listed a workload enabled later,
    while /var still holds files owned out of that range. A `useradd` there
    allocates it legitimately. Same /etc-vs-/var asymmetry as claim_uid.

    Scope is ranges starting strictly below SUB_UID_MAX. A range starting *at*
    SUB_UID_MAX — which on stock Fedora is also SUBID_BASE, since the two
    windows abut — cannot be taken while the entry is listed, per the refusal
    measured above, so it is not reported.
    """
    sub_uid_min, sub_uid_max = window
    inside = [(f, e) for f, e in entries if e is not None and e[0] < sub_uid_max]
    if not inside:
        return (True,
                f"Subid ranges are clear of useradd's window "
                f"({sub_uid_min}-{sub_uid_max})", None)
    detail = ", ".join(f"{f} at {s}:{c}" for f, (s, c) in inside)
    return (False,
            f"Subid range sits inside the window useradd allocates from "
            f"({sub_uid_min}-{sub_uid_max}): {detail} — useradd skips ranges "
            f"it can see in /etc/subuid, but nothing protects this range if it "
            f"is provisioned after a colliding one, or if a rollback boots an "
            f"/etc/subuid that never listed it",
            "Remap onto the derived range (see subid_derived's fix). Not "
            "urgent on its own — check `/etc/subuid` for a human user's range "
            "that already overlaps this one, which is the case that has "
            "already gone wrong rather than one that might")


def _gid_names(gids, names):
    return ", ".join(f"{g} ({names[g]})" if g in names else str(g)
                     for g in gids)


def extra_gidmap_host_gids(security: dict) -> set[int]:
    """Host gids the `extra_gidmaps` of a [security] table name, which the
    operator delegates by hand."""
    hosts = set()
    for m in security.get("extra_gidmaps", []):
        match = re.fullmatch(r"\+?\d+:@?(\d+):(\d+)", m)
        if match:
            host, size = (int(g) for g in match.groups())
            hosts.update(range(host, host + size))
    return hosts


def subgid_delegation_check(
    subgid_text: str,
    username: str,
    required: list[int],
    mapped: set[int],
    names: dict[int, str] | None = None,
) -> tuple[bool, str, str | None]:
    """Verdict: do the user's single-gid subgid lines match the groups the
    workload delegates?

    podman numbers a rootless user's namespace by sorting its subgid ranges
    by host id, and the single-gid lines sort before the main range. Adding
    or removing one shifts the group ids of the files already in the
    workload's images and volumes, so both directions are findings:

    - stale: a `user:G:1` line whose G is neither in `required` (what the
      writer would delegate) nor in `mapped` (host gids `extra_gidmaps`
      names, delegated by hand);
    - pending: a required G with no line yet.

    A user with no main range line is not provisioned: nothing exists to
    shift, so the verdict is clean. A line with a count other than 1 is the
    main range and never stale. Only `username`'s lines count.
    """
    names = names or {}
    lines = []
    for raw in subgid_text.splitlines():
        parts = raw.strip().split(":")
        if len(parts) != 3 or parts[0] != username:
            continue
        try:
            lines.append((int(parts[1]), int(parts[2])))
        except ValueError:
            continue
    if not any(count != 1 for _, count in lines):
        return True, "Subgid delegations match the required groups", None
    present = [start for start, count in lines if count == 1]
    stale = sorted({g for g in present
                    if g not in required and g not in mapped})
    pending = [g for g in required if g not in present]
    if not stale and not pending:
        return True, "Subgid delegations match the required groups", None
    parts = []
    if stale:
        parts.append(
            f"{username} has subgid delegations no workload group needs: "
            f"{_gid_names(stale, names)}. Removing a delegation shifts the "
            f"group ids of the workload's existing image and volume files.")
    if pending:
        parts.append(
            f"{username} needs subgid delegations it does not have yet: "
            f"{_gid_names(pending, names)}. Adding a delegation shifts the "
            f"group ids of the workload's existing image and volume files.")
    return False, " ".join(parts) + " " + _MANUAL, None
