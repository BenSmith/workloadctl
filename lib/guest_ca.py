#!/usr/bin/env python3
"""What a guest is given so that it trusts its workload's egress CA.

The anchor's path inside the guest and the variables that name it, which
the seed, the container's run arguments and validation all spell from
here. The CA itself -- where it lives on the host, how it is minted -- is
egress_ca's; this module decides only where a guest finds it.

Installed to /usr/libexec/workloadctl/guest_ca.py.
"""

from moatery.egress_ca import ca_dir


# Where the guest finds the CA whose certificates the inspector presents. A
# guest path, not a host path: the file arrives inside the seed and is written
# by cloud-init. /usr/local/share/ca-certificates is the directory
# `update-ca-certificates` consumes on Debian-family guests, so it holds the CA
# alone.
GUEST_CA_PATH = "/usr/local/share/ca-certificates/egress-ca.crt"

# What the five variables below name: the system's roots and the CA, in one
# file. Each variable replaces its runtime's trust store, and a connection the
# inspector splices presents the origin's own certificate, which only the
# roots verify; one it terminates presents a leaf only the CA verifies. A
# container gets the host's roots (host_trust_bundle); a guest builds it from
# its own store (GUEST_BUNDLE_LINES), since the seed is fingerprinted and the
# host's roots change under it.
CA_BUNDLE_PATH = "/usr/local/share/workloadctl/egress-ca-bundle.pem"

# Where a system's roots are, by distribution: Fedora's extracted bundle,
# Debian's, and the BSD/Alpine name.
SYSTEM_BUNDLES = (
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/cert.pem",
)


def container_ca_bundle_path(state_dir):
    """Where the host writes a container's bundle: beside the CA, whose
    label the containers may read."""
    return ca_dir(state_dir) / "bundle.pem"


def host_trust_bundle(ca_pem: bytes, bundles=SYSTEM_BUNDLES) -> bytes:
    """The first of `bundles` that holds anything, then the CA."""
    for path in bundles:
        try:
            roots = open(path, "rb").read()
        except OSError:
            continue
        if roots.strip():
            return roots.rstrip(b"\n") + b"\n" + ca_pem
    raise FileNotFoundError(f"no system trust bundle in {', '.join(bundles)}")


# The guest's half: its own roots, then the CA, into CA_BUNDLE_PATH. Run from
# runcmd at first boot, after write_files has put the CA down, and from bootcmd
# on every boot after, so the guest's own root updates reach it. A guest with
# none of SYSTEM_BUNDLES gets the CA alone.
_BUNDLE_TMP = CA_BUNDLE_PATH + ".tmp"
GUEST_BUNDLE_LINES = (
    f"if [ -s {GUEST_CA_PATH} ]; then",
    f"  mkdir -p {CA_BUNDLE_PATH.rsplit('/', 1)[0]}",
    f"  for f in {' '.join(SYSTEM_BUNDLES)}; do",
    '    if [ -s "$f" ]; then cat "$f"; break; fi',
    f"  done > {_BUNDLE_TMP}",
    f"  cat {GUEST_CA_PATH} >> {_BUNDLE_TMP}",
    f"  chmod 0644 {_BUNDLE_TMP} && mv {_BUNDLE_TMP} {CA_BUNDLE_PATH}",
    "fi",
)


# The environment variables that point a guest's HTTP clients at that bundle.
# Five, because there is no single one: OpenSSL reads SSL_CERT_FILE, Node reads
# NODE_EXTRA_CA_CERTS, python-requests reads REQUESTS_CA_BUNDLE, git reads
# GIT_SSL_CAINFO and pip reads PIP_CERT. A guest missing any one of them fails
# only in that ecosystem, which is the hardest kind of failure to attribute.
CA_ENV_VARS = (
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
)


# The guest variables workloadctl seeds itself, and therefore the ones a
# credential's `env` may not be. Derived from the producers rather than listed,
# so a sixth CA variable cannot leave this behind: the failure a stale copy
# produces is a silent overwrite in the seed, not an error anywhere.
#
# No broker variable is reserved, because nothing seeds one -- the guest is
# never told a broker address (ADR 007 decision 6).
RESERVED_GUEST_ENV = frozenset(CA_ENV_VARS)
