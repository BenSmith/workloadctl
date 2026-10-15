# Zot Registry

OCI-native container registry with pull-through cache and web UI. Built from
the upstream `zot-linux-amd64` release binary on a Fedora base.

## Files

- `Containerfile` — fetches and verifies the Zot binary, installs to `/usr/local/bin/zot`
- built via `sudo workloadctl build zot-registry` → `localhost/zot-registry:latest`
- `entrypoint.sh` — runs `zot serve /etc/zot/config.json`
- `config.json` — default config: pull-through sync from docker.io, ghcr.io,
  quay.io, registry.fedoraproject.org, codeberg.org, plus search + UI
  extensions; listens on 127.0.0.1:5050, anyone reads, only `ci` pushes
- `htpasswd` (yours, in `data/`) — the `ci` user's bcrypt line

## Who can push

Zot listens on loopback only; caddy fronts it at `https://registry.local/`
and answers plain-HTTP `/v2` with a 404, so the push password only travels
over TLS. The check is in zot, not caddy: a host-network workload on the same
host reaches `127.0.0.1:5050` directly.

Anonymous clients may read everything. The `ci` user may create and update
only the repositories `config.json` lists for it: `workloads/**`,
`hypervisor-bootc`, `hypervisor-amd`, `hypervisor-nvidia`,
`fedora-bootc-minimal` and `negativo-rpms`. Nobody can push to a mirrored
name (`library/*`, `fedora`, ...): hosts accept those unsigned, so the cache
must be the only thing that writes them. Zot's sync writes them without the
API, so a pull still fills the cache. The longest matching pattern wins, which
is why each entry repeats `anonymousPolicy`.

Make the htpasswd line from a new random password (the host has no
`htpasswd`, so a throwaway container makes it):

```bash
PW=$(openssl rand -base64 32); echo "$PW"
printf %s "$PW" | podman run --rm -i registry.fedoraproject.org/fedora:44 \
  sh -c 'dnf -qy install httpd-tools >/dev/null && htpasswd -niB ci' \
  | sudo tee /var/lib/workloads/zot-registry/data/htpasswd
sudo workloadctl recreate zot-registry
```

Put the same password in the Forgejo secret `REGISTRY_CI_PASSWORD`, run the
`seal-registry-auth` workflow, and delete the secret once a build has pushed
(see the hypervisor image's [CI image signing notes](https://github.com/BenSmith/bootc-hypervisor/blob/main/docs/ci-image-signing.md)). Rotating it is the same three steps.

## Pinned version

`ZOT_VERSION` and `ZOT_SHA256` are baked into the Containerfile. To bump:

1. Pick a new tag from <https://github.com/project-zot/zot/releases>
2. Grab the matching checksum from the release's `checksums.sha256.txt`
3. Update both ARGs in `Containerfile`
4. Rebuild

## Customizing upstreams

`enable` seeds `config.json` into the workload's `data/` dir from the shipped
template (a `[setup].required_files` entry with an absolute hint). Edit
`/var/lib/workloads/zot-registry/data/config.json` there — not an
`/etc/workloads.d/zot-registry/` override, which the `./config.json` volume
would never read — and `sudo workloadctl recreate zot-registry`.

Each entry under `extensions.sync.registries` maps an upstream
URL; with `prefix: "**"` they all match every repo and Zot tries them in
order. Remove entries you don't need to speed up cache misses.

## Web UI

Open `https://registry.local/` after enabling. The UI surfaces repos, tags, layer
sizes, and metadata. CVE scanning is off by default (would pull a large Trivy
DB on startup); enable by adding `"cve": { "updateInterval": "24h" }` under
`extensions.search`.
