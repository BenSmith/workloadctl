# CI and the image supply chain

What this repository's CI does for the images the shipped bundles run, and
where that protection stops. The workflows themselves are listed in
`CLAUDE.md`.

## What it does

`.forgejo/workflows/build-workload-images.yml` builds the self-built bundle
images, scans each one before pushing it, and pushes and signs it. A scan
that finds a fixable critical CVE refuses the push unless
`.forgejo/cve-allowlist.txt` accepts that CVE. The workflow also runs every
week, so a published image is never much older than its base.
`.forgejo/workflows/scan-images.yml` scans the published images daily and
reports without failing anything.

On a host, `diagnose` reports an image built more than 30 days ago as
`image_current`.

## What the hypervisor image adds

The hypervisor image, built in its own repository, verifies the signature of
every image it pulls from `registry.local`. Its own CI reports, without
failing, security updates Fedora has shipped that the image lacks. The image
stages its own updates without applying them, so a new image boots at a
reboot the operator chooses.

## Where it stops

- A running workload keeps the image it was created from until it is
  recreated. A newer image in the registry changes nothing until `update` or
  `recreate`.
- Every job on the forge's runner can read the signing key and the registry
  login, so a signature says only that an image came from a job there. The
  runner takes jobs from the repositories of the user, organisation or
  repository it is registered for (`forgejo-runner`'s
  `FORGEJO_RUNNER_SCOPE`), never from the whole forge.
