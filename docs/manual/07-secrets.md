# 7. Secrets

A workload usually needs something you would not put in its TOML: an API
key, a database password, a TLS private key. workloadctl keeps these as
systemd credentials, encrypted on disk and decrypted only while the workload
that uses them runs. The TOML names a secret; it never holds one.

## What a secret is

A secret is a file in `/etc/credstore.encrypted/`, encrypted with AES-256-GCM
by `systemd-creds`. It is sealed to this host: to its TPM2 chip, to a key
file systemd keeps at `/var/lib/systemd/credential.secret`, or to both. The
file is useless on any other machine, and only root can read the directory.

Nothing decrypts a secret until a workload that references it starts. For a
container, systemd decrypts each secret the unit references into a
memory-backed directory private to that unit, workloadctl hands the value to
the container, and the directory goes away when the unit stops. A VM's
secrets are decrypted when its cloud-init seed is built, as described below.

The `--key-type` option chooses the seal: `tpm2` (the default), `host`, or
`host+tpm2`, which needs both to decrypt. On a host without a TPM2 chip,
`tpm2` fails, so pass `--key-type host` to every `create`, `rotate` and
`import`.

If the TPM is cleared or replaced, or the host key file is lost, every
secret sealed to it is gone. Keep a way back to each value: the provider's
console, a password manager, or an export file kept off the host.

## Creating a secret

```bash
sudo workloadctl secret create webapp-api-key
```

`create` prompts for the value twice, with echo off, and seals it as
`/etc/credstore.encrypted/webapp-api-key`. A name may contain letters,
digits, `_` and `-`. `create` refuses a name that exists; `--force`
overwrites it.

To script it, pipe the value in. Piped input is stored byte for byte, so use
`printf '%s'` rather than `echo`: a value ending in a newline cannot be
injected as an environment variable, and `create` warns when it sees one.

```bash
printf '%s' "$DB_PASSWORD" | sudo workloadctl secret create webapp-db-password
```

`--file` seals a file exactly as it is, which suits certificates and keys
that the workload reads as files:

```bash
sudo workloadctl secret create webapp-tls-key --file ./key.pem
```

## Listing and reading secrets

```bash
sudo workloadctl secret list
sudo workloadctl secret list --json
```

`list` shows each secret's name, size and modification time. `show`
decrypts a secret and prints its value to your terminal:

```bash
sudo workloadctl secret show webapp-api-key
```

Before enabling a workload, run `sudo workloadctl validate <name>`. As root
it checks that every secret the TOML references exists; as an ordinary user
it cannot read the store and says so. It also warns when a value in the TOML
looks like a pasted provider key, such as a GitHub token or an `sk-ant-`
key, which belongs in a secret instead.

## Giving a secret to a container

### As an environment variable

Write `${SECRET:name}` in an environment value, as the whole value or part
of one. `[secrets]` mounts secrets as files:

```toml
[workload]
name = "webapp"

[container]
image = "registry.example.com/webapp:1.4"

[container.environment]
PUBLIC_URL = "https://webapp.example.com"
API_KEY = "${SECRET:webapp-api-key}"
DATABASE_URL = "postgresql://webapp:${SECRET:webapp-db-password}@db.example.com:5432/webapp"

[secrets]
files = [
    { credential = "webapp-tls-cert", path = "/etc/webapp/tls/cert.pem" },
    { credential = "webapp-tls-key", path = "/etc/webapp/tls/key.pem" },
]
```

You don't list the secrets anywhere else. workloadctl finds every reference
and has systemd load those secrets, and only those, for this workload's
unit. At each start it resolves the references into a file only the
workload's user can read and passes it to podman with `--env-file`, so the
values never appear in the unit. A plain value such as `PUBLIC_URL` does go
on the unit's command line, where any user on the host can read it.

Because the values are read at every start, a plain `restart` picks up a
rotated secret. A `pet` container ([Containers](04-containers.md)) is the
exception: it is created once and keeps the environment it was created
with, so a restart does not give it the new value and `recreate` does.

A value injected this way must be a single line. A secret containing a
newline stops the workload starting, with a message telling you to mount it
as a file instead. `${SECRET:name}` is recognised only in environment
values. To pass the literal text `${SECRET:name}`, write `$${SECRET:name}`.

### As a file

Each entry under `[secrets] files` names a `credential`, the `path` it
appears at inside the container, and optionally a `mode`. At each start
workloadctl copies the decrypted secret into the workload's runtime
directory, which is in memory, and bind-mounts the copy, relabelled so that
only this container can read it. The default, `mode = "ro"`, mounts it
read-only. `mode = "rw"` mounts a writable copy: whatever the container
writes there is discarded at the next start, and the secret itself never
changes. Inside the container the file is readable by every user, as any
bind-mounted file is.

Use a file for anything multi-line or binary, and for anything the
application reads from a path: certificates, private keys, configuration
with credentials in it.

### In a multi-container workload

Each container declares its own secrets: `${SECRET:name}` in its
`[containers.environment]`, and files in `[containers.secrets]`. Each
container's unit loads only the secrets that container references, so in
this pod the database never receives the TLS key:

```toml
[workload]
name = "forge"
mode = "pod"

[[containers]]
name = "db"

[containers.container]
image = "docker.io/library/postgres:16"

[containers.environment]
POSTGRES_PASSWORD = "${SECRET:forge-db-password}"

[[containers]]
name = "app"

[containers.container]
image = "codeberg.org/forgejo/forgejo:11"

[containers.environment]
FORGEJO__database__PASSWD = "${SECRET:forge-db-password}"

[containers.secrets]
files = [
    { credential = "forge-tls-key", path = "/data/tls/key.pem" },
]
```

A top-level `[secrets]` section is not applied to any container in a
multi-container workload.

## Giving a secret to a VM

The host cannot set a VM's environment, so a VM's secrets go into its
cloud-init seed. That takes a seed of your own: `user_data_file` names a
`#cloud-config` file, and workloadctl substitutes placeholders in it, as
plain text, when it builds the seed. A custom seed has other obligations,
covered in [Virtual machines](05-vms.md).

```toml
[vm.cloud_init]
user_data_file = "./cloud-init/user-data"
```

Two placeholders take a secret. `${SECRET:name}` is replaced with the
decrypted value; if the secret does not exist, the seed is not built and the
VM does not start. `${SECRET?name}` is the optional form, and a missing
secret becomes an empty string:

```yaml
write_files:
  - path: /etc/myapp/agent.env
    permissions: '0600'
    content: |
      API_TOKEN=${SECRET:myvm-api-token}
      JOIN_TOKEN=${SECRET?myvm-join-token}
```

Until you create `myvm-join-token`, the guest gets `JOIN_TOKEN=` with
nothing after it, so whatever reads the file should check for an empty
value. `$$` writes a literal `$`, so `$${HOME}` reaches the guest as
`${HOME}`.

A value goes in exactly as it decrypts, minus any trailing newline, and is
not itself scanned for placeholders. Keep a secret meant for a seed on one
line: a second line loses the indentation of a block like the one above, and
the YAML breaks.

The seed is built when the VM is set up, at every host boot and at
`recreate`, and written to `/run/workload-vm/<name>/cloud-init.iso`, in
memory, so the rendered secret never rests on the host's disk. Inside the
guest it does: cloud-init keeps its own copy of the user-data under
`/var/lib/cloud/`, and whatever `write_files` writes is on the VM's disk.

A different secret value makes a different seed, and a different seed gets
a new cloud-init instance ID. On its next boot the guest treats itself as a
new instance and runs its per-instance modules again: users, `write_files`,
`runcmd`. Write the seed so that a second run does no harm.

## Rotating a secret

```bash
sudo workloadctl secret rotate webapp-api-key
```

`rotate` lists the workloads whose TOML references the secret, prompts for
the new value (or reads it from a pipe, as `create` does), seals it, and
restarts those workloads so they pick it up. It restarts every workload
under `/etc/workloads.d/` that references the name, and restarting a
stopped workload starts it.

`rotate` seals with `--key-type`, which defaults to `tpm2` whatever the old
seal was, so on a host that uses the host key, pass `--key-type host`. It
has no `--file` option; to rotate a file secret, redirect the file in, and
ignore the newline warning, which matters only for environment variables:

```bash
sudo workloadctl secret rotate webapp-tls-key < ./new-key.pem
```

`rotate` sees references in container environments and `[secrets]` files
only. After rotating a secret that a VM's seed uses, rebuild the seed with
`sudo workloadctl recreate myvm`, which renders it again and restarts the VM
without touching its disks. Broker credentials are covered below.

## Removing a secret

Take the references out of the TOML and apply the change before you delete
the secret:

```bash
sudo workloadctl edit webapp
sudo workloadctl secret delete webapp-api-key
```

In the editor, remove the `${SECRET:...}` values and `[secrets]` entries,
and answer `y` when `edit` offers to apply the change, or run `sudo
workloadctl recreate webapp` afterwards. A plain `restart` keeps the old
units, which still load the secret.

`delete` asks for confirmation; `--force` skips it. It does not check
whether anything still uses the secret, and a workload whose units load a
deleted secret fails at its next start.

## Credentials for the broker

The credential broker ([Networking](06-networking.md)) attaches a provider's
API key to a workload's requests so that the workload itself never holds the
key. The key is a secret like any other, sealed under a scoped name:

```bash
sudo workloadctl secret create broker/agent/anthropic
```

The form is `broker/<workload>/<name>`: `<workload>` is the workload's name
and `<name>` matches the `name` of the workload's `credential` block. The
file is `/etc/credstore.encrypted/broker/agent/anthropic`, sealed under the
name `broker-agent-anthropic`. systemd checks that name when it decrypts,
so another workload's broker cannot load this key even if its unit points
at the file.

A scoped name cannot be written as `${SECRET:...}`, whose names have no
room for a `/`, so broker material never reaches a workload's environment,
files or seed. It is decrypted only for that workload's broker, which runs
as a user of its own.

Every `secret` subcommand takes the scoped form, and two behave differently
with it. `rotate` restarts nothing for a broker key, and the broker reads
its key only when it starts, so restart the broker yourself:

```bash
sudo workloadctl secret rotate broker/agent/anthropic
sudo systemctl restart workload-agent-broker.service
```

Restarting the workload restarts its broker too. `export` needs an explicit
`--output` for a scoped name, because the default file name would contain
the slashes. `sudo workloadctl validate agent` reports any broker key the
TOML declares that the store lacks, and gives the command that creates it.

## Moving a secret to another host

A sealed file opens only on the host that sealed it, so copying it achieves
nothing. `export` decrypts a secret and encrypts it again under a
passphrase, into a portable file; `import` decrypts that file on the other
host and seals the value there.

```bash
# on the old host
sudo workloadctl secret export webapp-api-key --output webapp-api-key.secret

# on the new host
sudo workloadctl secret import webapp-api-key webapp-api-key.secret
```

`export` asks for the passphrase twice and writes `<name>.secret` in the
current directory unless `--output` (`-o`) names another path. `import`
asks once, refuses to replace an existing secret unless you pass `--force`,
seals with `--key-type` (default `tpm2`), and lists the workloads that
reference the name, with the `recreate` command for each. The file does not
record the secret's name, so you can import it under a different one.

For scripts, both commands take the passphrase from a file with
`--passphrase-file PATH` (`-` reads standard input) or from standard input
with `--passphrase-stdin`. One trailing newline is dropped, and the
passphrase must be a single, non-empty line.

The file is encrypted with AES-256-CBC under a key derived by PBKDF2 over
600,000 iterations, and carries an HMAC-SHA256 of the ciphertext. A wrong
passphrase or a modified file fails that check before anything is
decrypted, and `import` refuses a file without the format's header.
[ADR 004](../adr/004-secret-export-versioned-crypto.md) records the format.
Anyone with both the file and the passphrase has the secret, so move them
separately and delete the file once it is imported.

## Secrets in a bootc image

The workload TOMLs in a bootc image ([Installing](02-installing.md#in-a-bootc-image))
name their secrets, and the image needs nothing more. Because a sealed file
opens only on the host that sealed it, one image cannot carry a secret for
many hosts. Seal on each host instead.

On a bootc host, `/etc` belongs to the host, so a secret you create there
survives every image update. A workload the image enables that starts
before its secret exists fails to start; create the secret, then restart the
workload.

An image built for a single host can carry that host's sealed files. Create
the secrets on the host, copy the files from `/etc/credstore.encrypted/`
into the build context, and install them root-only:

```dockerfile
COPY credstore.encrypted/ /etc/credstore.encrypted/
RUN chmod -R u=rwX,go= /etc/credstore.encrypted
```

The files are encrypted, so they are safe to keep in version control, and
they decrypt on that host alone. If you later rotate one of them on the
host, bootc keeps the host's changed copy across updates and the image's
copy no longer applies.

## Backup and restore

`workloadctl backup` ([Operating](09-operating.md)) puts the sealed files of
the secrets a workload's TOML references into the archive, beside the TOML
and `data/`. They stay sealed, so the archive holds no plaintext secret, and
they open only on the host that sealed them. Two kinds of secret are left
out: those only a VM's seed references, which the TOML never names, and
broker keys.

`restore` puts the sealed files back into `/etc/credstore.encrypted/`,
skipping any name that already exists unless you pass `--force`. On the same
host, that is all you need.

On another host the restored files cannot be decrypted. Bring each secret
over with `export` and `import`, replacing the restored copy, before you
enable the workload:

```bash
# on the old host
sudo workloadctl backup webapp --output /mnt/usb/
sudo workloadctl secret export webapp-api-key --output /mnt/usb/webapp-api-key.secret

# on the new host
sudo workloadctl restore /mnt/usb/webapp-<timestamp>.tar.zst
sudo workloadctl secret import webapp-api-key /mnt/usb/webapp-api-key.secret --force
sudo workloadctl validate webapp
sudo workloadctl enable webapp
```

`validate` names any secret the TOML references that is still missing,
broker keys included. It does not read a VM's seed, so check those secrets
with `secret list`. `restore` also suggests `secret rotate` for each file it
restored, which works if you know the value: it prompts for it and seals it
on the new host.

## Sealing by hand

`workloadctl secret` drives `systemd-creds`, and a secret you seal yourself
works the same way, provided the name embedded in it matches its file name.
systemd checks that name on every decryption. For a broker key the embedded
name is `broker-<workload>-<name>` and the path is
`broker/<workload>/<name>`.

```bash
sudo install -d -m 0700 /etc/credstore.encrypted
printf '%s' "$TOKEN" | sudo systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7 \
    --name=webapp-api-key - /etc/credstore.encrypted/webapp-api-key
sudo chmod 0600 /etc/credstore.encrypted/webapp-api-key
```

Sealing by hand gives you the options `workloadctl secret` does not expose.
`--tpm2-pcrs=7` binds the secret to the Secure Boot state, so it stops
decrypting when Secure Boot is turned off or its key databases change, which
a firmware update can do. `--not-after=` sets an expiry, after which
decryption fails and the workload does not start. Both trade availability
for protection, so keep a way to recreate the value. `workloadctl secret
rotate` seals with the key type alone, so rotating a secret drops both.

## Where the plaintext is

| Location | What it holds | How long |
|---|---|---|
| `/etc/credstore.encrypted/` | the sealed secrets, readable by root only | until deleted |
| `/run/credentials/workload-<name>.service/` | systemd's decrypted copies for one unit | while the unit runs |
| `/run/workload-env/workload-<name>.secrets` | the `KEY=value` lines for `${SECRET:...}` variables, one file per container, readable by the workload's user | rewritten at each start |
| `/run/user/<uid>/workload-secrets/` | the copies `[secrets]` mounts | rewritten at each start |
| `/run/user/<uid>/containers/` | podman's record of each container's environment | until the container is removed |
| `/run/workload-vm/<name>/cloud-init.iso` | a VM's rendered seed | rebuilt at each boot |

Everything under `/run` is in memory, so on the host nothing but the sealed
file survives a reboot. What the container or the guest does with a value
once it has it, such as writing it to a volume or its own disk, is up to the
software inside.

## Who can read a secret

Secret names are one namespace for the whole host: any workload's TOML can
reference any secret that is not scoped, including one meant for another
workload. That is deliberate. Writing a TOML already takes the trust of root
([Concepts](01-concepts.md#when-to-use-something-else)), so a rule about
which names it may use would protect nothing. What is kept apart is the
decrypted value: each workload's copies are readable only by root and that
workload's user, and a broker key is not readable by its workload at all.
Root on the running host can read every secret. [Security](08-security.md)
sets out the threat model behind these choices.

## Compared with other approaches

A plain value in `[container.environment]` ends up on the generated unit's
command line, readable by every user on the host, and the TOML itself is
usually world-readable as well. A file in a volume is plaintext on disk, and
if it lives under `data/`, every backup copies it in the clear. A value
baked into an image goes wherever the image goes, and changing it means a
rebuild.

`podman secret` keeps the value, with podman's default `file` driver,
unencrypted in the workload user's container storage under `state/`, where
that user can read it whether or not the workload is running. No TOML key
hands a podman secret to a container, so using one means working around
workloadctl rather than with it.

A secrets service such as Vault, or encrypted files such as SOPS, adds
central rotation, auditing and sharing across many machines, at the cost of
a service to run or a key to manage. systemd credentials need neither: they
work offline and use the TPM the host already has, which suits a host that
manages its own workloads. They do not share anything between hosts, so
moving a secret is the manual `export` and `import` above.
