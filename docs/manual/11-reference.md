# 11. Reference

This chapter collects what you look up rather than read through: every
command in one place, the files and units workloadctl keeps on a host, exit
codes, the variables a setup script and a VM seed receive, and the bundles
the package ships. Two references have files of their own: [the CLI
reference](../cli.md) gives every command's flags, and [the schema
reference](../schema-reference.toml) gives every TOML key.

## Commands

The tables group the commands by what you use them for. Each command's name
links to its flags in the CLI reference, and the last column names the
chapter that explains it. **Root** says whether the command needs `sudo`.

`exec`, `shell`, `cp`, `incant`, `reboot`, `health`, `stats` and `images` do
not check for root themselves. They act as the workload's user, through its
own podman or its SSH key, and that takes root, so run them with `sudo` too.

### Creating and changing workloads

| Command | What it does | Root | Explained in |
|---|---|---|---|
| [`catalog`](../cli.md#catalog) | Lists the shipped and local bundles, and whether each is a container or a VM. | no | [Concepts](01-concepts.md#bundles-and-instances) |
| [`init`](../cli.md#init) | Copies a bundle's TOML into `/etc/workloads.d/` as an instance; `--as` names it. `--scratch` and `--scratch-vm` write a stub with no bundle behind it. | yes | [First workloads](03-first-workloads.md#a-shipped-bundle), [VM workloads](05-vms.md#starting-from-a-template) |
| [`duplicate`](../cli.md#duplicate-alias-clone), `clone` | Copies a workload's TOML under a new name. The copy keeps the original's bundle. | yes | [Concepts](01-concepts.md#bundles-and-instances) |
| [`install`](../cli.md#install) | Copies a directory holding a `workload.toml` into `/etc/workloads.d/`, under the name its TOML gives. | yes | [Concepts](01-concepts.md#bundles-and-instances) |
| [`create`](../cli.md#create) | Writes a container workload's TOML from flags; `--enable` enables it as well. | yes | [First workloads](03-first-workloads.md#the-shortcut), [Container workloads](04-containers.md#from-the-command-line) |
| [`edit`](../cli.md#edit) | Opens the TOML in your editor, validates it when you save and offers to apply it. Given a file name, makes a copy-on-write override of one of the bundle's files. | yes | [Operating](09-operating.md#applying-a-change), [Container workloads](04-containers.md#changing-a-bundles-files) |
| [`validate`](../cli.md#validate) | Checks one TOML, or every TOML with `--all`, against the schema. | no | [Operating](09-operating.md#applying-a-change) |
| [`build`](../cli.md#build) | Builds a container workload's image from its bundle's `Containerfile`, or with its build script. | yes | [Container workloads](04-containers.md#building-your-own-image) |

### Running workloads

| Command | What it does | Root | Explained in |
|---|---|---|---|
| [`enable`](../cli.md#enable) | Marks a workload to start at boot, provisions its user, directories and units, and starts it. | yes | [Operating](09-operating.md#enabling-and-disabling) |
| [`disable`](../cli.md#disable) | Stops it and removes its units and its marker. `--purge` also deletes its user and everything under `/var/lib/workloads/<name>/`. | yes | [Operating](09-operating.md#enabling-and-disabling) |
| [`start`](../cli.md#start), [`stop`](../cli.md#stop) | Start or stop it, without changing whether it starts at boot. | yes | [Operating](09-operating.md#starting-stopping-and-restarting) |
| [`restart`](../cli.md#restart) | Restarts its units as they are. Edits to the TOML are not applied. | yes | [Operating](09-operating.md#starting-stopping-and-restarting) |
| [`recreate`](../cli.md#recreate) | Regenerates its units from the TOML, reruns its setup, and restarts it on the new units. | yes | [Operating](09-operating.md#applying-a-change) |
| [`reboot`](../cli.md#reboot) | Soft-reboots the systemd inside a container that runs systemd, or inside a VM's guest. | yes | [Operating](09-operating.md#starting-stopping-and-restarting) |
| [`update`](../cli.md#update) | Pulls newer images and restarts on them, going back to the old ones if the workload fails its check. Rebuilds a cattle VM's system disk. | yes | [Operating](09-operating.md#updating-container-images), [VM workloads](05-vms.md#update-and-rollback) |
| [`rollback`](../cli.md#rollback) | Returns a workload to its previous image, or a VM to its previous system disk. `--list` shows the targets. | yes | [Operating](09-operating.md#rolling-back) |

### Looking at workloads

| Command | What it does | Root | Explained in |
|---|---|---|---|
| [`list`](../cli.md#list) | Every workload under `/etc/workloads.d/`, enabled or not, with its state, image and ports. | no | [Operating](09-operating.md#seeing-what-is-there) |
| [`status`](../cli.md#status) | `systemctl status` for the workload's units, with a warning when the TOML or workloadctl has changed since they were generated. | no | [Operating](09-operating.md#seeing-what-is-there) |
| [`info`](../cli.md#info) | Its configuration, user, UID, image, ports and volumes. `--files` shows which control files come from `/etc` and which from `/usr`. | no | [First workloads](03-first-workloads.md#look-around) |
| [`logs`](../cli.md#logs) | Its journal: the units' messages and the containers' own output. Anything after the name is passed to `journalctl`. | no | [Operating](09-operating.md#logs) |
| [`stats`](../cli.md#stats) | CPU, memory, network and disk use, for one workload or all of them; `-f` follows. | yes | [Operating](09-operating.md#resource-usage) |
| [`health`](../cli.md#health) | Checks the unit, the user, the container, its health check and its published ports. | yes | [Container workloads](04-containers.md#checking-health) |
| [`drift`](../cli.md#drift) | Compares the running units, and the egress policies the inspectors loaded, with what the TOML gives now. | yes | [Operating](09-operating.md#drift) |
| [`images`](../cli.md#images) | Lists the images each workload uses. `images prune` removes untagged images from every workload's store. | yes | [Operating](09-operating.md#rolling-back) |

### Reaching inside a workload

| Command | What it does | Root | Explained in |
|---|---|---|---|
| [`shell`](../cli.md#shell) | Opens a shell in a container, or logs in to a VM's guest over SSH and falls back to its serial console. `--console` goes straight to the console. | yes | [VM workloads](05-vms.md#getting-into-the-guest) |
| [`exec`](../cli.md#exec) | Runs one command in a container, or over SSH in a VM's guest, and exits with its status. | yes | [First workloads](03-first-workloads.md#look-around), [VM workloads](05-vms.md#getting-into-the-guest) |
| [`cp`](../cli.md#cp) | Copies files between the host and a container. | yes | below |
| [`incant`](../cli.md#incant) | Runs a podman command as the workload's user, or sends one QMP command to a VM's QEMU. | yes | [Operating](09-operating.md#working-in-a-workloads-podman) |

`cp` takes `<workload>:<path>` on one side, or `<workload>/<container>:<path>`
in a multi-container workload, and a path on the host on the other:

```bash
sudo workloadctl cp web:/etc/nginx/nginx.conf ./nginx.conf
sudo workloadctl cp ./nginx.conf web:/etc/nginx/nginx.conf
```

Root handles the host side, so `cp` reads and writes any host path, and a
relative host path means your current directory. `cp` works on containers
only. For a VM, copy through `exec`, as in `sudo workloadctl exec myvm -- cat
/etc/hostname > hostname`.

### Diagnosing and housekeeping

| Command | What it does | Root | Explained in |
|---|---|---|---|
| [`doctor`](../cli.md#doctor) | One report: this boot's generator messages, the state of each unit, the setup checks, drift and health. | yes | [Troubleshooting](10-troubleshooting.md#doctor-everything-at-once) |
| [`diagnose`](../cli.md#diagnose) | The setup checks alone (user, ID ranges, linger, SELinux labels, egress plumbing), each with a fix when it fails. | yes | [Troubleshooting](10-troubleshooting.md#diagnose-what-is-wrong-with-this-hosts-setup) |
| [`cleanup`](../cli.md#cleanup) | Lists users, directories and SELinux modules whose TOML is gone. `--apply` removes them. | yes | [Operating](09-operating.md#cleaning-up) |

### Network

| Command | What it does | Root | Explained in |
|---|---|---|---|
| [`rules`](../cli.md#rules) | What a filtered workload's policy allows, for one host or for all of them. | yes | [Networking](06-networking.md#what-may-it-do-rules) |
| [`egress`](../cli.md#egress) | What a filtered workload asked for, from its per-request record. | yes | [Networking](06-networking.md#what-did-it-do-egress) |
| [`pcap`](../cli.md#pcap) | Captures a workload's packets on the host side, the guest side or both, with tcpdump's options. | yes | [Networking](06-networking.md#capturing-packets) |

### Data and secrets

| Command | What it does | Root | Explained in |
|---|---|---|---|
| [`backup`](../cli.md#backup) | Archives a workload's TOML, the sealed secrets it names, and its `data/` directory. | yes | [Operating](09-operating.md#backup-and-restore) |
| [`restore`](../cli.md#restore) | Puts an archive back. `--enable` starts the workload; `--force` overwrites what is there. | yes | [Operating](09-operating.md#backup-and-restore) |
| [`secret create`](../cli.md#secret-create) | Seals a value, from standard input or `--file`, into `/etc/credstore.encrypted/`. | yes | [Secrets](07-secrets.md#creating-a-secret) |
| [`secret list`](../cli.md#secret-list), [`secret show`](../cli.md#secret-show) | List the sealed secrets; decrypt and print one. | yes | [Secrets](07-secrets.md#listing-and-reading-secrets) |
| [`secret rotate`](../cli.md#secret-rotate) | Replaces a secret's value and restarts the workloads that use it. | yes | [Secrets](07-secrets.md#rotating-a-secret) |
| [`secret delete`](../cli.md#secret-delete) | Deletes a secret. | yes | [Secrets](07-secrets.md#removing-a-secret) |
| [`secret export`](../cli.md#secret-export), [`secret import`](../cli.md#secret-import) | Move a secret to another host, protected by a passphrase on the way. | yes | [Secrets](07-secrets.md#moving-a-secret-to-another-host) |

### Output for scripts

The commands that change a workload (`enable`, `disable`, `start`, `stop`,
`restart`, `recreate`, `reboot`, `build`, `update` and `rollback`) print
their progress on standard output and warnings and errors on standard error.
`-q` drops the progress and keeps the rest. `--json` replaces the progress
with one result document:

```json
{
  "command": "restart",
  "ok": true,
  "workloads": [
    {"workload": "web", "result": "restarted", "service": "workload-web.service"}
  ]
}
```

`ok` agrees with the exit status. A command that fails before it can report
still prints a document, with `ok` set to false and an `error` string. The
`--json` of a read command such as `list` or `doctor` is different: it prints
that command's own report as JSON. [The CLI
reference](../cli.md#the-result-object) lists the `result` values and each
command's extra keys. The same rows go to the workload's [operations
log](09-operating.md#the-operations-log).

## Exit codes

### workloadctl's own

| Status | Meaning |
|---|---|
| 0 | Success. For a report command, nothing wrong was found. |
| 1 | The command failed. Also returned when `validate`, `health`, `diagnose`, `doctor` or `drift` finds a problem, when a command that needs root is run without it, when the workload is masked, and when its user does not exist yet. An unexpected error also prints a traceback and asks for a bug report. |
| 2 | A usage error: an unknown flag, a missing argument, or a container named on a single-container workload or left out on a multi-container one. |
| 130 | Interrupted with Ctrl+C. |
| any other | The status of the `systemctl` or `podman` command that failed, or of a host setup script that failed during `enable`, passed through unchanged. |

`exec` exits with the status of the command it ran, so `sudo workloadctl exec
web -- test -f /etc/app.conf` works in a script as `test` would. For a VM,
255 means that SSH itself failed. `disable` carries on past a failed step and
exits 1 at the end if any step failed.

### In a workload's unit

`systemctl status`, `workloadctl status` and `doctor` show how a workload's
main process ended. For a container this is the container's own exit status,
except for three values podman keeps for itself:

| Status | Meaning |
|---|---|
| 125 | podman failed: the image is missing, an option is wrong, or a device or volume does not exist. |
| 126 | The container's command exists but could not be executed. |
| 127 | The container's command was not found in the image. |
| 137 | Killed with SIGKILL: the container did not stop within its stop timeout, or ran out of memory. |
| 143 | Ended by SIGTERM. A container unit counts this as a clean stop. |
| 159 | Killed by the seccomp profile for a forbidden system call ("Bad system call"). |
| 133 | A VM with `[vm].restart = "on-reboot"` was rebooted from inside the guest, and systemd starts it again. |
| `203/EXEC` | systemd could not execute the unit's program, as happens to a virtiofs sidecar given `NoNewPrivileges=`. |
| `226/NAMESPACE` | systemd could not set up the unit's namespaces. For a container workload this usually means the workload user's `/run/user/<uid>` is gone. |

Any other status is the application's own, and its output in `workloadctl
logs` says why. [Troubleshooting](10-troubleshooting.md#the-service-fails-with-status-125-126-or-127)
takes each of these from symptom to fix.

## Files and paths

### Configuration: `/etc/workloads.d/`

```
/etc/workloads.d/
├── shares.toml             # directories shared between workloads
└── web/
    ├── workload.toml       # the configuration
    ├── .enabled            # present while the workload is enabled
    └── Containerfile       # an override of the bundle's file, if you made one
```

Each workload is a directory, and its name must match the TOML's
`[workload] name`. A TOML anywhere else, such as a flat
`/etc/workloads.d/web.toml`, is not read.

The local bundle layer is `/etc/workloadctl/bundles/<bundle>/`, laid out
like a shipped bundle. A directory there overrides the shipped bundle of the
same name file by file, or is a bundle of its own if nothing ships that name
([Bundles and instances](01-concepts.md#bundles-and-instances)).

`.enabled` is what makes the workload start at boot. `enable` creates it and
`disable` deletes it ([The enabled marker](09-operating.md#the-enabled-marker)).

The other files are **control files**. A relative path the TOML gives for a
`Containerfile`, a build script, a `[host] setup` script or a `policy.cil` is
looked up first in the instance's own directory, then in the bundle's local
layer under `/etc/workloadctl/bundles/`, then in its directory under
`/usr/share/workloadctl/workloads/`. An absolute path is
used as written. `sudo workloadctl edit <name> <file>` makes the override in
`/etc` for you, and `workloadctl info <name> --files` shows which copy of
each file wins. A VM's relative `user_data_file` is the exception: it is
read from the instance's directory only.

`shares.toml` declares directories that several container workloads mount
([Sharing a directory between workloads](04-containers.md#sharing-a-directory-between-workloads)).

### Masking a workload

To stop a workload from being configured at all, as you would mask a systemd
unit, replace its TOML with a link to `/dev/null`. This is the way to switch
off a workload that a bootc image ships in `/etc/workloads.d/` on one host:
the link is a local change to `/etc`, which the image's next update keeps.

```bash
sudo workloadctl disable web
sudo mv /etc/workloads.d/web/workload.toml /root/web.workload.toml
sudo ln -s /dev/null /etc/workloads.d/web/workload.toml
```

Disable the workload first. Once it is masked, every command that names it
says so and exits 1, `doctor` aside, which reports the mask and exits 0. So
`disable` can no longer reach it, and units already running keep running
until the next boot. `list` and the `--all` forms leave a masked workload
out without a word. At boot the generator skips it, and logs an error if
its `.enabled` marker is still there.

Do not run `cleanup --apply` while a workload is masked. `cleanup` reads the
masked TOML as an empty file, so it counts the workload's user, its whole
directory under `/var/lib/workloads/`, data included, and its SELinux module
as orphans, and deletes them. Plain `cleanup` lists what it would delete.

To unmask the workload, delete the link and put the TOML back.

### Shipped by the package

| Path | What it holds |
|---|---|
| `/usr/share/workloadctl/workloads/<bundle>/` | The bundles: each one's `workload.toml` and its control files. `init` copies only the TOML out of here. |
| `/usr/libexec/workloadctl/` | The generator, the setup and arming helpers, and the modules the CLI runs from. |
| `/usr/lib/systemd/system-generators/workload-generator` | The systemd generator that schedules the generation step at boot. |
| `/usr/share/containers/seccomp-workload-baseline.json` | The seccomp profile every container runs under unless it names another ([Seccomp](08-security.md#seccomp)). |
| `/usr/libexec/moatery/` | The egress inspector, DNS responder and credential broker, from the moatery package. |
| `/etc/ssh/sshd_config.d/40-workloadctl.conf` | Refuses SSH logins to the host as any `_wl-*` user. |

### A workload's directory: `/var/lib/workloads/<name>/`

```
/var/lib/workloads/web/
├── state/              # the workload user's home; rebuilt, not backed up
│   └── volumes/        # the workload's @/ volumes
├── data/               # the workload's ./ volumes; backed up
├── operations.log      # one JSON line per command that changed the workload
├── provenance.json     # on a bootc host, the deployment that last set it up
└── .image-cache/       # a VM's downloaded cloud images
```

`state/` is the workload user's home directory. For a container it holds the
user's podman: its image store, the container layers and a pet's snapshots.
For a VM it holds:

| File in `state/` | What it is |
|---|---|
| `system.qcow2` | The system disk. |
| `system.qcow2.gen-<n>` | Earlier system disks, kept for `rollback`; the highest number is the newest. |
| `nvram.fd` | The VM's UEFI variables. |
| `.ssh/id_ed25519` | The key `shell` and `exec` log in to the guest with. |
| `.ssh/vm_host_ed25519_key` | The guest's SSH host key, which the seed installs in the guest. |
| `.ssh/vm_known_hosts` | The pin that `shell` and `exec` check that host key against. |
| `.cloud-init-provisioned` | Whether cloud-init's first boot finished for the current seed. |

`data/` holds what cannot be rebuilt: each `./` volume, the required files
the workload needs before it starts, a VM's shared directories, and a VM's
data disk, `data.qcow2`. workloadctl creates every `./` and `@/` volume
directory, owned by the workload user. For a volume mounted inside another
one, it also creates the directories that the inner mount point needs inside
the outer volume's directory, so the container's root does not create them.

`.image-cache/` keeps each cloud image a VM was built from, named after the
last part of its URL. Its checksum is verified every time it is used, and a
copy that fails is downloaded again. `operations.log` is described in
[Operating](09-operating.md#the-operations-log), and `provenance.json` in
[State from another bootc deployment](09-operating.md#state-from-another-bootc-deployment).

### Elsewhere on the host

| Path | What it holds |
|---|---|
| `/var/lib/workloads/backups/` | `backup`'s default destination, `<name>-<YYYYMMDD-HHMMSS>.tar.zst`, readable by root only. It survives `disable --purge`, and `cleanup` never treats it as an orphan. |
| `/etc/credstore.encrypted/` | Sealed secrets, one file each. A broker credential is under `broker/<workload>/<name>`. |
| `/var/lib/workloadctl/egress/<name>/` | A filtered workload's egress CA and its inspector's certificate caches. |
| `/var/log/workloadctl/egress/<name>/requests.log` | A filtered workload's per-request record, which `egress` reads, rotated by `/etc/logrotate.d/workloadctl-inspect`. |
| `/etc/subuid`, `/etc/subgid` | Each workload user's range of subordinate IDs. |
| `/var/lib/systemd/linger/_wl-<name>` | The marker that keeps the workload user's systemd manager running with nobody logged in. |

### Runtime files under `/run`

`/run` is emptied at every boot and rebuilt from the TOMLs, so nothing here
is worth editing.

| Path | What it holds |
|---|---|
| `/run/systemd/system/workload-<name>*` | The workload's generated units and its sysusers file. A container with `seccomp_allow`, `seccomp_netlink` or `seccomp_32bit` also has its seccomp profile here. |
| `/run/workload-env/workload-<name>.env` | Written at setup for the units to read: the workload user's runtime directory and the host's address, `HOST_IP`. |
| `/run/workload-env/workload-<name>.secrets`, `workload-<name>-<container>.secrets` | A container's secrets as environment variables, written as the container starts, readable by the workload user only. |
| `/run/workload-vm/<name>/` | A VM's QMP, guest-agent, serial console and virtiofs sockets, and its cloud-init seed. For any filtered workload, its inspector's and responder's status files. |
| `/run/workload-vm/_policy/<name>/` | The egress policy the inspector loaded when the workload started, owned by root. |
| `/run/user/<uid>/` | The workload user's runtime directory, where its rootless podman keeps its pause process and temporary state. |
| `/run/workload-exporter/` | The metrics files for node_exporter ([Metrics](09-operating.md#metrics)). |

## Units

### The units of one workload

You rarely need these names, because `status`, `logs`, `start`, `stop` and
the rest find a workload's units for you. They matter when you read
`systemctl` or the journal directly. For a workload `web`:

| Unit | Present for | What it does |
|---|---|---|
| `workload-web-setup.service` | every workload | Creates the workload's user, its ID ranges and directories, and its environment file before anything else of the workload runs. For a VM it also writes the keys, the firmware variables and the seed. |
| `workload-web.service` | every workload | The workload itself. In `single` mode it runs the container. In `pod` and `bridge` mode it is an umbrella, active while every member is. For a VM it runs QEMU, with passt beside it. |
| `workload-web-pod.service` | `pod` mode | Creates the pod the containers share. |
| `workload-web-net.service` | `bridge` mode | Creates the network `workload-web-net` the containers join. |
| `workload-web-<container>.service` | each container in `pod` or `bridge` mode | Runs that container. |
| `workload-web-build.service` | a VM | Builds the system disk when it does not exist yet, and the data disk with it. |
| `workload-web-clock.timer`, `workload-web-clock.service` | a VM | Checks the guest's clock through its guest agent, and sets it when it has drifted ([The guest's clock](05-vms.md#the-guests-clock)). |
| `workload-web-virtiofs-<tag>.service` | each shared directory of a VM | Serves that directory to the guest. |
| `workload-web-inspect.socket`, `workload-web-inspect.service` | a filtered workload | The egress inspector, started by the workload's first connection. |
| `workload-web-resolve.socket`, `workload-web-resolve.service` | a filtered workload that uses the DNS responder | The DNS responder, started by the workload's first query. |
| `workload-web-broker.service` | a filtered workload that declares a credential | The credential broker ([Keeping API keys out of the workload](06-networking.md#keeping-api-keys-out-of-the-workload)). |

A container workload also has its user's own systemd manager,
`user@<uid>.service`. Its containers run under that manager, in
`workloads.slice`, and the journal attributes their output to it rather than
to `workload-web.service`. That is why `journalctl -u workload-web` shows
only systemd's start and stop lines, and `workloadctl logs` is the command
that shows the rest. [Boot and generation](../dev/boot-and-generation.md#the-files-a-workload-owns)
lists every file a workload owns under `/run` and what starts each unit.

### Host-wide units

| Unit | What it does |
|---|---|
| `workload-generate.service` | Runs once, early in every boot. It writes the units of every enabled workload into `/run/systemd/system/` and starts them. `doctor` shows its messages for one workload. |
| `workloads.slice` | The slice every workload runs in, with limits for all workloads together ([The workloads slice](04-containers.md#the-workloads-slice)). |
| `workload-exporter.timer`, `workload-exporter-disk.timer` | Write the metrics files every 30 seconds and every 15 minutes ([Metrics](09-operating.md#metrics)). |
| `workload-pcap-<name>.service` | Exists while `pcap` captures a workload's traffic, and is removed when the capture ends. |

## How the CLI reaches a VM

`shell`, `exec` and `reboot` log in to a VM's guest over SSH as `[vm].user`,
with the key in `state/.ssh/id_ed25519`, and check the guest's host key
against the pin in `state/.ssh/vm_known_hosts`. A VM on passt, which is
every VM without `[vm.network].bridge`, is reached at its management
address: `127.128.0.0` plus the workload user's offset from UID 10000, on
port 2222 ([Getting into the guest](05-vms.md#getting-into-the-guest)).

A bridged VM has an address of its own on your LAN, and the host has to find
it. It asks three sources in turn, and the first answer wins:

1. the guest's `qemu-guest-agent`, taking only the addresses on the network
   interface that carries the MAC address workloadctl gave the VM;
2. the host's neighbour table for the bridge, matched on that MAC address;
3. mDNS, as `<name>.local`, when the host can resolve `.local` names.

The neighbour table only knows a guest the host has exchanged packets with
recently, so a VM that has been idle for a while drops out of it. Run
`qemu-guest-agent` in a bridged guest and the first source always answers.
When no source answers, `exec` fails and `shell` falls back to the serial
console, which needs no network at all. `workloadctl info` shows the
addresses the guest agent reports, for any VM that runs it.

## Variables

### What a host setup script receives

A `[host] setup` script ([Host setup scripts](04-containers.md#host-setup-scripts))
runs as root with one argument. `enable` runs it with `enable`, `disable`
with `disable`, and `doctor` and `diagnose` with `artifacts`, which asks it
to print what it installed and change nothing. Its environment names the
instance it acts for:

| Variable | Value |
|---|---|
| `WORKLOAD_NAME` | The instance name. |
| `WORKLOAD_BUNDLE` | The bundle the instance came from. |
| `WORKLOAD_LOCAL_BUNDLE_DIR` | That bundle's local layer, `/etc/workloadctl/bundles/<bundle>`, which may not exist. |
| `WORKLOAD_BUNDLE_DIR` | That bundle's shipped directory, `/usr/share/workloadctl/workloads/<bundle>`. |
| `WORKLOAD_USER` | `_wl-<name>`. |
| `WORKLOAD_INSTANCE_DIR` | `/etc/workloads.d/<name>` |
| `WORKLOAD_ROOT_DIR` | `/var/lib/workloads/<name>` |
| `WORKLOAD_STATE_DIR` | `/var/lib/workloads/<name>/state` |
| `WORKLOAD_DATA_DIR` | `/var/lib/workloads/<name>/data` |

Five of these, `WORKLOAD_NAME` and the four directories, can also be written
as `${WORKLOAD_NAME}` and so on inside a `security_opt` entry,
where they are replaced with the instance's values. No other key replaces
them, and `validate` refuses one anywhere else.

### What a VM seed receives

A seed file of your own (`[vm.cloud_init] user_data_file`) can use these
variables as `${NAME}`. A `[vm.cloud_init.template_vars]` entry with the same
name takes their place.

| Variable | Value |
|---|---|
| `WORKLOADCTL_SSH_KEY` | The workload's SSH public key, for the login user's `ssh_authorized_keys`. |
| `WORKLOADCTL_WORKLOAD_NAME` | The workload name. |
| `WORKLOADCTL_VM_USER` | `[vm].user`, the account the CLI logs in as. |
| `WORKLOADCTL_VM_HOST_KEY` | The guest's SSH host private key, as PEM. |
| `WORKLOADCTL_VM_HOST_KEY_B64` | The same key, base64-encoded on one line. |
| `WORKLOADCTL_VM_HOST_PUBKEY` | The matching public key. |
| `WORKLOADCTL_VM_EGRESS_CA` | A filtered VM's egress CA certificate, as PEM. Empty for an open VM. |
| `WORKLOADCTL_VM_EGRESS_CA_B64` | The same certificate, base64-encoded. |
| `WORKLOADCTL_VM_INSPECT_ADDR` | The VM's own address on the host, through which the guest reaches a service on its host. Not set for a bridged VM. |

[A seed of your own](05-vms.md#a-seed-of-your-own) shows them in use, with
the `${SECRET:name}` form for secrets.

## User namespace modes

| `[security] userns` | The workload user is, inside the container | Use it for |
|---|---|---|
| `"keep-id"` (default) | the UID equal to its own; container root is a subordinate ID | most images |
| `"keep-id:uid=N,gid=N"` | UID N | an image that runs as a fixed user and writes to its volumes |
| `"keep-id:uid=0,gid=0"` | root, in a private user namespace | an image that has to run as root, including systemd |
| `"host"` | root, in the namespace the workload's podman itself runs in | a container that must see host UIDs through a host mount; needs `unsafe_host_userns = true` |

[User namespaces](08-security.md#user-namespaces) explains each one.

## Looking under the hood

These commands show what workloadctl built for a workload `web`, without
going through workloadctl:

```bash
id _wl-web                                # the user and its UID
grep _wl-web /etc/subuid /etc/subgid      # its subordinate ID ranges
loginctl show-user _wl-web -p Linger      # Linger=yes keeps its podman alive
systemctl list-units 'workload-web*'      # every unit of the workload
systemctl cat workload-web.service        # one generated unit
sudo workloadctl incant web -- ps -a      # its containers, in its own podman
journalctl -t workload-web                # the container's raw output
sudo journalctl -b -k -g workload-generate   # the generator's earliest lines
```

In a multi-container workload the journal tag is
`workload-<name>-<container>`. `systemctl daemon-reload` does not regenerate
a workload's units: `recreate` does.

## The bundle catalogue

The package ships these bundles under `/usr/share/workloadctl/workloads/`.
`workloadctl init <bundle>` makes an instance of one, and each TOML's
opening comments walk through its setup. All are single-container workloads
unless the second column says otherwise.

The bundles marked "built here" carry a `Containerfile`. Most of them name
an image under `registry.local/workloads/`, where this project's CI publishes
it; on any other host, run `sudo workloadctl build <bundle>` before `enable`,
and the image it builds is used in place of the registry's. `zot-registry`'s
image exists only once you build it.

Several bundles copy a starter file into `data/` on the first `enable`, from
the `hint` of a `[setup] required_files` entry. Edit that copy and run
`recreate` to apply it.

| Bundle | Runs | What it is | Before you enable it |
|---|---|---|---|
| [`alloy`](../../workloads/alloy/README.md) | container | A per-host telemetry collector: host metrics, the journal and OTLP traces, forwarded to `otel-lgtm`. | Set `CENTRAL_HOST`, `HOST_LABEL` and `ROLE_LABEL`, and pick the `[network] ports` variant for a host that also runs `otel-lgtm`. Starter: `alloy-config.alloy`. |
| [`avahi`](../../workloads/avahi/README.md) | container, host network, built here | Publishes `<alias>.local` names for this host over mDNS, to pair with `caddy`. | Set `ALIASES`. Stop the host's own avahi-daemon and turn off mDNS in systemd-resolved, since only one responder can hold the port. |
| [`caddy`](../../workloads/caddy/README.md) | container, host network, built here | A reverse proxy on ports 80 and 443 that routes requests to local workloads by host name. | Starters: `Caddyfile`, and `homelab-root.crt`, copied from `/etc/pki/ca-trust/source/anchors/`, so the host needs that root certificate. Open 80 and 443 in the firewall. |
| [`comfyui`](../../workloads/comfyui/README.md) | container, built here | ComfyUI, a node-based image, video and audio generation UI, on port 8188 on the host's loopback. | Choose the GPU vendor when you build, with `CUDA_INDEX` (NVIDIA by default, `rocm7.1` for AMD, `cpu`). |
| [`dns-vpn`](../../workloads/dns-vpn/README.md) | container, built here | dnsmasq answering on port 53 and forwarding every query through a WireGuard tunnel. | Put your provider's WireGuard config at `data/wg0.conf`. |
| `example-multi-container` | containers, `bridge` mode | A template: Forgejo with PostgreSQL in two containers. | Create the secret `forgejo-db-password`, and allow `codeberg.org` images in podman's signature policy. |
| `forgejo` | container | Forgejo, a Git forge, with its web UI on port 3000 and SSH on 2222. | Allow `codeberg.org` images. Create the admin account over `ssh -L` before you open the ports. |
| [`forgejo-runner`](../../workloads/forgejo-runner/README.md) | VM | A Fedora VM that registers with a Forgejo on the same host as an Actions runner. | Set `FORGEJO_ADMIN_URL`, `FORGEJO_RUNNER_SCOPE` and `SAME_HOST_HOSTNAMES` in `[vm.cloud_init.template_vars]`, and create the secret `forgejo-admin-token`. |
| [`jellyfin`](../../workloads/jellyfin/README.md) | container | The Jellyfin media server, transcoding on the host GPU through VAAPI. | Put media in `data/media`. Finish the setup wizard over `ssh -L` before you open port 8096. |
| `llama-swap` | container | An OpenAI-compatible API on port 8080 that starts and swaps llama.cpp servers by the model each request names. | Put GGUF models in `data/models` and list them in the starter `config.yaml`. The default image uses Vulkan; the TOML lists the others. |
| `llamacpp` | container | A llama.cpp server for one model, on port 8080 on the host's loopback. | Put a GGUF model in `data/models` and name it in `--model` in `[container] command`. |
| [`nvidia-gpu-exporter`](../../workloads/nvidia-gpu-exporter/README.md) | container | Prometheus metrics for NVIDIA GPUs on port 9835. | Enable it only on a host with an NVIDIA GPU, and point `alloy` at it. |
| `oobabooga` | container | text-generation-webui, with its UI on port 7860 and an OpenAI-compatible API on 5000, both on the host's loopback. | Choose the image tag for your GPU. Put models in `data/models`. |
| `otel-lgtm` | container | The central observability backend: an OpenTelemetry collector with Prometheus, Loki, Tempo, Pyroscope and Grafana. | Create the secret `grafana-admin-password`. Open ports 3000, 4317 and 4318 to the hosts that report to it. |
| `pihole` | container, host network | Pi-hole, blocking ads and trackers for the whole network by DNS. | Turn off systemd-resolved, which holds port 53. Optionally set the admin password from the secret `pihole-webpassword`. Run `pihole -g` through `exec` after the first start. |
| [`pihole-vpn`](../../workloads/pihole-vpn/README.md) | container, built here | Pi-hole whose upstream DNS queries go through a WireGuard tunnel. | Put your WireGuard config at `data/wg0.conf`. |
| [`proxy-stack`](../../workloads/proxy-stack/README.md) | container, built here | Squid, a SOCKS5 proxy and Pi-hole together, all leaving through a WireGuard tunnel. | Put your WireGuard config at `data/wg0.conf`, and a `squid.conf` taken from the image, as the TOML shows. |
| `registry` | container | A Docker Registry v2 on port 5000 on the host's loopback, with no authentication. | Nothing. Add authentication before you publish it wider, or use `zot-registry`. |
| [`remote-dev`](../../workloads/remote-dev/README.md) | container, built here | A workload to develop in from an IDE on another machine, over SSH with nothing listening. | Make one instance per project with `init remote-dev --as <project>`, and authorize your client's key. |
| [`smb-server`](../../workloads/smb-server/README.md) | container, host network, built here | A Samba file share, guest-only and read-only unless you name users. | Starter: `smb.conf`. For named users, set `SMB_USERS` and a password secret for each. |
| [`socks5-vpn`](../../workloads/socks5-vpn/README.md) | container, built here | A SOCKS5 proxy on the host's loopback port 1080 that leaves through a WireGuard tunnel. | Put your WireGuard config at `data/wg0.conf`. |
| [`squid`](../../workloads/squid/README.md) | container, built here | A caching HTTP proxy on port 3128, tuned for packages and container images. | Starter: `squid.conf`. |
| `sunshine-streaming` | container, host network, built here | A headless Wayland desktop with Sunshine, streaming games to Moonlight clients ([notes](../../workloads/sunshine-streaming/NOTES.md)). | Set `DESKTOP_RESOLUTION`, and optionally a web UI login from the secret `sunshine-web`. Its setup script loads `uinput` and installs a udev rule on the host. |
| [`swarmui`](../../workloads/swarmui/README.md) | container, built here | SwarmUI, an image generation suite on top of ComfyUI, on port 7801 on the host's loopback. | Nothing. Its install wizard runs on first load and downloads its own ComfyUI backend. |
| `vm-base` | VM | A minimal Fedora Cloud VM to start from. | Make an instance with `init vm-base --as <name>` and set its size, its `user` and its egress stance. |
| `vncdesktop-labwc` | container, host network, built here | A labwc Wayland desktop served over VNC on the host's loopback port 5900. | Nothing. Connect through `ssh -L 5900:localhost:5900`. |
| `vncdesktop-sway` | container, host network, built here | The same with sway. | Nothing. Connect as above. |
| `vncdesktop-wayfire` | container, host network, built here | The same with wayfire. | Nothing. Connect as above. |
| `webproxy-demo` | containers, `bridge` mode | A demonstration of bridge mode: Caddy in front of a small backend, reached on port 8888. | Nothing. |
| [`wireguard-vpn`](../../workloads/wireguard-vpn/README.md) | container, built here | A WireGuard tunnel in a network namespace of its own; host traffic does not use it. | Put your WireGuard config at `data/wg0.conf`. |
| `wolf-game-streaming` | container, host network, built here | Wolf, a game streaming server for Moonlight clients that renders and encodes on the host GPU ([notes](../../workloads/wolf-game-streaming/NOTES.md)). | Choose the GPU stack when you build, with `GPU_TYPE` (`amd` by default, `nvidia`, `intel`). Its setup script loads `uinput` and installs a udev rule. |
| [`zot-registry`](../../workloads/zot-registry/README.md) | container, host network, built here | Zot, an OCI registry with a pull-through cache and a web UI, on the host's loopback port 5050 behind `caddy`. | Starter: `config.json`. Create `data/htpasswd` with the push account, as the TOML shows. |
