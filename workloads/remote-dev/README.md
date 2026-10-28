# Remote development from an IDE

A workload to develop in from an IDE on another machine: JetBrains Remote
Development (CLion, RustRover, PyCharm, ...) or VS Code's Remote - SSH. The
IDE's window stays on the client; its server half, the toolchain, the
debugger and the project run here, under the workload's sandbox.

Nothing in the workload listens. The client's ssh reaches it through a
ProxyCommand:

```
IDE ── ssh ── ProxyCommand: ssh HOST sudo workloadctl exec NAME -- ide-sshd
                                               │
                              sshd -i in the workload, as dev
```

`ide-sshd` runs one sshd per connection over that pipe, as the workload's
own user, with the workload's environment. It takes keys only, forwards
nothing back out, and allows local forwarding, which is how the IDE
reaches its server half on the workload's loopback.

The image carries C/C++ (gcc, cmake, ninja), Rust (cargo, rust-src,
rustfmt, clippy), Python 3, git and gdb. `seccomp_allow` lets a debugger
trace the program it runs.

## Setup

1. **Create an instance**, named for the project:
   ```bash
   sudo workloadctl init remote-dev --as myproj
   ```
   To add a toolchain, `sudo workloadctl edit myproj Containerfile`, and give
   the edited image its own `[container].image`: instances share the
   bundle's image otherwise.

2. **Build and enable:**
   ```bash
   sudo workloadctl build myproj
   sudo workloadctl enable myproj
   ```

3. **Authorize the client's key** for the workload's user:
   ```bash
   sudo workloadctl exec myproj -- sh -c \
       'umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys' < client.pub
   ```

4. **On the client**, an entry in `~/.ssh/config`. The account on the host
   needs `sudo` without a password: a ProxyCommand has no terminal to ask on.
   ```
   Host myproj
       User dev
       ForwardAgent no
       ProxyCommand ssh -T -a -x admin@hypervisor sudo workloadctl exec myproj -- ide-sshd
   ```
   `ssh myproj id` should print `uid=1000(dev)`.

## From the IDE

**JetBrains:** Remote Development → SSH → the `myproj` entry. Choose the IDE
build matching the client's and let it upload the backend from the client;
a download from inside the workload needs its egress to reach JetBrains.
The backend lands in `~/.cache/JetBrains/RemoteDev/dist`, 5-6 GB per build;
one a client no longer uses can be removed there. The IDE keeps its ssh
connections open across attempts, so after a failed one, quit it before
trying again.

**VS Code:** Remote - SSH → the `myproj` entry. Its server installs into
`~/.vscode-server`. It downloads that from inside the workload unless
`remote.SSH.localServerDownload` is `always`, which fetches it on the client
and copies it over.

## Notes

- **Egress** is open. A `[network] hosts` list filters it to the names a
  project needs (crates, packages, git); see
  `docs/manual/06-networking.md`.
- **gdb** warns that it cannot disable address space randomization; the
  personality call it uses is not allowed. Debugging is unaffected.
- **Everything the IDE keeps** (its server half, caches, settings, the
  project) is in the home, `/var/lib/workloads/NAME/data/home`, so it
  survives `recreate`.
