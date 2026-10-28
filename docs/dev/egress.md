# The egress plane

This is the maintainers' map of how a filtered workload's traffic is
policed: which units exist and what starts them, which nftables objects each
one arms, who writes and who reads each file, and the path a request takes
through the kernel and the three daemons. How to configure filtering is in
the manual's [Networking and egress](../manual/06-networking.md). The
decisions behind the design are ADRs
[006](../adr/006-vm-networking-passt-not-managed-bridge.md),
[007](../adr/007-per-workload-credential-broker.md),
[008](../adr/008-transparent-egress-inspection.md) and
[009](../adr/009-container-egress-parity-and-the-single-uid.md). The VM's own
units are in [the VM runtime](vm-runtime.md).

## Two halves: workloadctl writes, moatery runs

The three daemons are moatery's: `moat-inspect` (the egress inspector),
`moat-resolve` (the synthesising DNS responder) and `moat-broker` (the
credential broker), all in `/usr/libexec/moatery/`, with `moat-mint-ca`
minting each workload's CA. None of them knows what a workload is. Each is
handed every value it needs as a flag on its unit's `ExecStart=`, and
moatery's own closure test holds that their imports contain no config
grammar and nothing that turns a uid into an address.

Everything workload-shaped is on this side: deciding which workloads are
inspected, deriving addresses from the uid, rendering the policy document,
arming nftables, and writing the units. The vocabulary of the policy document
(the hostname rule, the TLS modes, a policy entry and how entries govern a
request, the digest) is `moatery.inspect_document`, which the renderer here
and the reader in the inspector both import.

The two substrates share all of it. A VM differs from a container only in
which TOML table holds the policy, which predicate turns it on, which helper
arms it, and which unit is the head the sidecars are ordered against.

## Which workloads get what

Three predicate pairs decide everything, and every consumer calls them rather
than restating them: the generator, the arming helpers, the run-file list
(so `drift` and `disable` see the same set), `diagnose`, `doctor` and the
exporter.

| Gets | VM | Container |
|---|---|---|
| inspector and filter | `egress_policy.vm_uses_inspect`: a VM, not bridged, `egress` filtered | `container_network_config.container_uses_inspect`: any of `hosts`, `allow`, `policy`, and not on the host network |
| responder | `egress_policy.vm_uses_resolve`: the above, and `resolver` not `"none"` | `egress_policy.container_uses_resolve`: the above, in a `single` or `pod` workload on pasta |
| broker | `broker_config.vm_uses_credentials`: inspected, and at least one credential block | `broker_config.container_uses_credentials`: the same |

An inspected VM gets its inspector whether or not it lists `hosts`. A passt
VM that is open still runs the filter helper on every start, which purges
any elements its uid left armed and then stops, and it runs
`workload-vm-svcaddr` (see [Addressing](#addressing)).

## The units, and what starts them

For a workload `web`, filtering adds up to five units beside the workload's
own:

| Unit | Started by | Runs |
|---|---|---|
| `workload-web-inspect.socket` | the head unit's `Requires=` | binds the inspector's four listening sockets; `ExecStartPre` arms the redirect, `ExecStopPost` retires it |
| `workload-web-inspect.service` | the socket, on the first connection | `moat-inspect` as `_wl-web`, in `workloads.slice` |
| `workload-web-resolve.socket` | the head unit's `Requires=` | binds `127.130.x.y:53`, UDP and TCP |
| `workload-web-resolve.service` | the socket, on the first query | `moat-resolve` as `_wl-web` |
| `workload-web-broker.service` | the head unit's `Requires=` | `moat-broker` as a dynamic user, `Type=notify` |

The **head unit** is the one unit ordered ahead of everything the workload
runs, and it carries both the dependencies on these units and the filter
arming. For a VM and for a `single` container it is `workload-web.service`.
For a `pod` or `bridge` container it is the pod-create or network-create
oneshot, `workload-web-pod.service` or `workload-web-net.service`
(`gen_container_heads._head_unit`), not the umbrella: the umbrella is
`After=` its member containers, so anything attached to it would run once
every container was already up.

The head is `Requires=` and `After=` each sidecar, and each sidecar carries a
`Before=` of its own. Ordering does not start anything, so the head's
`Requires=` is what actually pulls a sidecar in. It also works the other way:
restarting a sidecar by hand restarts the head, and with it the workload.
The sidecars are `PartOf=workload-web.service`, so stopping or restarting the
workload stops or restarts them, and the responder service is
`StopPropagatedFrom=` it. The sockets and the broker also `Requires=` and
`After=` `workload-web-setup.service`, because their prestarts and their
`User=` need `_wl-web` to exist, and the sockets set
`DefaultDependencies=no` to avoid an ordering cycle through `sockets.target`
and `basic.target` at shutdown.

A VM start therefore runs in this order. The setup unit creates the user.
The inspect socket's `ExecStartPre`, `workload-vm-inspect up`, writes the
policy and arms the redirect, then the socket binds; the responder socket
binds; the broker starts and reports ready once it is listening. These three
run in no particular order among themselves. Then the VM unit's own
prestarts run `workload-vm-netdev` (which points passt's DNS at the
responder), `workload-vm-filter up` and `workload-vm-svcaddr up`, and QEMU
starts with passt beside it. The inspector and responder services start later,
on the guest's first connection and first query.

A container's order is the same, with `workload-container-inspect` on the
socket and `workload-container-filter up` as an `ExecStartPre` of the head
unit, ahead of `podman run` or the pod or network create. pasta is pointed
at the responder by the `--dns-host` option the generator adds to the
container's `--network=`.

Every arming helper has an `up` that fails loudly and a `down` that is
tolerant (`helper_main.run_helper`). `up` runs as `+` (root, failing the unit
if it fails), and a filtered workload that failed to arm does not start. `down`
runs as `-+` from `ExecStopPost`, which systemd also runs on a kill or a
failed start, and treats a missing element as the expected state.

## Who writes and reads each file

| File | Written by | Read by |
|---|---|---|
| `/run/workload-vm/_policy/<name>/inspect.json` | `inspect_arm.up`, at every socket start, root-owned, mode 0640, group `_wl-<name>`, replaced atomically | `moat-inspect` once at start (`--policy`); `moat-resolve`, to count unlisted lookups; `rules`; `drift`, which compares its bytes with a fresh render; `diagnose`, which compares its digest with the one the inspector reports |
| `/run/workload-vm/_policy/<name>/resolve-static.json` | `filter_arm.up`, from the same resolution that armed the `allow` elements | `moat-resolve` (`--static`) |
| `/run/workload-vm/<name>/inspect-status.json` | `moat-inspect` (`--status`); cleared by `inspect_arm.up` | `diagnose`, `doctor`, `workload-exporter`, through `lib/inspect_figures.py` |
| `/run/workload-vm/<name>/resolve-status.json` | `moat-resolve` (`--status`); cleared by `filter_arm.arm_resolve` | the same three |
| `/var/log/workloadctl/egress/<name>/requests.log` | `moat-inspect` (`--record`), in the service's `LogsDirectory=` | `egress`, through `lib/egress_record_query.py` |
| `/var/lib/workloadctl/egress/<name>/` | the CA by `ensure_common.generate_egress_ca` (running `moat-mint-ca`) at setup; the leaf caches by `moat-inspect` | `moat-inspect` (`--state-dir`); the VM seed embeds the certificate; a container's `ca_delivery` mounts it or a bundle built from it |

The policy inputs sit under `_policy/`, a root-owned tree, rather than in the
workload's runtime directory, because the workload user can rename anything
in its own directory and a guest that escaped into QEMU could otherwise
replace the policy its traffic is held to. The policy is written at start,
not at generation, because `/run` does not exist when the generator runs, and
because writing it at start is what lets an edited list take effect on a
restart. It is written before anything is armed: the inspector is
socket-activated, so the workload's first dial can start it the moment the
redirect exists.

## Addressing

Every per-workload value is the workload uid's offset from `UID_MIN` (10000)
added to a base, in `lib/workload_addr.py`. There is no registry and no
allocation step, so uniqueness comes from the uid allocator. For uid 10004:

| Value | Base | uid 10004 | Reached by |
|---|---|---|---|
| management address, port 2222 | `127.128.0.0` | `127.128.0.4` | `exec` and `shell`, through passt |
| broker, port 8081 | `127.129.0.0` | `127.129.0.4` | the workload's inspector only |
| responder, port 53 | `127.130.0.0` | `127.130.0.4` | passt's or pasta's DNS forward only |
| inspector, ports 8080 and 8443 | `198.18.1.0`, and `2001:2::` with the IPv4 address in the low 32 bits | `198.18.1.4`, `2001:2::c612:104` | the redirect |
| nflog group | 1000 | 1004 | `pcap`'s host vantage |

The rows are `UidDerived` entries collected in `UID_DERIVED`, and
`RESERVED_RANGES` is derived from them: 127.128.0.0/9, which covers the
three loopback rows, 198.18.0.0/16 and 2001:2::/48. `reserved_range` stops
`[vm.network].ports` binding into them, and `allow_reserved_reason` stops an
`allow` entry naming an inspector address, which would otherwise be accepted
ahead of the cross-workload guard.

The broker and the responder are on loopback because a guest cannot reach
the host's 127/8: passt runs with `--map-host-loopback none`, and a guest's
own 127/8 is its own. The only ways in are passt's DNS forward to the
responder and the inspector's dial to the broker. 127/8 needs no address
assigned, so neither has an address-add step.

The inspector cannot be on loopback. Guest traffic re-originated toward a
remote address cannot be DNATed to 127/8 without `route_localnet`, a
host-wide loosening, so its addresses go on a dummy link, `wl-egress`
(`EGRESS_IFACE`). `ensure_egress_interface` creates the link with no
address of its own, idempotently, and nothing ever removes it. Each
workload's /32 and /128 are added on start and removed on stop, so an address
on the link means a workload that should be running. On a dummy link the
addresses are local but not loopback, which is why the filter table has an
input chain dropping these ranges on any interface but `lo`.

Every passt VM, filtered or open, also gets its own inspector address on the
link at start from `workload-vm-svcaddr` (`lib/svcaddr_arm.py`), so a host
service can publish there for an open guest to reach. The guest learns it
from the seed variable `WORKLOADCTL_VM_INSPECT_ADDR`. A filtered guest cannot
use it: its own address is guarded on every port the inspector does not
serve.

## The nftables tables

Two tables, each applied from a skeleton in `nftables/` on every start that
needs it. Both files are idempotent and each load is one transaction, so
concurrent starts cannot interleave.

- `inet workload_filter` (`workload-filter.nft`): the output chain, at filter
  priority 0 ahead of firewalld, and a small input chain. Applied by every
  inspect `up` and every filter `up` but a bridged VM's.
- `inet workload_redirect` (`workload-redirect.nft`): the redirect, a nat
  output chain at priority `dstnat`. Applied by inspect `up`.

Units add and remove set and map elements; they never touch a rule. The one
exception is `pcap`, which creates its own `pcap_output` and `pcap_input`
chains on demand, because the skeleton flushes its own chains on every load.

| Object | Table | Key | Armed by | Holds |
|---|---|---|---|---|
| `wl_filtered` | filter | uid | filter `up` | every filtered uid |
| `wl_allow4`, `wl_allow6` | filter | uid . address . port | filter `up` | `allow` entries |
| `wl_inspect4`, `wl_inspect6` (maps) | proxy | uid . port → address . port | inspect `up` | the redirect, two per family |
| `wl_inspect_dst`, `wl_inspect_dst6` | filter | uid . listener address . listener port | inspect `up` | the redirected connection, as the filter sees it |
| `wl_inspect_self`, `wl_inspect_self6` | filter | uid . listener address, with a counter | inspect `up` | the workload's own listener, for the wrong-port guard |
| `wl_inspect_live`, `wl_inspect_live6` | filter | address | inspect `up` | every armed listener address, for the cross-workload guard |
| `wl_internal_ok4`, `wl_internal_ok6` | filter | uid . address | inspect `up` | `internal` addresses, and the broker's own address |
| `wl_internal4`, `wl_internal6` | filter | address intervals | the skeleton | the private ranges; constant, flushed and reloaded |
| `wl_egress_cg` | filter | cgroup, level 2 | the inspector service | the inspector, exempt from the default deny |
| `wl_inspect_cg` | proxy | cgroup, level 2 | the inspector service | the inspector, exempt from the redirect |

### The two cgroup elements

The inspector runs as the workload's own uid, so `meta skuid` cannot tell its
upstream connections from the workload's. Its control group can: systemd
assigns it, nothing in the workload can enter it, and because the service
pins `Slice=workloads.slice`, its path is always the two components
`workloads.slice/workload-<name>-inspect.service`, which is what
`socket cgroupv2 level 2` matches. The responder is not a member of either
set because it originates nothing.

Both elements are armed by the inspector **service**'s own `ExecStartPre`
and removed by its `ExecStopPost`, not by the socket's helper. An element
resolves a cgroup path to an id when it is added, and systemd creates a fresh
cgroup on every start, so the add has to happen after the cgroup exists and
the remove while the path still resolves. A leftover from an unclean stop
names an id the kernel never reuses, so it matches nothing. Both or neither:
without `wl_inspect_cg` the inspector's dials are redirected into itself, and
without `wl_egress_cg` they meet the default deny.

### Purge, then add

Every `up` removes the workload's existing elements before adding the
configured ones, so what is armed is a function of the current config alone.
Filter `up` calls `nft.purge_uid_elements`, which enumerates `wl_filtered`
and the allow sets and deletes everything keyed on the uid; nft has no
delete-by-prefix. Inspect `up` deletes its eight elements and then purges the
`internal` exemptions by uid with `nft.purge_internal_exemptions`, reading
them back from the kernel rather than re-resolving names whose answers may
have changed. Purging by uid matters because uids are reissued: an element
left behind would be armed for the next workload to get that uid.

## The redirect and the two planes

The proxy table's one chain does two things. A connection from a socket in
`wl_inspect_cg` returns unchanged, so the inspector's own dials are never
redirected. Any other TCP connection to port 80 or 443 is DNATed through the
map, keyed on `meta skuid . tcp dport`. A uid with no element misses the
lookup and passes through, so only inspected workloads are redirected, and
the destination address is not part of the key, so a workload that dials an
address directly is redirected like one that resolved a name.

Each redirected port is a **plane**, defined in `moatery.egress_plane`:
cleartext, 80 to 8080, and TLS, 443 to 8443. The inspect socket binds four
`ListenStream=` lines, both families times both planes, and the inspector
learns the plane from which socket accepted the connection. The plane is what
`egress --plane` filters on.

## The path a request takes

Follow `web`, uid 10004, running `curl https://api.example.com`.

The guest asks its resolver for `api.example.com`. passt forwards the query
to `127.130.0.4:53` as a socket owned by uid 10004, which the output chain
accepts on `oif lo` to 127/8. The responder answers `198.18.1.4`.

The guest connects to `198.18.1.4:443`, and passt opens the matching host
socket as uid 10004. The nat chain runs first, at `dstnat` (−100): the socket
is not in `wl_inspect_cg`, the port is 443, and the map turns
`10004 . 443` into `198.18.1.4 . 8443`. The filter output chain, at 0, sees
the translated destination and walks these groups in order:

1. A non-terminating rule sets the connection mark from the uid, for any
   workload uid, filtered or not. Inbound packets carry no uid, so this mark
   is how `pcap` attributes them.
2. Reply-direction packets from a filtered uid are accepted, ahead of every
   destination-keyed drop.
3. `wl_allow4`/`6` accept the operator's `allow` entries.
4. `wl_inspect_dst`/`6` accept the redirected tuple, which is where this
   connection is accepted.
5. The listener guards: `wl_inspect_self` drops a workload's dial to its own
   listener on a port the inspector does not serve, with a per-workload
   counter, and `wl_inspect_live` drops any non-root uid's dial to another
   workload's listener. Root is exempt so `diagnose` can probe.
6. For the inspector's cgroup only: port 53 is accepted, then
   `wl_internal_ok`, then connections the inspector opens to `wl_internal`
   are dropped.
7. Loopback destinations (`127.0.0.0/8`, `::1`) from a filtered uid are
   accepted: the management address, the responder and a stub resolver.
8. The inspector's cgroup is accepted to anywhere else.
9. UDP 443 from a filtered uid is dropped on a counter of its own, so
   HTTP/3's silent fallback can be told apart.
10. Everything else from a filtered uid is dropped, on one counter shared
    by every filtered workload.

The packet arrives on `lo`, passes the input chain, and the socket unit
hands the connection to `moat-inspect`. The inspector reads the ClientHello,
matches `api.example.com` against the policy, and opens its own connection
to the origin, as uid 10004 from its own cgroup. The nat chain returns at
the cgroup rule; in the filter chain the inspector's lookup is accepted in
group 6 and its connection in group 8, unless the origin resolved into a
private range, where group 6 drops it and the guest receives a 502.

If the host's policy entry names a credential, the inspector does not dial
the origin at all. It dials `127.129.0.4:8081`, plain HTTP over loopback.
That address is inside 127/8 and so inside `wl_internal4`, which group 6
would drop; inspect `up` arms it in `wl_internal_ok4` for any workload with a
broker, and that element is what lets the dial through. The broker runs as a
dynamic uid in 61184–65519, outside the workload range, so nothing in the
output chain matches its connection to the provider. Its only egress bound is
its unit's `IPAddressAllow=` and `IPAddressDeny=any`.

A TLS dial to an address literal is redirected by port and reaches the
inspector with no server name, so it is dropped there. A guest packet to another
workload's listener meets group 5. QUIC meets group 9. Anything else not
allowed meets group 10.

## The broker

### Identity

A broker instance serves one caller, the uid on its `--caller-uid`. The
source address cannot identify a caller: passt re-originates every guest's
traffic from the host, so every VM reaches a host service from the same
address. `moatery.peer_identity` instead finds the row in `/proc/net/tcp`
whose local and remote endpoints mirror the accepted connection, and reads
its owner. The local side is matched against a set, the bound address and
the `SO_ORIGINAL_DST` of the connection, so the match survives a DNAT in
front of the broker. Only rows for live connections are trusted (a TIME_WAIT
row reports uid 0), and an unresolved caller is refused.

The unit must not set `PrivateUsers=`. `/proc/net` translates the owner
through the reader's user namespace, so from a restricted namespace every
caller reads as the overflow uid and they all merge into one, with no error.
The broker refuses to start when it can prove this and warns when it cannot.

Identity and reachability are separate checks. The per-instance address
decides who can reach an instance at all, and the uid decides whether the
caller on a connection is the one the instance serves. The inspector's
listener uses the same module to check each of its own callers, refusing any
uid but its workload's, root included. It admits a caller it cannot resolve
and counts it, because socket rows can vanish under load, but refuses one
that closed before it could be identified.

### Admission

The upstreams are fixed by the `--host` flags and never taken from a
request. A request's `Host` selects among those rows, and one naming no row
is a 403; an absolute-form target is a 400. Credential headers from the
caller are stripped and the real one set; other headers pass unless they are
on a denylist.

An instance accepts 128 concurrent connections, all available to its one
caller, plus 8 shared by every other uid together, so idle sockets from
elsewhere cannot exhaust it. Past the bound a connection is closed without a
reply. A connection idle for 60 seconds is dropped. Request bodies are
buffered whole, up to 64 MiB each and 256 MiB across all callers, reserved
on the declared `Content-Length` before the bytes are read; past that a
request is a 503. Chunked request bodies are refused with 411. An upstream
failure is a 502 while the broker still owns the response, and a cut
connection once the upstream's status has been relayed.

### Host integration

`gen_egress.generate_broker_service` writes the unit with `DynamicUser=yes`,
so the material is decrypted into a tmpfs owned by a uid disjoint from the
workload's: a guest that escapes into QEMU, which runs as the workload user,
cannot read it. One `LoadCredentialEncrypted=<seal name>:<path>` line is
written per declared credential. The seal name, `broker-<workload>-<name>`,
is bound into the ciphertext by `systemd-creds`, so a unit pointed at
another workload's file fails to decrypt instead of loading that workload's
key. `IPAddressAllow=` lists `localhost`, the host's nameservers from
`/etc/resolv.conf`, and the addresses each brokered host resolved to when the
unit was generated, which go stale if the provider moves until the unit is
regenerated. There is no config file and no `ExecStartPre`: everything is on
the command line, and nothing on it is secret.

## How the generator writes moatery's flags

Three functions build the argv of the three daemons, and each value is
quoted with `dq` on the `ExecStart=` line:

- `gen_egress.inspect_listener_command`: `--name`, `--policy`,
  `--state-dir`, `--status`, `--record` and `--broker`. `--broker` is always
  written, so a later edit that adds a credential needs no regeneration of
  the inspector's unit.
- `gen_egress.resolve_command`: `--name`, `--address` (the inspector's IPv4
  address, which every synthesised answer names), `--policy`, `--static` and
  `--status`. There is no IPv6 answer address, so AAAA queries get no
  records.
- `broker_config.broker_command`: `--name`, `--listen`, `--caller-uid`, one
  `--host HOST=SEAL` per brokered host (collapsed, since one host may appear
  in several policy entries), and `--placeholder`, `--auth-header` and
  `--auth-format` per selected credential, each written only when the
  credential block states it, so the defaults stay the broker's.

The broker's address and port are computed once, by `broker_listen_address`
and `BROKER_INSTANCE_PORT` in `lib/workload_addr.py`, and written onto the
broker's `--listen` and the inspector's `--broker`. Neither daemon derives
them, and a mismatch would look exactly like a broker that is down;
`tests/test_broker.py` asserts the two units carry the same pair.

## The seam test

`tests/test_moatery_seam.py` holds the workloadctl half of the interface with
moatery, against the installed programs or a checkout named by
`MOATERY_CHECKOUT`. It checks that every name imported from moatery is one
moatery publishes; that every key the renderer writes into the policy
document is a key moatery's loader reads; that the generator hands each
program every flag it requires, and that the program accepts each one; that
the responder's status is read only by published keys; that the CA mint
writes where the inspector reads; that the broker reports ready only once it
is listening; and that the units name moatery's programs and the spec
requires a moatery that has them. moatery's own suite holds the other half.

`tests/test_nft_selector_intent.py` pins every rule in the output chain to
the selector its purpose needs, uid or cgroup, since picking the wrong one is
a silent hole or a silent outage.

## The arming programs

`lib/inspect_arm.py` and `lib/filter_arm.py` are each one body over a small
`Substrate` dataclass, with a `VM` and a `CONTAINER` instance holding what
differs: where the network table is, the predicate, the renderer, how
`internal` or `allow` entries are read and resolved, and the wording of
failures. The four `libexec/workload-{vm,container}-{inspect,filter}`
scripts bind a substrate to the shared `up` and `down`, so the code that
writes to the kernel exists once.

Inspect `up`, as the socket's prestart:

1. loads the config and returns if the substrate's predicate says the
   workload is not inspected;
2. writes the policy document and clears the previous run's status file;
3. ensures the dummy link and applies both skeletons, since the filter table
   holds guard sets and this unit runs before the head's filter `up`;
4. adds the workload's listener addresses;
5. deletes and re-adds its eight elements: both maps, both accept sets, both
   self sets, both live sets;
6. purges the `internal` exemptions, resolves every `internal` name, adds the
   broker's address when the workload has a broker, and arms them. An
   unresolvable name, or one resolving outside the private ranges, fails the
   start with a message saying that it is the workload's start that failed.

Inspect `down` deletes the eight elements, purges the `internal`
exemptions and removes the listener addresses. It cannot remove the cgroup
elements, which the service's own stop has already handled, and it never
touches the link.

Filter `up`, as the head's prestart, applies the filter skeleton, purges the
uid's elements, returns if the workload is not filtered, resolves the
`allow` entries once, arms them, and, when the workload has a responder,
writes the static map from that same resolution. The nft elements and the
responder's answers come from one lookup, because a second lookup of a
round-robin name could send the workload to an address the set does not
hold. Filter `down` purges the uid.
