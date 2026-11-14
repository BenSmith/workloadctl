# Manual rigs

Checks that need a real host and cannot run in the normal suites. Nothing
here runs under `just test` or `just test-runtime`; each is invoked by hand on a
host that has the workloadctl RPM installed. A run's result, and what each
break flag or deliberate break showed, goes in the commit message of the
change it proved.

## Writing a row here

These rigs exist because unit gates do not see the seam. They have blind spots
of their own, and every rule below was paid for by a defect that shipped past a
green rig. Read this before adding a row.

**Probe the window, not the settled state.** A row shaped enable, recreate,
sleep, probe is blind to a control that arms *too late*. If the egress arming
ran after a workload's containers started, the workload would run unfiltered
and become filtered mid-flight; by the time anything is probed, that is
indistinguishable from correct. The class is general and it is most of what
these rigs guard: a filter, a policy load, a seccomp profile, a cgroup move can
all be right and late. If a row sleeps before it measures, ask what it would
miss.

**Assert the ordering, not the presence of a string.** A containment check
(*"the arming appears in this unit"*) passes for any unit ordered after the
members. Read systemd's **parsed** state — `systemctl show <unit> -p
ExecStartPre` and friends — not the generated file: only the host says what the
manager actually loaded, and the two differ after an RPM upgrade without a
regenerate, which is the state the `%post` scriptlet warns about. Where an
observation is available rather than a configuration reading, prefer it;
`ExecMainStartTimestampMonotonic` is comparable across units.

**Pin the premise as its own row.** "The arming is on the head unit" only
matters because the umbrella runs late. Without a row asserting *that*, the
remedy is a preference, and a future change could quietly make it pointless.
The premise row is usually the one worth writing first.

**A row can assert the defect and pass on it.** A row that pins a product
message is green over a bug once the message becomes the wrong one — the
sentence an *uninspected* workload gets, say, printed for an inspected one.
When a product message changes, the row that pinned it must be **re-derived
from what the message should now say**, not edited until it goes green again.
A row that only ever had to pass is a row that has stopped measuring.

**Ask what a "needs another host" row actually needs.** Usually it is a
*fixture*: a veth, an `/etc/hosts` line, a routable address in a namespace.
Ask what property the row needs before asking for a machine.

**And check the fixture cannot satisfy the property by accident.** An origin on
a dummy link is *local*, and `oif lo` accepts a filtered uid's traffic
unconditionally — so a row measuring a drop would measure the loopback
exemption and pass. Put fixtures behind the veth. Where a row asserts
something is blocked, add a **control row** proving an unblocked caller reaches
the same fixture: without it, a responder that never started satisfies every
assertion in the section.

**A drop is not always a timeout.** An output-chain nft `drop` rejects a
*local* sender synchronously, so a blocked UDP send fails with `EPERM` rather
than hanging. Prefer that reading where it is available — an absent reply is
also what a dead fixture looks like; `EPERM` is not. Conversely
connection-*refused* means the packet arrived and nothing was listening, which
is a broken fixture reporting itself as a working filter, and must never count
as blocked.

**Iterate under enforcing, never permissive**, and assert on `audit.log`
directly rather than on functional success — a silent denial leaves the feature
working and the counters reconciling. `ausearch -ts boot` is unreliable on at
least one host here; grep the log.

**A rig's own config decays.** `tests/test_manual_rig_configs.py` parses and
validates the TOML every rig generates, so a config the schema has moved past
fails in `just test` rather than at `enable` on a hardware trip, where it looks
like the thing under test.

## broker_rig.py — does a guest get a key it never holds, and can two brokers tell each other's callers apart?

Needs root, KVM and the workloadctl RPM installed. Boots **two** throwaway VM
workloads, runs a stub provider on the host, and probes from inside each guest
and from the host as each workload's own uid.

```bash
sudo python3 tests/manual/broker_rig.py
```

**Four claims, on two workloads.** The arms differ in exactly one line — which
credential they name — so a difference in what comes back has one available
explanation.

1. A guest reaches a credential-backed host holding a placeholder and never the
   key. Asserted from both ends: the stub reports which `Authorization` arrived,
   and the guest is asked what its whole environment holds. Either half alone is
   satisfied by a broker that attached nothing.
2. A `Host` the broker does not know is refused.
3. A guest dialling `127.129.x.y` directly reaches its own loopback and finds
   nothing — which is the whole of "the guest is never told where the broker
   is", given that the address is derivable by anyone who reads the source.
4. Two workloads get different credentials from two instances. Only this one
   needs the second workload.

**Claim 2 is probed from the host as the workload's uid, not from the guest, and
that is not a shortcut.** A guest cannot construct the request: the inspector
dials the broker only for hosts the policy names with a credential, and
validation refuses a wildcard on such an entry, so every `Host` that can reach a
broker *through a guest* is one the generated config named. The refusal is real
all the same — it is what stands between a compromised inspector and a key
attached to a destination of its choosing — so it is probed where it can be
reached from. Three controls make it mean what it says: the same dial with the
`Host` the config *does* name must return the credential (or the 403 proves only
that nothing was listening), the same dial as **root** must be refused *for its
caller* (or the 403 is consistent with a broker that has stopped checking who is
calling), and the same dial as the **other workload's** uid must be refused too
— both instances are on the same host's loopback, so nothing but the uid check
keeps one workload's caller out of the other's credential. Both refusals are
403, so each assertion matches the broker's sentence rather than the status.

**The arms cover the shapes a generated config has to express.** One arm takes
the default auth convention (`x-api-key`) and the other overrides it
(`Authorization: Bearer`), so one run covers both `[[vm.network.credential]]`
keys. Both split one host's rules across two policy entries with one
credential — `/v1/*` for GET, `/v2/*` for POST — the ordinary way to write a policy,
which has to collapse to one `--host` on the broker's command line because the
broker refuses a repeated host.

**No `[[vm.network.internal]]` exemption, deliberately.** For a brokered host
the inspector never dials the origin; it dials the broker on loopback. An
origin dial would make the origin's reachability and certificate a
prerequisite for a request that goes to loopback, and with no exemption the
first probe would fail with `internal destination`. That absence is the only
check on hardware that the origin dial stays gone.

**What the host-side scaffolding costs.** The broker's upstream is
`https://<the Host>` with no override — deliberately, so a policy-matched path
cannot be prefixed on the way out — so the provider has to answer at that name
on 443. The rig writes one `/etc/hosts` line and serves the stub on 443 at
`10.99.97.30`, inside a network namespace of its own reached over a veth, and
removes all of it at teardown; a VM host running a reverse proxy already holds
its own `127.0.0.1:443`. The stub's certificate is handed to each broker
instance through `SSL_CERT_FILE` in a drop-in rather than installed into the
host trust store: the trust decision stays the broker's, made the way it always
is, and the rig leaves no trust anchor behind on a machine it borrowed. Nothing
about the path under test is weakened — the drop-in adds one environment
variable and changes no directive.

**The guard rows read the manager's parsed `ExecStart=`, not a file.** The
broker takes everything as flags on the generated unit: there is no config
file, no `ExecStartPre` and no runtime directory. Four rows on `systemctl show
-p ExecStart`: the line names the workload's own uid and address; it carries
the placeholder (the positive half, so the next row measures something); it
carries no secret (it is on a world-readable unit, so this has to be true
rather than arranged); and `ExecStartPre` is empty and the runtime directory
absent.

**It also reads two things no probe can show.** The inspector's own record:
`upstream` is honestly the broker's loopback address on a brokered request and
`credential` names the material that rode along, which is what makes a loopback
upstream legible rather than alarming. And the audit log, because a denial on
the inspector's dial to the broker's port is silent by construction: the
connect fails, the listener counts a dead broker, and the guest gets a 502
naming the broker, which is exactly what a genuinely dead broker produces. The
same presentation comes from the broker's address, `127.129.x.y`, falling
inside `wl_internal4` without its exemption. A green run of the four claims
does not establish that the grant is present, only that nothing needed it yet.

## self_dial_rig.py — does the wrong-port counter count, and does `diagnose` say so?

Needs root and a host with at least one workload uid; **no KVM and no VM**,
everything happens in a throwaway network namespace. Install the RPM first — it
reads the installed skeleton and imports the installed modules.

```bash
sudo python3 tests/manual/self_dial_rig.py
```

Three things have to hold and only the first has a unit test: the parser reads
the element shape a counted set renders, the kernel increments that element on
the dropped packet, and `diagnose` gets from the host's nft to the printed
line. The second is why this exists — `meta skuid` cannot be exercised without
a process that really owns the uid, so nothing under `just test` can send the
packet, and a counter that never increments looks exactly like a guest that
never self-dialled. The third is the seam.

**The element shape is the trap.** A set carrying `counter` renders its
elements wrapped, `{"elem": {"val": {"concat": [...]}, "counter": {...}}}`,
where an uncounted set renders them bare. `owned_elements` matches the bare
shape and so finds nothing at all in these sets. The rig reads a real
incremented counter through the real reader, which is the only way to know the
wrapped path was taken rather than assumed.

**Two controls carry the rig.** A dial to a *served* port must not be counted —
a self rule that caught those would drop every guest's own inspector traffic,
which is the failure the rule ordering exists to avoid. And a *root* dial to
the same address and port must not be counted: without that one, every other
assertion still passes against a rule that has lost `meta skuid` and is
dropping the address for everyone, host tooling included. Absent and zero are
also held apart — an unarmed element reads as absent, not as zero.

## inspect_rig.py — does a guest told nothing land in the inspector?

The one thing about transparent inspection that only a real boot can show.
Needs a KVM host with the workloadctl RPM installed; it boots two throwaway VM
workloads and probes them from inside, then purges them. Run it under
**enforcing**, not `semodule -DB`: a permissive or dontaudit-disabled pass
measures the branch that ran, and an earlier denial changes which branch that
is.

```bash
sudo python3 tests/manual/inspect_rig.py
sudo python3 tests/manual/inspect_rig.py --quiet   # failures and the tally only
```

`--quiet` is for reading a run back over ssh rather than watching it: a green
run collapses to one tally line. Failures are never suppressed — each prints in
full, under the section header naming the phase it was in, and an escaping
exception prints that header too. `tests/test_manual_rig_quiet.py` pins that,
because the branch that matters here only runs on a KVM host and only when
something is already wrong.

**Two guests, differing in one config line.** The `plain` arm is filtered with
no `hosts`, so nothing is allowlisted and every dial to 80/443 is DNAT'd onto
the listener and dropped there — the redirect's own claim, isolated from any
question about what policy then says. The `hosts` arm is the allowed path: a
dial to an allowlisted name is forwarded (cleartext) or spliced (TLS) and comes
back 200. Nothing else in the rig walks the inspector's *upstream* leg, so
without that arm the forward and splice code paths never execute under SELinux
at all. The single-line difference between the arms is what makes a failure
attributable to one half or the other.

**The negative half is the guest's.** The plain arm also dials
`192.0.2.1:3128` and asserts nothing answers, then sets `https_proxy` to that
endpoint and asserts a real `curl` through it fails. A workload whose image
bakes in a proxy export has to get a hard failure rather than a client that
quietly falls back, or the transparent path is not the only path out.

**The cgroup exemptions are matched per arm, after the probes.** An inspector
missing from `wl_inspect_cg` dials into itself, and **no unit test can see that
fail**, because the element resolves a cgroup id at add time. The inspector is
socket-activated and both cgroup elements are armed by the *service*'s
`ExecStartPre`, not the socket's — a socket-bound but unstarted service has no
cgroup to resolve — so the sets are legitimately empty until the first guest
dial. The check runs after `probes()` and matches the exact cgroup path per
arm in *both* sets (`wl_inspect_cg` for the redirect, `wl_egress_cg` for the
default-deny), because the invariant is both-or-neither and a bare count of
`>= 1` is satisfied by one arm while the other dials into itself.

**The record's seam.** A live guest makes an *allowed* cleartext request to an
allowlisted host with a per-run marker in its path, and the rig then reads it
back through `workloadctl egress` — the same command an operator would type.
The file exists with the modes and owner the design claims (`0700` directory,
`0600` file, both `_wl-<name>`), the allowed request is in it, its `id` is the
id on the journal line for the same connection, `--id` selects that connection
alone, the plain arm's denial carries the `reason` that says *which* denial it
was, a non-root read is refused with a sentence rather than a traceback, and an
unknown `--reason` is an error rather than an empty report.

Nothing in `just test` reaches any of that. The writer is unit-tested against a
fake listener and the reader against a fixture directory, and **both stay green
on a host where the file is never created** — a wrong `LogsDirectory=`, a
missing SELinux label, or a denied write swallowed by the handler that must
never let a diagnostic kill a guest request all look identical from there. The
*allowed* request is the one under test on purpose: refusals already reach the
journal, so a record holding only refusals would be a green reading that says
nothing about the path the private sink exists for.

**The staleness seams.** Three comparisons between a value a *running* process
holds and a value on disk, which is a shape the unit suite can only test
against injected observations: the listener reports a policy digest at all,
that digest is the digest of the document on disk, a healthy workload is *not*
reported stale, an edited document *is* — and its remedy names the VM rather
than the socket — the edit is then restored and the report goes quiet again,
all four filter-table sets carry the workload's uid, and the CA fingerprint the
minter reports equals a fresh `openssl x509 -fingerprint -sha256` of the file,
with an expiry beside it.

**Every one of these comparisons treats an unknown as silence**, deliberately,
so that a diagnostic never manufactures a failure out of a missing diagnostic.
A digest the listener could not write, a set name that drifted, an `nft` the
CLI's domain may not exec — each produces exactly what a healthy host produces.
A comparison that never runs and a comparison that always agrees are the same
green line, and only a live host distinguishes them.

The policy edit is destructive and is undone in a `finally`, with the undo
*asserted* rather than assumed. A rig that breaks the product and then dies
leaves the next run measuring the break.

**Ordering against user creation.** A first enable has to produce VM units and
a working inspect socket on a host where `_wl-<name>` did not exist a moment
before: the generator must not need `getpwnam` for a user it has only just
written the sysusers config for, and the socket is ordered
`After=workload-<name>-setup.service`. A unit test that mocks `getpwnam` cannot
see either.

**Status files.** Both producers keep counters and write them into the VM's
runtime directory, and that write is guaranteed never to raise: a failure is a
journal warning and nothing else. So a confined domain with no grant on that
directory produces precisely what a working one produces — green suite, green
rig, no file. `status_files()` therefore looks for the file itself, checks the
stamp is fresh rather than merely present, and dials again to confirm the
counters *move* (a file written once at startup and never again is a producer
whose every later write is failing). It waits out `STATUS_INTERVAL` (30 s)
before reading a tick, since a pre-loop write is zeros, freshly stamped,
identical to a broken counter. A policy grant on the runtime directory needs
`rename` too, which `os.replace` needs.

**Domains.** `moat-inspect` runs as `wlinspect_t` and the responder as
`wlresolve_t` (`security/workload-resolve.cil`); without its own domain the
responder would run as `unconfined_service_t`, parsing guest-supplied DNS
wire format with nothing failing. On a permissive host every check in this
group passes trivially, so the rig says so out loud rather than reporting a
green it has not earned.

**Stale status across a restart.** The runtime directory is
`RuntimeDirectoryPreserve=yes` (so a restart does not yank the qmp and console
sockets out from under the sidecars) and both producers are socket-activated,
so after a restart the file on disk belongs to the previous boot with no
process running to correct it. `written_at` cannot tell that apart from a live
producer idle since the same moment. The arming helpers clear it, and this is
the only check that can see that wiring — it needs a real preserved directory
surviving a real restart. The inspect service is
`PartOf=workload-<name>.service`, so a VM restart restarts the producer, which
writes a fresh snapshot with no dial needed; the property is that the previous
instance's COUNTS cannot survive. The check makes drops non-zero first, then
asserts the post-restart file is absent or all-zero *before* anything dials the
restarted guest.

**IPv6 on a host with no uplink.** The rig installs a temporary route to the
probe address over the inspector's dummy link and removes it afterwards;
without it the v6 probes die at the routing lookup, before nftables is
consulted, which looks like a redirect defect and is not. That route makes the
guest's v6 source address come off the `wl-egress` link, which carries every
workload's listener address — so the listener logs a `peer=` that is some
*other* workload's plane. It is an artifact of the rig's own route, not a
policy finding: the guards match on destination, and a host with a real v6
uplink sources from a global address.

**A name resolves to IPv4 only.** passt's DHCPv6 hands the guest a host IPv6
address, and on a host with no v6 uplink the only global ones are the
inspectors' on `wl-egress`. A responder answering AAAA with that address would
send every by-name dial to v6 first, refused inside the guest in a millisecond;
the fetch rows would stay green over it, because curl falls back to v4. So no
responder is handed `--address6`, and the row reads `getent ahosts` and prints
the guest's own v6 addresses beside it, so a run on a host with a real uplink,
where the trap is not set, says so.

### Harvesting the missing policy

Do the `semodule -DB` pass *first*, not after several enforcing iterations.
Shipped policy dontaudits some rules this domain needs, and a missing one can
surface only as a systemd error message naming no SELinux concept at all.

```bash
sudo semodule -DB                        # disable dontaudit, rebuild
sudo python3 tests/manual/inspect_rig.py # provoke the denials
sudo semodule -B                         # restore dontaudit when done
```

Read the denials out of `/var/log/audit/audit.log` directly; the rig remembers
a byte offset into the file rather than asking `ausearch` for a time range. An
empty result from `audit_denials()` means "nothing in the audited set" and is
not proof the domain is complete.

## input_chain_rig.py — two measurements of packets crossing a real kernel hook

`just test` cannot reach either: one asks whether a drop rule stops traffic
that has never been sent, and the other counts what a capture actually holds.

Unlike the VM rigs it needs **no KVM and no VM** — everything happens in
throwaway network namespaces, so it runs anywhere `ip netns` and `tcpdump` do.
It reads the installed skeleton, so install the RPM first.

```bash
sudo python3 tests/manual/input_chain_rig.py
```

**The off-box drop.** The input chain's `iif != lo ... daddr <plane> counter
drop` has two halves. The loopback half is implied by any green `inspect_rig`
run — if the exemption were wrong, no guest dial would reach the listener. The
off-box half is implied by nothing: the unit tests assert the rules carry
`counter`, which is that the keyword is present, not that it ever increments.
The rig sends a packet in over a veth from a peer namespace, which is the only
way to produce `iif != lo` without another machine.

**The capture doubling.** `pcap_output_rule` and `pcap_input_rule` log to the
same nflog group, and a host-local packet crosses both hooks: 10 packets on the
wire are 18 in the file, `pcap_output` 8 + `pcap_input` 10. So the loss check
has to sum both counters, and the inflation is **2x, not 4x** — the 4x needs a
second leg, which arrives only when the inspector re-originates.

Every packet a socket sent is captured twice; bare ACKs the kernel emits on its
own behalf appear once, because there is no owner for `meta skuid` to match.

## clock_rig.py — what a vCPU pause does to a guest's clock, and whether a wrong clock costs the guest its egress

```bash
sudo python3 tests/manual/clock_rig.py       # --keep leaves the guest up
```

Needs root, `/dev/kvm`, the workloadctl RPM and the same
`/var/lib/broker-rig/base.qcow2` the other VM rigs use. Boots **one** throwaway
filtered VM workload **with its egress inspector on**, measures its clock
across a QMP `stop`/`cont`, tries both forms of the guest agent's
`guest-set-time`, drives a real HTTPS request from a guest whose clock is
deliberately wrong, and then skews it again with nothing dialling and waits for
the clock keeper. Twelve minutes end to end, most of it the 120-second pause,
cloud-init's first boot, and two waits on a one-minute timer.

**Why it exists.** The inspector mints 30-day leaves for the guest to validate,
which puts the guest's clock on the critical path for all of its traffic. Drift
is a non-issue — about 10 ppm, four orders of magnitude inside a leaf's window
— but a *pause* is not: the guest loses the pause exactly and never gets it
back, and the 1-hour `notBefore` backdate covers roughly 1,200 years of drift
and exactly one hour of pause. Past that, every freshly-minted leaf has a
`notBefore` in the guest's future and validation fails on every request while
`diagnose` reports a healthy VM.

**One of the two paths that reaches it is ours.** `workloadctl backup
--consistency crash` issues QMP `stop`, copies the qcow2, and `cont`s in a
`finally`, resyncing nothing — so the guest is left behind by the copy duration,
bounded by disk size and storage speed rather than by any check. The rig pauses
over the same socket in the same order, so it is measuring that operation and
not an analogue of it.

**The guest is filtered on purpose.** An `egress = "open"` guest would resync
over NTP and measure nothing. The rig records that NTP is dead first, because
that premise is invisible from the host: `chronyd` stays `active` while
`chronyc tracking` reports stratum 0 and a 1970 reference time.

**Offsets are reported as intervals, not numbers.** The guest's clock is read
somewhere inside the `workloadctl exec` round-trip, so the reading is bracketed
by two host reads and the interval's *width* is that latency. The upper bound is
the stable one; the lower tracks the round-trip.

**The `ptp_kvm` arm needs a host this rig does not control**, and that is the
one thing to check before reading a result. `ptp_kvm` answers only where the
**host's** clocksource is the TSC; on `hpet` or `acpi_pm` the module refuses to
load in every guest and measurements 3, 3b and 3c skip, saying so. Check the
candidate host rather than assuming.

**The guest-side arm.** `/dev/ptp_kvm` appears, chrony selects it as a refclock
(`#* PHC0`) with `makestep 1 -1`, and the guest repairs a 120-second pause by
itself within about half a minute. Measurement 3c then turns the remedy off,
and the rest of the rig measures the guest that a custom `user_data_file`
produces — one with no `ptp_kvm` wiring — rather than contriving a second
workload for it.

**The pause itself.** The step equals the pause to within tens of
milliseconds, the guest survives it, and **nothing puts it back** with the
guest-side remedy off. `guest-set-time` with **no argument fails** — it reads
the guest's RTC and returns `hwclock: select() to /dev/rtc0 to wait for clock
tick timed out`. The **explicit-nanoseconds form works**, inside the
measurement's own bracket, and is the remedy the clock keeper uses. The
no-argument form is recorded as an observation rather than a failure, so a
future QEMU or image that makes it work shows up as a change here.

**Measurement 7 measures the failure.** Everything above measures a clock; 7
measures what the clock is on the critical path *of*. With the clock keeper's
timer stopped (and recorded as stopped), it pushes the guest **two hours** back
— past the `notBefore` backdate, so a stale clock cannot validate a fresh leaf
by accident — and asks it for a name it has never asked for, so the leaf it is
handed is minted now. The handshake must **fail** with `certificate is not yet
valid`. Four corroborations say why it failed: the inspector's `mints` moved
(it signed the leaf and has no idea), the `mint` block carries no clock or
remedy figure (the inspector does not touch the guest's clock, and a key there
is that seam coming back), the guest is **still** two hours out afterwards
(nothing on the mint path touched it), and `workloadctl diagnose --json` fails
its `vm_guest_clock` line naming the offset — the operator's one view of a
guest the keeper cannot see or has not yet reached.

This arm needs the host to have real internet, unlike the rest of the rig — it
dials two names on the workload's allowlist.

**Measurement 8 is the remedy.** `workload-<name>-clock.timer` runs
`libexec/workload-vm-clock` once a minute for every VM, inspector or not, in
its own `wlclock_t` domain. The rig starts the timer on the guest 7 left
skewed and polls the offset for the keeper's period plus its accuracy. Then it
dials the name 7 failed on **again**: the same cached leaf must validate now,
on a cache **hit** (`hits` moves, `mints` does not), because the clock is what
changed and not the certificate. The tick is caught running with `wlclock_t`
in its label, the keeper's journal line appears exactly once, and `diagnose`
goes green on the same line it was red on.

**The domain is read off the live process, not the journal.** A oneshot leaves
no `MainPID` to ask, so the rig scans `/proc` at 20 Hz for the tick and reads
its `attr/current` before it exits, skipping systemd's pre-exec child, which
`/proc` names `(workload-vm-clock)` for a few milliseconds before execve and
which is still `init_t`. The obvious shortcut — journald's `_SELINUX_CONTEXT`
on the keeper's stdout line — reads `init_t` on every service that transitions
on exec, because for `_TRANSPORT=stdout` that field is the stream socket's peer
label, captured when systemd's pre-exec child connected it; `_COMM` and `_EXE`
on the same line are post-exec, which is what makes it convincing.

---

## reporting_rig.py — do the egress reporting surfaces tell the truth about a live guest?

`workloadctl rules`, `doctor`'s egress section and the exporter's inspector
series. Needs root, `/dev/kvm` and the installed RPM — `workloadctl` and
`workload-exporter` are invoked by name, off PATH and out of `/usr/libexec`,
exactly as an operator gets them. Two throwaway VMs: one filtered, one with
`egress = "open"`.

```bash
sudo python3 tests/manual/reporting_rig.py
sudo python3 tests/manual/reporting_rig.py --quiet   # failures and the tally only
```

**Why it exists when every figure has a unit test.** All three surfaces are
tested against documents written by hand. What no unit test can reach is
whether the document those readers open is the one a *live listener* wrote, at
the path it really writes it to, with the permissions it really writes it with,
and whether the numbers in it move when a guest actually dials something. Three
claims only a host settles:

- **`rules` reports origin `disk`.** Off a host every test takes the `config`
  fall-back, because there is no `/run/workload-vm/<name>/inspect.json` to
  prefer — so the preferred branch, and the 0640 root-owned read that goes with
  it, never executes against a file the listener wrote.
- **`doctor` and the exporter agree.** There is one producer, and the unit
  suite proves the two renderers agree about a hand-written document. Agreeing
  about a live one is a different claim: both must have opened the same file,
  through their own code paths, and come back with the same numbers.
- **The counters move.** A reader stuck at zero passes every assertion written
  against a document full of zeros. The rig drives an allowed request and a
  refused one and insists the figures changed.

**The policy is two entries over one host, and both state both keys.** Two
entries are the point — they union, neither overrides the other, and `rules`
has to print both against the one name, which is the composition rule the
report exists to make visible. Both entries state `methods` *and* `paths`
because `validate` refuses overlapping entries that omit one: an omitted key
means ANY, so the omitting entry silently permits everything its sibling was
narrowed to forbid.

**Admission is read off two status codes, not asserted directly.** Nothing
serves `api.example.com`, so the governed probes end 502 at the dial rather
than as policy decisions — and that is the signal, not a flaw: reaching the
upstream at all is what proves the host was admitted, while the unlisted probe
never gets that far and is refused at the allowlist with a 403. Whether a
permitted request is permitted and a forbidden one forbidden is moatery's
rigs' question, against a stub origin built to answer it.

**The unlisted probe uses `--resolve`, not DNS.** The synthesising resolver
answers only for names the lists carry, so an unlisted name never resolves and
never becomes a connection — the drop would be the *resolver's*, and the
inspector's `not allowlisted` counter would stay at zero. Every egress port is
redirected, so any address reaches the listener and the SNI decides.

### Reading a failure

Every probe's result is recorded, pass or fail. If the traffic line says a
probe returned nothing, read no further down: a guest that had not finished
booting produces no traffic, no socket activation and no status document, and
everything below it is measuring an inspector that was never dialled.

---

## container_egress_rig.py — does the container substrate actually filter?

Needs **no KVM**. Everything the VM rigs prove about the egress path is proven
on a guest; this asks the same questions of a container, where the traffic is
re-originated by pasta as the workload's own uid rather than by passt on a
guest's behalf. Needs root, podman and the installed RPM. Throwaway container
workloads, all prefixed `ceg-`. The row count is in the run's own output.

Use `--only=<section>,<section>` to iterate one arm; a full pass is about
40 minutes.

```bash
sudo python3 tests/manual/container_egress_rig.py
sudo CEG_LAN_HOST=192.0.2.10 python3 tests/manual/container_egress_rig.py
sudo python3 tests/manual/container_egress_rig.py --keep   # leave them running
```

**The ladder is walked on one workload, not built three times.** No
`[network]` egress key, then `hosts` only (spliced, no CA), then a
`[[network.policy]]` entry (refused until `ca_delivery` is stated, then
terminating) are three states of one file with a `workloadctl recreate` between
them. Three separately-enabled workloads would each prove their own end state
and say nothing about the *transition*, which is where a silently-gained CA
requirement would hide. It also settles the apply question by exercising it:
`recreate`, never `restart` — `restart` regenerates no units, and the
terminating transition adds a bind mount and five environment variables to the
podman argv.

**Both redirected planes, and the cleartext one first.** A rig that checks 443
and stops leaves plaintext HTTP unfiltered in a workload every report calls
filtered. The assertion on port 80 is not that the request succeeded but that
the record carries a `method` and a `path` — that the *Host header* was read,
not merely that the dial landed somewhere.

**The re-dial check is a stopwatch, not a return code.** A missing cgroup
exemption in either table does not error: one loops the inspector into itself
and the other filters its upstream leg like the workload's own, and both
present as a request that eventually times out. So the rig asserts the elements
are present *and* that a request which used them finished well inside a
wall-clock budget.

**`[[network.internal]]` is probed in both directions.** Testing only the
entry-present case would pass against an inspector with no internal-destination
guard at all — which is the guard that stops an allowlisted *public* name from
being pointed at your LAN. Without `CEG_LAN_HOST`, and if that host does not
answer on port 80 from the machine running the rig, this section **skips**: a
probe against an unreachable target fails identically to a working drop.

**One reporting surface is asserted to REFUSE; two more are measured, not
asserted.** `rules` is VM-only pending the container document renderer and its
refusal names the trigger, which is the shape a VM-only surface should have.
`drift` and `pcap` are merely *unrouted*, which is not the same as declining —
whatever they do, an operator meets it, so the rig records it rather than
guessing. `diagnose` gives a filtered container an inspector line like a VM's.

### Cross-workload inspector reachability

The rig dials the filtered workload's listener from an unfiltered container, on
the listener's real ports rather than through a redirect, and requires two
layers to stop it. `workload_filter` drops a non-root packet aimed at a live
inspector address that is not the sender's own (`@wl_inspect_live`), and the
listener refuses a caller whose uid is not the workload's own — root included —
through `moatery.peer_identity`, which reads the kernel's socket table because
`SO_PEERCRED` is AF_UNIX-only and says nothing about a TCP peer. A `REACHED`
line is a regression in one of those two.

Both are needed because the default-deny drop in `workload_filter` is guarded
on `@wl_filtered` membership, which an unfiltered workload of *either*
substrate is not in, so an untranslated packet from it is not dropped there. A
dial that got through would land in the *victim's* egress record, so a
workload's own record of what it sent would describe traffic it never sent.

### Fixtures in place of another host

**IPv6** needs a v6 destination the kernel will *route*, not an uplink. A ULA
on the far side of a veth is one: the packet is built, the routing lookup
succeeds, and it arrives at the nftables hook under test. An uplink would add
an ISP to the measurement rather than removing a doubt from it. The
discriminating probe is the *denied* one — a second name at the **same
address** that is not in `hosts`, so a refusal for it can only have come from
the inspector reading the name.

**A moved `[[network.allow]]` address** needs two stub origins with different
bodies and one line in `/etc/hosts`. Which origin answered is the whole
question, and one origin moved would make "the pin held" and "the rotation
never took" the same reading. The rig asserts the container itself now
resolves the new address before the row it guards; otherwise the row measures
a DNS cache. After a rotation `diagnose`'s `allow_drift` check names the stale
address and the entry that pinned it: the inspector is not in this path and
never sees the connection, so nothing else would.

**`ca_delivery = "env"` against an embedded root store** needs an *image*. Node
is the wrong one: `NODE_EXTRA_CA_CERTS` is one of the five variables
workloadctl delivers, so Node trusts the CA and the row would pass having
measured nothing. Go reads `SSL_CERT_FILE` too. A JVM reads none of the five;
its anchors are `cacerts` inside the image. The refused-handshake message it
gets names both remedies — re-seeding a VM, and a container image's own trust
store or `[[network.splice]]`.

**The origins live in a network namespace behind a veth, and that is
load-bearing.** An address on a dummy link is *local*, and
`workload-filter.nft` accepts a filtered uid's traffic unconditionally when
`oif lo`, because loopback is the workload's control plane and not egress. A
local origin is reached whether or not any element authorises it. The rig
asserts its fixture addresses bind before the rows that use them, so a bad
address reads as a fixture failure rather than three layers from the cause.

### Pod mode, and the ordering that no steady-state row can see

The egress arming lives on the head unit, not the umbrella
(`workload-<name>.service`). The umbrella looks like the right place —
`[network]` is workload-level, one uid per workload, and the umbrella is the
unit that represents "this workload is up" — but it is `After=` its members, so
systemd would start every container *first* and arm afterwards, leaving the
workload unfiltered for the whole of member startup, image pull included.

So `check_head_unit_ordering` asserts the *ordering*, not the presence of a
string. Five of its six rows read systemd's parsed state rather than the
generated file, because only the host can say what the manager actually
loaded. **The load-bearing row is the one about the umbrella:** `the umbrella
really is ordered AFTER its members` pins the *premise*. Without it, "the
arming is on the head unit" is a preference; with it, the other placement is
provably a hole. The sixth row is an observation rather than a configuration
reading: monotonic start timestamps for the head unit and each member, head
first.

`ceg-pod` carries **two** members deliberately: with one member there is less
window, and the claim is that the arming precedes *all* of them. The second
member is also probed against a denied host on its own, because it shares the
pod's netns and therefore the redirect; if only the first were filtered, every
other assertion here would still pass with half the pod unfiltered.

### The default deny takes DNS, and it is a fact about the host

`check_container_resolver`. A triggered container's uid enters
`wl_filtered` and meets the last rule in the output chain. The port-53 accept
in `workload-filter.nft` is scoped to `wl_egress_cg` — the **inspector's**
cgroup, which a container is never in — so a container's queries survive only
through `oif lo`. A loopback stub (127.0.0.53) resolves fine; a LAN resolver is
a workload-uid socket to a routable address on port 53 that no rule accepts,
and the container then resolves **nothing**, including the hostnames its own
`hosts` allowlist names. A host using the resolved stub passes through the
`oif lo` accept without anyone choosing it, so the row stands up a routable
resolver on the far side of the veth rather than relying on the host's.

**Both protocols.** The drop carries no protocol qualifier and the accept above
it matches `th dport`, which is TCP and UDP alike — but real DNS is UDP first,
and a TCP-only probe leaves the protocol resolvers actually use unmeasured.

**The UDP drop reads as `EPERM`.** An nftables `drop` in the *output* chain
rejects a **local** sender synchronously, so the blocked query fails at
`send()` (`DROPPED-EPERM`) rather than waiting. That is the filter's own
signature: an absent reply is also what a dead responder looks like, `EPERM`
is not. The TCP half does time out, and the control row is what makes *that*
readable: a refusal counts as `reached`, and an unfiltered uid must reach the
responder before any other row is scored.

The remedy is asserted too, not just the break: an `[[network.allow]]` entry
for the resolver **on port 53 specifically** — the element is
(uid, address, port), and an entry written without the port arms nothing that
matches, which is why `diagnose`'s message spells the TOML out rather than
saying "add an allow entry".

### A filtered container asks its own responder

`check_container_responder`, plus two rows each in the pod and bridge
sections. A triggered single or pod container on pasta resolves through
moat-resolve on its own `127.130.x.y`, reached by pasta's `--dns-host`. The
default-deny DNS section above still stands for bridge mode, which aardvark-dns answers, and for the uid's
own port-53 dials.

- **No AAAA answer is the container's own address.** On a host with no IPv6
  default route, pasta copies whatever global v6 address the host has onto the
  container's interface, and on a host running filtered workloads that is an
  inspector's address on the `wl-egress` link. A client that tries v6 first
  would be refused inside the container. No responder gets `--address6`; every
  fetch by name in the rig is the row that sees this.
- **The static map is current.** The responder service is
  `StopPropagatedFrom=` the workload rather than `PartOf=` it, so a workload
  restart does not restart a running responder before the workload's prestart
  has rewritten the map. The row starts a query first and records that as its
  premise, so a responder that has not loaded anything yet cannot pass it.

**nslookup, never getent.** podman builds the container's hosts file from the
host's, so a name the rig put in `/etc/hosts` is answered there and the
responder is never asked. That is also reported as a gap: such a name is
neither synthesised nor counted.

**The outside-resolver row has a real resolver behind it.** moat-resolve
again, in the fixture namespace, answering a fixed address; the unfiltered
container getting that answer is the control that makes the filtered one's
timeout a drop.

### The credential broker

**The last row is a real request.** A container holding only a placeholder
makes a request that reaches the provider carrying the sealed key. The three
refusal rows — another workload's uid, root, and the container being unable to
name `127.129.x.y` at all — sit behind a control row proving the broker serves
its OWN inspector, without which all three are satisfied by a broker that is
dead. The broker unit's own text says nothing about whether anything starts
it — `Before=` orders a unit; it does not start one — so only that control row
sees a broker nothing pulls in.

### The record's readers

**Every negative row has a positive one in front of it.** The flat and grouped
renderers, `--host`, `--since`/`--until`, the closed `--reason` vocabulary (an
unknown value must be an *error naming the set*, because an empty report is
what a workload that never hit that refusal looks like), `-n -1` refused as not
a count, the non-root branch reached with `setpriv`, and the no-record-file
branch. **A reader that returned an empty list unconditionally would score full
marks on any set of negative assertions** — it answers "no records", "nothing
matched" and "nothing in that window" identically and plausibly. So each is
paired with a row over a record whose host, path and time the section itself
caused.

**Rotation is the only moment the record file is created by the listener
rather than by systemd**, so it is the only moment the owner, the mode and the
SELinux label come from a different actor — and a write that fails there does
not raise. `RequestLog` warns once and never again, by design, so a broken
rotation is a record that silently stops on a host where every unit is active
and every counter still moves. The arm forces a rotation, **makes a request
before asserting anything about the new file** (the listener sets a flag in the
handler and reopens on the next write, so an immediate assertion measures the
flag), then checks owner, mode, label, and that `egress` reads *across* the two
generations rather than only the live one.

**`disable --purge` is asserted, not left to cleanup.** What it prevents is not
tidiness: the next workload given that uid inherits a `LogsDirectory=` owned by
a user that no longer exists, systemd refuses to set it up, and the inspector
fails `240/LOGS_DIRECTORY` while the workload itself starts fine — hanging on
80 and 443 and nothing else, with the explanation in a different unit's
journal. The pre-purge rows are the control: without them, "the directory is
gone" is satisfied by one that was never created.

**The near-end reading is measured and deliberately not scored.** It asks what the listener
sees as the *near* end of a container connection, because a pod- or
bridge-mode workload is N containers under one uid and the record names the
workload. There is no correct answer to pin: a single address means no
attribution is available and the disclosure is the deliverable; a per-container
address means a second reading with two members is worth taking. Nothing is
added to the record until that reading exists — a field that is constant in
every topology is worse than no field, because it reads as attribution.

### What it does not measure

**A global-scope IPv6 destination.** The redirect map keys on `tcp dport`
alone, so translation is scope-blind and the ULA result carries — but that is a
reading of `workload-redirect.nft`, not a measurement, and it is the one claim
here still worth a v6-capable host.

## uid_attribution_rig.py — which uid does a container's egress actually leave as?

Needs root and the workloadctl RPM; no KVM and no base image, so this is the
cheapest rig here to run. Deploys three throwaway single-container workloads
that differ only in `[container] user`, and counts one SYN from each against
three competing nftables selectors.

```bash
sudo python3 tests/manual/uid_attribution_rig.py          # host mode
sudo python3 tests/manual/uid_attribution_rig.py pasta    # the shipped path
```

### What it answers

Does `[network] mode = "host"` keep uid attribution? Every rule in
`nftables/workload-filter.nft` selects on the single workload uid, so the whole
design rests on a container's packets carrying it:

|                    | image default | `user = "0"` | `user = "1000"` |
| ------------------ | ------------- | ------------ | --------------- |
| `mode = "pasta"`   | workload uid  | workload uid | workload uid    |
| `mode = "host"`    | workload uid  | **subuid**   | **subuid**      |

The cause is that `[security] userns` defaults to `keep-id`: exactly one
in-container uid maps to the workload uid, and every other one — including
in-container root — maps into the workload's 65536-wide subuid window. Pasta
hides this entirely, because it re-originates the container's traffic as a host
socket that it owns. Host mode has no such indirection: the container's sockets
*are* host sockets, and two arms of three leave as subuids no shipped rule
matches. That is why `validate_container_network()` refuses `mode = "host"`
combined with any egress key — the alternative is filtering whichever
containers happen to run as the keep-id uid while reporting the workload as
filtered.

Both arms also confirm that the host's own traffic is never captured. Root and
an ordinary user match no workload selector on any arm, even with the network
namespace shared.

### Why counters rather than an end-to-end dial

Nothing is armed for a host-mode workload, so there is nothing to dial through.
Three counters competing for one packet at the output hook measure the
primitive itself and cannot be confounded by whether an inspector is up,
whether a route exists, or whether anything is listening. The destination is
unroutable on purpose (TEST-NET-3), so every probe is a single SYN and the only
variable is which rule claimed it.

### Traps the code is shaped around

1. **`nft reset counters table` resets named counters only**, not the anonymous
   per-rule ones used here, so every row reads deltas.
2. **busybox `su` is not GNU `su`** and refuses to drop privileges with `must
   be suid to work properly`. The "non-root" probe proves the uid changed
   before its verdict counts.
3. **keep-id injects the host username into the container's `/etc/passwd`**, so
   `id` inside prints `uid=10002(_wl-<name>)` — which looks exactly like an
   `exec` that escaped to the host. It has not; that *is* the container.
4. **Retransmits cross probe boundaries.** An unroutable destination leaves
   every probe retransmitting on a doubling backoff, and under pasta those are
   re-originated by a long-lived host process owned by the workload uid — so
   they would land in the next probe's window and attribute the host's own
   `curl` to the workload. A settle-and-hope window fits *inside* a backoff
   gap; each probe gets its own destination port and a freshly built table,
   which makes the contamination unmatchable rather than unlikely.

### What it deliberately does not measure

**IPv6** — `container_egress_rig.py` covers the v6 redirect on a ULA fixture,
but this rig measures the uid *selector*, which is family-blind (`meta skuid`
reads neither address nor family), so there is nothing here a v6 arm would
add. **Whether the DNAT redirect would capture host traffic in host mode** — it
cannot, because nothing arms a redirect for a host-mode workload; the rig
measures the uid selector, which is the part the design depends on.
**`userns = "host"`**, where in-container root maps to the workload uid
directly and the mapping question does not arise; the refusal covers it
regardless, which is deliberate — a `[network]`-level rule that changed meaning
based on a `[security]` key would be the kind of coupling nobody remembers.

---

## deployed_snapshot_rig.py — do the workloads nobody opted in still get the same units?

The one guarantee an opt-in change owes above all others: a workload that did
not opt in gets **exactly** what it got before. `tests/test_generator_snapshot.py`
asserts that against the bundles committed to this repo — the smaller set, and
the one whose shapes were chosen by whoever wrote the feature. A `[network]`
shape that no bundle contains but a live host does is precisely what a
bundle-derived snapshot is structurally unable to cover.

So this rig reads the other set: `/etc/workloads.d` on real hosts. It pulls
every deployed config, renders each one through the generator from two git
revisions (`git archive`, so neither the worktree nor the current branch is
touched), and diffs every emitted unit and sysusers file byte-for-byte.

```
./deployed_snapshot_rig.py --before <rev> [--after HEAD] --self-check <ssh-target>...
```

It needs ssh and passwordless sudo on each host, and nothing else — no root
here, no KVM, no podman. The generator is a pure function from config to unit
text, which is what makes this cheap enough to run against every host for
every change.

### What it answers

- **Byte-identical, per deployed config.** Rows are tagged `no trigger` or
  `opted in via <key>`; an opted-in workload is *supposed* to change, so the
  tag is reported and never asserted.
- **Does the `mode = "host"` refusal take a live workload down?** The refusal
  fails closed — the generator emits no units, so a workload pairing host mode
  with an egress key stops running rather than running unfiltered. That is the
  right direction and still an outage, and "no shipped bundle uses that
  combination" is only a claim about this repository.
- **Can the differ see a difference at all?** `--self-check` perturbs the
  "after" generator, asserts every row goes red, then reverts and asserts they
  all go green again. A rig that compares nothing prints the same clean sweep
  as one that works. The perturbation is indented to its anchor's own column,
  and a mutation that fails to apply is itself a FAIL rather than a silent
  no-op.

### Traps the code is shaped around

1. **The render root is in the output.** Each render gets a fresh `mkdtemp`
   whose path lands in the emitted `ExecStart=/usr/bin/systemd-sysusers ...`
   line, so it is normalised before the diff; otherwise *every* unit differs
   for a reason having nothing to do with the generator.
2. **A disabled workload renders nothing, and nothing equals nothing.** A
   deployed workload with no `.enabled` marker is skipped by the generator and
   compares equal having emitted zero units. The marker is forced and a
   zero-unit render is a hard error.

### What it deliberately does not measure

Whether the deployed units on disk match what the generator *would* now write —
that is `workloadctl drift`, and it is a different question. This rig compares
two generators against one config, not one generator against one host.

## local_bundle_rig.py — do control files in the local bundle layer work under enforcing?

`/etc/workloadctl/bundles/<bundle>/` lays an admin's files over a shipped
bundle, or holds a bundle nothing ships. The unit suite proves every path
resolves to the right layer. It cannot prove that each reader is allowed to
read what it resolved: files there are `etc_t` where shipped ones are `usr_t`,
and the readers are root's podman (the build context), `semodule` (the policy),
root (the setup script) and whatever system service a setup script starts.

```
sudo python3 tests/manual/local_bundle_rig.py [--keep] [--no-vm]
```

It needs the workloadctl RPM installed from the branch under test, enforcing,
podman, and KVM unless `--no-vm`. It plants three throwaway bundles:
`lbr-local` lives only in the local layer; `lbr-over` is planted in the shipped
tree with a local layer carrying `asset.txt`, `setup.sh` and `helper.py` over
it; `lbr-vm` is a VM bundle planted in the shipped tree from this checkout's
`vm-base`, with its relative `user_data_file` answered by a seed in the local
layer. Every local file says `local` and every shipped one says `usr`, so each
row reads which copy a reader got. Each bundle's asset carries the bundle's
name, so a build served from another bundle's cached layers cannot satisfy the
asset row.

### What it answers

- **Premises.** The host is enforcing, the local files are `etc_t` and the
  planted shipped ones `usr_t`, and the installed `catalog` reports `local` and
  `shipped+local`. A host without the layered catalog stops the run.
- **`info --files` names the winning layer**, file by file.
- **The build context carries the local asset.** The image's `/asset.txt`
  says `local <name>`, so the copy came from the layer, through a context root's
  podman read.
- **`policy.cil` from either layer loads**, and the container runs as
  `wl_<name>.process`. `disable --purge` removes the module.
- **`setup.sh` runs from the layer**, and a `systemd-run` service runs a helper
  it found through `WORKLOAD_LOCAL_BUNDLE_DIR`.
- **A VM boots the local layer's seed.** The seed writes a marker naming its
  layer, and the guest reads it back over `exec`, so the row sees the seed
  the guest actually got rather than the path workloadctl resolved. A premise
  row first checks that the installed `vm-base` names its seed relatively; a
  build without layered seed lookup stops the run there.
- **No AVC anywhere during the run**, unfiltered, since an AVC from one of
  these readers need not name a workload.

### What it deliberately does not measure

A unit whose `ExecStart=` is a file in the layer itself (the setup script's
service runs `python3` on the helper, not the helper directly), and an
image-based host, where `/etc` is the merged ostree `/etc` rather than a plain
directory.

## bundle_pull_rig.py — does `workloadctl bundle` hold its threat model on a host?

The unit suite drives `bundle add|update|rm` through a stub skopeo. Only a
host says whether the real skopeo checks `/etc/workloadctl/bundle-policy.json`
rather than the host's `policy.json`, whether a signed artifact podman pushed
unpacks to root-owned `etc_t` files, and whether an added bundle then inits
and enables under enforcing.

```
sudo python3 tests/manual/bundle_pull_rig.py [--keep]
```

It needs the workloadctl RPM installed from the branch under test, enforcing,
podman and skopeo. It starts a throwaway `registry:2` on 127.0.0.1:5000, makes
a sigstore keypair and a wrong one, and writes a registries.conf.d drop-in, a
registries.d entry and the bundle policy, restoring whatever was there.

### What it answers

- **Premise and control.** The host's own `policy.json` accepts the unsigned
  artifact, so a refusal later is the bundle policy's.
- **No bundle policy refuses every OCI add.**
- **Unsigned, wrong-key and moved-signature artifacts are refused**, each
  leaving nothing in the bundles root or staging. A mistyped bare name and a
  shipped bundle's name are refused. Every add names `--name`, so "leaves
  nothing" looks where the bundle would have gone, and a wrongly admitted
  bundle is removed after its row, so a later refusal fails on its own check
  rather than on "already exists".
- **Root-run files.** A setup script and a `[build] script` are each refused
  without `--allow-host-setup` and added with it.
- **Signed add.** The record pins the pushed digest, every file is `etc_t`
  and root-owned, modes are kept, `catalog` shows the origin, and the bundle
  inits and enables, running its setup script.
- **Update.** A new digest with an unchanged setup script needs no flag; a
  changed one does. Drift is refused and `--force` replaces it; with the same
  digest, `--force` restores. A shipped bundle appearing under the name makes
  `update` refuse and `diagnose` warn.
- **Directory bundles** follow their directory, record a second one, and are
  refused once it's gone.
- **`rm`** is refused while an instance uses the bundle.
- **No AVC denial** during the run.

To break it on purpose, edit the installed `cmd_bundle.py` or
`bundle_fetch.py`: the policy gate, the root-run gate, drift, the shipped name,
rm in use, a missing policy, a dropped `--policy`. Each should turn its rows
red.

## device_rig.py — does sunshine-streaming's configuration reach a real GPU, and leave the sound card out?

The runtime rung's `test_runtime_devices` runs sunshine-streaming's devices,
groups, seccomp, rlimits and `policy.cil` in a VM: uinput, the refusal of a
real keyboard's node, Steam's bwrap syscalls, 32-bit code and the scheduling
limits. A VM has no render node and no sound card, so this rig runs the same
configuration on a host with both.

```
sudo python3 tests/manual/device_rig.py
```

It needs an AMD GPU (`/dev/dri/renderD*`, `/dev/kfd`), a sound card, the
workloadctl RPM installed and enforcing. It builds each arm's TOML from the
checkout's sunshine-streaming bundle and loads that bundle's `policy.cil`.

### What it answers

- **Premises.** Enforcing, and the host has a render node, `/dev/kfd` and a
  sound card, so an absence in the container is the configuration's.
- **The GPU works, not just mounts.** The DRM version ioctl on the render node
  names the driver (`amdgpu`) and the KFD version ioctl answers.
- **The host's sound card stays out.** The stream's audio is the container's
  own PipeWire sink, so `/dev/snd` is empty in the container.
- **No denial with the payload as its source.**
- **Control:** the same configuration without `gpu` has no render node and no
  `/dev/kfd`, and no denial. The control's own denials have a row, so an
  absence the policy caused cannot pass as one the configuration caused.

## image_fetch_rig.py — does a filtered container get its image from outside its filter?

Needs root, the workloadctl RPM installed, SELinux enforcing, and anonymous
access to registry.access.redhat.com and docker.io. Turns dontaudit rules off
for the run and restores them on exit.

```bash
sudo python3 tests/manual/image_fetch_rig.py
```

A filtered workload's image is fetched by `workload-image-fetch`
(`lib/image_fetch.py`) as a `DynamicUser=` uid in a transient unit, and loaded
as the workload user. Five arms: the main one (`pull = "newer"`, a small image
in no store) runs a first start, a second start, a start with the registry
blocked, a start stopped mid-copy, an `update` with a rollback target and a
purge. A ~400 MB image checks the start timeout, a 16 MiB tmpfs over the fetch
cache checks the free-space refusal, a missing tag is the fetch step broken on
purpose, and an unfiltered workload is the control. One arm fetches from
registry.access.redhat.com, whose repositories carry thousands of tags, so
the worker's `skopeo inspect --no-tags` is on the path under test.

**The fetch's uid is watched, not inferred.** The transient unit is collected
the moment it ends, so a thread polls its `UID` during the start; a row on a
journal line would pass for a fetch that ran as root.

**The egress row has a control.** "The filter saw no registry attempt" is
also what a filter that logs nothing would show, so the workload then dials
the registry itself and the row after it requires that attempt in the record.

**The killed-start row pins its premise.** A stop during the start kills the
start step but not the transient unit; the rig asserts the unit is still
copying afterwards, so the next row (the next start stops it first) measures
the cleanup rather than a fetch that had already ended.
