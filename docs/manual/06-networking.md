# 6. Networking and egress

This chapter is about what a workload may reach. It covers how the host
filters a VM's or a container's outbound traffic, how you write that policy,
how a provider's API key is kept out of the workload altogether, and how you
read what the filter did. Container network modes and published ports are in
[chapter 4](04-containers.md), and a VM's passt networking and published
ports are in [chapter 5](05-vms.md). [The egress plane](../dev/egress.md)
describes the same machinery for maintainers.

## How the host sees a workload's traffic

Everything here rests on one fact: a workload's traffic leaves the host from
sockets owned by the workload's own user. A VM's network stack ends inside
passt, which runs as `_wl-<name>` and opens an ordinary host socket for every
connection the guest makes. A container's traffic goes through pasta, the
same program in its container mode, or through podman's rootless network
stack in a bridge-mode workload, which also runs as the workload user. The
host can therefore tell one workload's traffic from another's by its owner,
and nothing inside the workload can change that owner.

The filter keys on that owner, so it needs nothing from the workload: no
proxy setting, no cooperation, nothing the workload could decline to do. A
process that ignores its environment entirely is filtered exactly like one
that doesn't.

Two shapes break the property, and workloadctl refuses to filter them rather
than filter them partly. A VM on a LAN bridge sends from its own address,
with no host socket in the way. A container with `[network] mode = "host"`
shares the host's network, and its processes appear under different host
uids depending on which user they run as inside the container, so a filter
keyed on the workload's uid would cover some of them and miss the rest.
`validate` rejects every filtering key in either shape.

## Choosing a stance for a VM

A VM is in one of three stances, chosen in `[vm.network]`.

**Filtered** is the default. Everything the VM sends is dropped except what
its configuration names. Web traffic on ports 80 and 443 goes to the
workload's own egress inspector, which allows it by host name, and anything
else needs an address-level `allow` entry:

```toml
[vm.network]
egress = "filtered"
hosts  = ["fedoraproject.org", "*.fedoraproject.org"]
```

A filtered VM has to name somewhere it may go: at least one `hosts` pattern,
`allow` entry or `policy` entry. A filtered VM that names nothing, including
a VM with no `[vm.network]` section at all, fails validation instead of
booting into a network where nothing answers. So every VM's TOML states its
stance, one way or the other.

**Open** turns the policy off:

```toml
[vm.network]
egress = "open"
```

An open VM's traffic is neither filtered nor inspected, and its DNS queries
go to the host's resolver. It is still not on your network: passt keeps it
off the host's loopback and gives it no address of its own (see
[chapter 5](05-vms.md)). `hosts`, `policy`, `internal`, `splice` and `tls`
are refused under `open`, because nothing would read them.

**Bridged** attaches the VM to a host bridge you provide, giving it a real
address on that LAN:

```toml
[vm.network]
bridge = "br0"
```

You create the bridge yourself, with NetworkManager or systemd-networkd, and
allow it in `/etc/qemu/bridge.conf`; workloadctl does neither. A bridged VM
is outside the host's policing altogether, because its traffic never becomes
a host socket. `egress` and every filtering key are refused beside `bridge`,
as are `ports` and `outbound_if`, and `workloadctl diagnose` reports the
stance as information, not as a fault. Use it for a VM that must be reachable
at its own address, such as one serving TLS under its own name.

One more key shapes a passt VM's outbound traffic without any filter.
`outbound_if` binds passt's host-side sockets to one interface, in both
address families, so a VM pinned to the WAN-facing interface cannot
originate traffic on a management network at all:

```toml
[vm.network]
egress      = "open"
outbound_if = "eno1"
```

## Filtering a container

A container has no `egress` key, and writing one does nothing. A container
is filtered when its `[network]` section names what it may reach, with any
one of three triggers:

- `hosts`, the host names it may reach over HTTP and HTTPS;
- a `[[network.allow]]` entry, a destination on some other port;
- a `[[network.policy]]` entry, the methods and paths it may use on a host.

A container with none of them is not filtered, and its units are exactly
what they would be if this chapter did not exist.

Once any trigger is present, the container is under the same default deny as
a filtered VM, and this is the part that surprises people. Filtering does not
police ports 80 and 443 and leave the rest alone. What gets through is
connections to 80 and 443, which go to the workload's inspector and are
decided by `hosts` and `policy`; each `allow` destination; the workload's own
DNS and management traffic on the host's loopback; and replies on
connections already accepted.

Everything else the workload sends is dropped: a database on 5432, an SMTP
relay, an NTP server, git over SSH. Each needs an `allow` entry of its own.
The drop is counted on one counter shared by every filtered workload on the
host, so the symptom is a timeout with nothing naming it as a policy
decision. Work out what the workload needs before you filter it, not from
the failures afterwards.

`mode = "host"` cannot be combined with a trigger in a `single` or `pod`
workload, and the workload will not enable until one of the two goes. A
`bridge`-mode workload never reads `[network].mode`, so a `mode = "host"`
left there does not block filtering.

### The image pull

A container's image is pulled by the workload's own user when its unit
starts, after the filter is armed, and so is any later pull such as the one
`update` makes. If the image is not already in the workload's store, the pull
goes to port 443, lands on the inspector and is refused, because a registry
is not a host you would think to list. It looks like a registry outage.

There are three ways around it, in the order worth trying:

- Enable the workload with no trigger so the image is pulled, then add the
  triggers and `recreate` it.
- Build the image from a `Containerfile` in the bundle. Root builds it and
  transfers it into the workload's store, and the workload never fetches it.
- List the registry's names in `hosts`. This is the widest of the three: it
  lets everything in the workload reach the registry, and a registry is
  usually several names (its API, its token service, its blob storage).

## The same keys on both substrates

The policy keys mean the same thing on both substrates and are read by the
same inspector. The differences are in where they live and in a few
defaults:

| | VM | Container |
|---|---|---|
| Section | `[vm.network]` | `[network]` |
| Filtering on | `egress = "filtered"`, the default | any of `hosts`, `allow`, `policy` |
| Other ports | `[[vm.network.allow]]`, with `address = "<addr>:<port>"` or `"<name>:<port>"` | `[[network.allow]]`, with `address` or `host`, and `port` |
| Internal names | `[[vm.network.internal]]` | `[[network.internal]]` |
| Spliced hosts | `[[vm.network.splice]]` | `[[network.splice]]` |
| Methods and paths | `[[vm.network.policy]]` | `[[network.policy]]` |
| Credentials | `[[vm.network.credential]]` | `[[network.credential]]` |
| `tls` when unset | `"inspect"` | `"splice"` with no policy entries, `"inspect"` with any |
| Trusting the CA | the cloud-init seed | `ca_delivery` |
| Resolver | `resolver = "host"` or `"none"` | no key |

The rest of this chapter uses the short names (`hosts`, `allow`, `policy`
and so on) and gives examples in both spellings.

Write every scalar in the section (`egress`, `hosts`, `tls`, `ca_delivery`
and the rest) above the first `[[...]]` table. The first array-of-tables
header ends the section, so a scalar written below it belongs to that table
entry instead. TOML accepts the file without complaint, and you cannot fix it
by opening the section again further down, because TOML forbids declaring a
table twice.

## Allowing hosts by name

When a filtered workload dials port 80 or 443, the host redirects the
connection to that workload's own egress inspector, whatever address was
dialled. The inspector reads the name the workload asked for (the `Host`
header of an HTTP request, or the server name in a TLS ClientHello), checks
it against the policy, and then makes the connection on the workload's
behalf or refuses it.

The workload is told nothing. There is no proxy address, no environment
variable and nothing to configure in the image, so there is nothing it can
unset to get out. Don't set `http_proxy` or `https_proxy` in a guest or an
image either: no proxy listens anywhere, so a client that honours them fails
while the ones that ignore them work.

`hosts` lists the names:

```toml
[network]
hosts = ["pypi.org", "files.pythonhosted.org"]
```

Each entry is an fnmatch pattern matched against the host name alone. A
scheme, a path or a port in an entry is an error, and so is `*` on its own,
which would filter nothing while looking configured. For a VM, say
`egress = "open"` instead; for a container, remove the triggers.

`*.example.com` does not cover `example.com`. The wildcard needs a label
before the dot, so list the apex as well when you want both:

```toml
[vm.network]
hosts = ["fedoraproject.org", "*.fedoraproject.org"]
```

An apex the wildcard missed gets the same 403 as a host nobody listed, so it
reads as a policy decision rather than as a pattern that stopped short.

Be careful with a wildcard under a domain where anyone can register a name,
such as `*.github.io` or `*.pages.dev`. The workload picks the label, the
pattern authorises it, and the name is looked up through a nameserver
someone else runs. `validate` warns about such a pattern on a VM. Name the
sites you need instead.

A connection carrying no readable name is dropped: an HTTP request with no
`Host` header, a TLS connection with no server name, or bytes on 443 that
are not TLS. That is what happens to a TLS connection made to an IP address
directly. The redirect keys on the port, so the connection still reaches the
inspector, and with no name there is nothing to match.

Only TCP ports 80 and 443 are redirected. HTTP/3 runs over UDP 443, which is
not, so it meets the default deny. Clients fall back to TCP, sometimes after
a delay.

## Destinations on other ports

An `allow` entry admits one destination on a port other than 80 or 443: SSH,
a database, an NTP server. Every entry carries a `reason`, because it is a
hole opened on purpose and whoever later decides whether it is still needed
is rarely the person who opened it.

A VM entry names the address and port together, as an address or as a
host name:

```toml
[[vm.network.allow]]
address = "192.0.2.10:22"
reason  = "backup target over SSH"

[[vm.network.allow]]
address = "git.example.internal:2222"
reason  = "git over SSH to the site's forge"
```

Write an IPv6 address in brackets, as `"[2001:db8::10]:22"`. A container
entry gives either `address` or `host`, never both, and the port separately:

```toml
[[network.allow]]
host   = "db.example.net"
port   = 5432
reason = "the reporting database"

[[network.allow]]
address = "192.0.2.10"
port    = 22
reason  = "backup target over SSH"
```

Each entry is one address and one port. A port range or a subnet is written
as one entry per port or address.

Ports 80 and 443 are refused in `allow`. Those connections are redirected to
the inspector before `allow` is consulted, so the entry could never match
while the file read as though the destination skipped inspection. Name such
hosts in `hosts`. An entry may not point into the inspector's own address
ranges (198.18.0.0/16 and 2001:2::/48) either.

A name in `allow` is resolved on the host when the workload starts, and every
address it answers with is armed, in both families. A name that does not
resolve fails the start. The addresses stay fixed until the next start, so a
destination whose address changes falls through to the default deny until
you restart the workload; `diagnose` compares what each name resolves to now
with what is armed and names both addresses. On a filtered VM, or a filtered
container on pasta, the workload's own DNS lookups for that name are answered
with the same armed addresses (see the next section).

An `allow` entry opens the workload's own direct path to that destination,
uninspected. It is not an exemption for the inspector alone.

## DNS under filtering

A filtered VM's DNS never leaves the host. passt intercepts the guest's
queries and hands them to the workload's own synthesising responder, which
answers every A query, for any name, with the address of the workload's
inspector. Every other query type, AAAA included, gets an empty answer.
There is no upstream: the responder forwards nothing and asks no one, so the
host's own resolver never sees the guest's queries, and DNS is not a channel
out of the workload.

This works because the answer never has to be true. Any connection to 80 or
443 is redirected to the inspector by port, and the inspector resolves the
name it authorised for itself, on the host. The address the workload was
given is never dialled.

Two consequences follow. An unlisted name still resolves: the workload always
gets an address, always connects, and learns the answer from the inspector's
refusal. (The responder notes each lookup for a name on no list, which shows
up in the counters as an unlisted query.) And a name used on any other port
needs an `allow` entry written by name. The responder answers those names
from the addresses the entry was armed with; without the entry, the
synthesised answer sends the connection to an inspector that does not serve
that port.

A filtered container in a `single` or `pod` workload on pasta, the default
network, gets the same responder through pasta. A bridge-mode workload, or
one on a custom podman network, does not: podman's DNS server answers it and
forwards to the host's nameservers, as the workload user. A nameserver on
the host's loopback, such as `127.0.0.53`, is reachable. One elsewhere on the
LAN meets the default deny, and the container loses DNS entirely until you
allow it:

```toml
[[network.allow]]
address = "192.0.2.53"
port    = 53
reason  = "the LAN resolver; bridge-mode DNS goes to it directly"
```

In bridge mode the content of DNS queries is not controlled, so DNS stays a
channel in both directions wherever the container can reach a resolver. If
that matters, use a pod workload, whose containers still talk over
localhost. In either mode, a nameserver a tool inside the container picks for
itself, such as `8.8.8.8`, meets the default deny. `validate` warns about an
`allow` entry on port 53 for a workload that has a responder, because it
hands the workload a resolver of its own, past the responder.

A guest cannot look up a `.local` name. Its resolver sends `.local` to mDNS
and a single-label name to LLMNR, and neither crosses passt, so the lookup
fails inside the guest with "No appropriate name servers or networks for name
found" before the responder is asked. Give such a service a second name in a
private-use domain, such as `.internal` or `home.arpa`, with a record in the
LAN's ordinary DNS, and use that name in the policy.

`[vm.network].resolver = "none"` gives a VM no resolver at all, and it is
almost never what you want. A guest that cannot resolve can dial only
addresses, and an address reaches the inspector with no name to match, so
every name-based destination fails while the workload starts cleanly.
`validate` rejects it beside `hosts`, `internal`, `splice`, `policy` or an
`allow` entry written by name, and warns even in the one case that works, a
workload whose destinations are all `allow` entries by address. It is not
what keeps DNS from carrying data out; the responder already does that.

## Terminating or splicing TLS

The inspector handles a permitted HTTPS connection in one of two ways, set by
`tls`.

Under **inspect**, the inspector terminates the connection. It completes the
workload's TLS handshake itself, with a certificate for the requested name
signed by a CA that belongs to this workload alone, and opens its own
connection to the origin, verified against the host's trust store. It then
checks every request inside the session by its `Host` header, and by method
and path where `policy` says so, the same way it checks plain HTTP. A request
naming a different host from the one the session was opened for is answered
421, and a well-behaved client retries it on a connection of its own.

A refused name gets a real 403 through a completed handshake, so the client
prints an error rather than reporting a dropped connection. The certificates
for refused names are rationed, and a workload that keeps hammering refused
names gets closed connections once the ration runs out.

Under **splice**, the inspector reads the server name from the ClientHello,
checks it, and relays the workload's own bytes to the origin unchanged.
Nothing is decrypted and no CA is involved. The name is checked once, at the
start of a connection whose contents nobody sees, and a refusal is a closed
connection the client cannot tell from the host being down.

A VM's `tls` is `"inspect"` unless you set it. A container's depends on its
`policy` entries: with none it is `"splice"`, and with any it is
`"inspect"`, because method and path rules need the request decrypted. You
may set it either way; `tls = "inspect"` on a container without policy
entries is allowed. Since a container's mode can be computed, its file may
not say which one is running; `doctor` and `egress` report the mode in force.

Writing `tls = "splice"` explicitly needs `tls_reason` beside it, because it
gives up per-request checking for every host the workload reaches:

```toml
[vm.network]
egress     = "filtered"
hosts      = ["updates.example.com"]
tls        = "splice"
tls_reason = "appliance image; its trust store cannot be changed"
```

A container that reaches splice by having no `policy` entries needs no reason,
since nothing narrower was given up. `tls_reason` without an explicit
`tls = "splice"` is an error on both substrates.

Usually one host is the problem, and a `splice` entry exempts just that
host while the rest stay terminated:

```toml
[[vm.network.splice]]
host   = "sum.golang.org"
reason = "client verifies a signed log, not the chain; cannot take our CA"
```

`host` is a pattern like the ones in `hosts`, with the same apex rule, and it
must match a `hosts` pattern; an entry that matches nothing is an error. A
host may not be both spliced and named in `policy`, since its method and path
rules could never run. On a container whose mode is already splice, a
`splice` entry is an error, because it exempts nothing.

### Trusting the workload's CA

Termination only works if the workload trusts its CA. Each workload's CA is
generated once, kept for its lifetime, and trusted by that workload alone, so
it can only ever impersonate sites to the one workload that already runs
behind it.

A filtered VM gets the CA through its cloud-init seed, whatever `tls` says.
The built-in seed installs it in the guest's trust store, builds a bundle of
the guest's own roots plus the CA at
`/usr/local/share/workloadctl/egress-ca-bundle.pem`, and points five
variables at that bundle: `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
`REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` and `PIP_CERT`. Many language
runtimes ignore the system store and read only these. Because the CA is in
the seed even under splice, switching `tls` between the two modes needs only
a restart.

cloud-init applies a seed once per instance, so a VM provisioned while it
was open does not trust the CA after you switch it to filtered. `recreate`
rebuilds the seed. Until then every HTTPS request inside the guest fails
certificate verification.

A VM with its own seed (`[vm.cloud_init].user_data_file`) has to install the
CA itself, or provisioning refuses the seed. The seed can read the CA from the
template variables `WORKLOADCTL_VM_EGRESS_CA` and
`WORKLOADCTL_VM_EGRESS_CA_B64`, and the `vm-base` bundle's sample seed carries
the whole block to copy. If the image already trusts the CA by other means,
`seed_provides = ["ca"]` in `[vm.cloud_init]` says so.

If you set one of the five variables yourself, point it at a bundle that
includes the system roots, not at the CA alone. `SSL_CERT_FILE` and
`REQUESTS_CA_BUNDLE` replace a runtime's store instead of adding to it, so a
file holding only the CA breaks every spliced host and every other TLS
connection that client makes.

A container is an image someone else built, so you say how the CA gets in
with `ca_delivery`, which is required whenever the container's mode is
inspect:

- `"env"`: workloadctl mounts a bundle of the host's roots plus the CA at
  `/usr/local/share/workloadctl/egress-ca-bundle.pem` and sets the same five
  variables. This suits anything built on OpenSSL, Python, Go, curl or a
  Fedora-like base.
- `"mount"`: workloadctl mounts the CA certificate read-only at
  `ca_mount_path`, and the image's own entrypoint installs it.
- `"image"`: the image was built trusting this workload's CA, which only
  makes sense for a bundle with its own `Containerfile`.

```toml
[network]
hosts         = ["*.example.org"]
tls           = "inspect"
ca_delivery   = "mount"
ca_mount_path = "/etc/pki/workload-ca/ca.crt"
```

`ca_delivery` states a route; nothing checks the image. A wrong value
validates, starts and reports healthy, then fails on the first HTTPS request
with a certificate error inside the container. A statically linked binary
with its own root store ignores all five variables, and needs `"mount"` with
an entrypoint, a `splice` entry, or no `policy` at all.

### What termination cannot carry

Some hosts cannot be terminated, and each shows a distinct symptom:

- A host that requires a client certificate answers 502, because the
  inspector has none to present.
- A host that merely offers client authentication completes the handshake
  with none and treats the workload as anonymous. The host starts answering
  its own 401 or 403 only under termination, and nothing on the host counts
  it, because nothing failed. Splice it.
- A host whose certificate the host cannot verify answers 502. An internal
  service signed by a private root needs that root in the host's trust store
  (`/etc/pki/ca-trust/source/anchors`, then `update-ca-trust`); installing it
  in the guest changes nothing.
- A host spoken to in anything but HTTP/1.1 over 443, such as a database
  protocol, a tunnel or HTTP/2, has its connection closed, and the journal
  says `not HTTP`. The inspector offers `http/1.1` alone and does not relay
  HTTP/2, so a client that insists on h2, as gRPC clients do, fails too.
  There is no setting for HTTP/2: splice the host.

`diagnose` lists the hosts whose connections were closed for not speaking
HTTP, which is the list of hosts that need a `splice` entry. Whether a host
speaks HTTP over 443 can only be learned from a connection.

### What the origin receives

Under inspect, the origin does not receive the workload's bytes. The inspector
parses each request, decides on it, and sends a request it composed itself.
Header names arrive in lowercase, which HTTP allows but which can break an
origin that matches names case-sensitively. `Content-Length` and
`Transfer-Encoding` are recomputed, and a request framed both ways at once is
refused. `Host` is the name that was authorised. Hop-by-hop headers are
dropped. A protocol upgrade is passed on, and once the origin answers 101 the
connection becomes an opaque tunnel, which the journal says in so many words.
An offer to upgrade to `h2c` is withheld, and the request completes as plain
HTTP/1.1. Responses come back as the origin sent them.

## Names that resolve into your network

The inspector will not open a connection into private address space, even
for an allowed name. That stops an allowed public name from being pointed at
your LAN: a wildcard over a domain where others can create records, a third
party whose DNS is compromised, or an internal name allowed without thinking
about where it points. On a cloud instance, `169.254.169.254` is the one to
think about first. The refused ranges are 0.0.0.0/8, 10.0.0.0/8,
100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.2.0/24,
192.168.0.0/16 and the broadcast address, and in IPv6 `::`, `::1`, fc00::/7,
fe80::/10 and the IPv4-mapped, NAT64 and 6to4 prefixes. Port 53 is exempt, so
the inspector can use the host's resolver wherever it lives.

A name that is supposed to resolve into private space, such as the site's own
forge, goes in `internal` with the reason it may:

```toml
[vm.network]
egress = "filtered"
hosts  = ["git.example.internal"]

[[vm.network.internal]]
host   = "git.example.internal"
reason = "the site's forge; on the LAN by design"
```

Without the entry, the workload gets a 502 for that host, and the record
gives the reason as `internal destination`. With it, the host stays
inspected and its `policy` still applies; only the address check is waived.
The entry must name a host that `hosts` or a `policy` entry already allows,
or it is an error. It applies under splice too, since a spliced connection
still has the inspector's own connection to the origin.

An `internal` name is resolved when the workload starts, and must resolve to
an address in one of the ranges above. If it does not resolve, or resolves to
a public address, the workload does not start, and the journal says which
entry stopped it. `validate` resolves the same names and warns at edit time,
though DNS when you validate is not DNS when the workload boots.

`internal` is for names reached over HTTP and HTTPS. A private destination on
another port, such as git over SSH to the same forge, is an `allow` entry;
`allow` entries are evaluated before the private-range check.

## Methods and paths

`hosts` says which hosts a workload may reach. A `policy` entry says what it
may ask one of them for: the methods and paths of each request inside an
inspected session.

```toml
[[vm.network.policy]]
host    = "registry.example.com"
methods = ["GET", "HEAD"]
paths   = ["/v2/*", "/token"]
```

`host` is a pattern like a `hosts` entry. `methods` are HTTP method names,
compared in upper case, and `paths` are fnmatch patterns matched against the
request's path. Within one entry the two are a cross product: two methods and
two paths permit all four combinations. To vary the methods by path, repeat
the host, one entry per rule:

```toml
[[network.policy]]
host    = "api.example.com"
methods = ["POST"]
paths   = ["/v1/messages"]

[[network.policy]]
host    = "api.example.com"
methods = ["GET"]
paths   = ["/v1/models", "/v1/models/*"]
```

An omitted `methods` means any method, and an omitted `paths` any path. An
empty list is an error, since it would permit nothing at all. `paths` matches
the path alone, so `/v1/messages` also permits `/v1/messages?stream=true`, and
a pattern carrying `?` or `#` is an error. Host names and methods are matched
without regard to case, but paths are case-sensitive: `/V1/messages` does
not match `/v1/*`. A method that is not a registered HTTP method is an error
rather than a rule that never matches, and `CONNECT` and `PRI` are refused by
name.

`policy` needs the request decrypted, so it is refused under an explicit
`tls = "splice"`, and on a VM it also needs `egress = "filtered"`. On a
container, the first `policy` entry moves the workload to inspect and makes
`ca_delivery` required; `validate` will not accept the file until you set it.

### How entries combine

A host that any `policy` entry matches is governed by those entries alone,
and `hosts` adds nothing to it. This is the rule to get right. If `hosts`
also applied, a wildcard written for some other reason, such as
`*.example.com` for git over HTTPS, would grant any method on any path to
every host it covers, including one you had restricted, and the change that
added it would look like it only added access. A host no entry matches is
allowed by `hosts` with no method or path limit.

A `policy` entry allows its own host, so a host named there need not also be
in `hosts`, and a workload may be written with `policy` entries alone.

Entries combine by union, so their order in the file never matters: a request
is permitted if any entry matching its host permits both its method and its
path. There is no way to subtract. A narrower entry cannot carve an exception
out of a wider one, and a specific entry does not override a general one:
`*.example.com` and `api.example.com` both govern `api.example.com`. If a host
needs a hole punched in it, the wide entry is the one to change.

Where more than one entry matches a host, every one of them must state both
`methods` and `paths`. Otherwise one entry with `paths` omitted would permit
every path and quietly undo every sibling you narrowed, so `validate` refuses
it. Overlap is judged by pattern, not by identical `host` strings.

The apex rule bites harder here, and `validate` refuses it. `*.example.com`
does not govern `example.com`, so with `example.com` allowed and the only
entry naming it the wildcard below it, the apex would be inspected with no
method or path rules at all. A `policy` entry allows its own host, so the
usual way to write this is `hosts = ["example.com"]` beside a lone
`*.example.com` entry. Add an entry for the apex too.

## Keeping API keys out of the workload

Software in a workload sometimes needs to call an API that wants a key, and a
workload that holds a key can leak it. The credential broker keeps the key on
the host. The workload calls the provider by its real name, exactly as it
would with a key; its inspector sees that the request is for a host whose
`policy` entry names a credential, and sends the request to the workload's
broker instead of to the provider. The broker attaches the real key and makes
the call.

The workload has no address, no variable and no name for the broker. It
cannot choose to use the broker or choose not to, and cannot be pointed at
another workload's. Each workload that declares a credential gets a broker of
its own, holding only that workload's keys, under a system user of its own
that is not the workload's.

### Sealing and declaring a credential

Seal the key under the workload's own scope, using the workload's name and a
credential name of your choice:

```bash
sudo workloadctl secret create broker/agent-vm/anthropic
```

`secret create` prompts for the value, or reads it from a pipe or from a file
named with `--file`; [chapter 7](07-secrets.md) has the details. Then declare
the credential and name it from the `policy` entry it applies to:

```toml
[[vm.network.policy]]
host       = "api.anthropic.com"
methods    = ["POST"]
paths      = ["/v1/messages"]
credential = "anthropic"

[[vm.network.credential]]
name        = "anthropic"
placeholder = "sk-ant-placeholder-not-a-real-key"
env         = "ANTHROPIC_API_KEY"
```

The last part of the sealed path and `name` must agree; workloadctl derives
everything else from them. `name` takes letters, digits, `_` and `-`. The
material is sealed under a name tied to this workload, so a broker handed
another workload's file fails to start instead of loading that workload's key.

As root, `validate` checks that each declared credential has been sealed and
fails if one is missing. Apply the change with `sudo workloadctl recreate`,
which generates the broker's unit.

A container declares the same thing under `[network]`. This one also sets the
provider's header convention, described below:

```toml
[workload]
name = "agent-sandbox"

[container]
image = "localhost/agent-sandbox:latest"

[network]
ca_delivery = "env"

[[network.policy]]
host       = "api.example.com"
methods    = ["POST"]
paths      = ["/v1/chat/completions"]
credential = "example"

[[network.credential]]
name        = "example"
placeholder = "placeholder-not-a-real-key"
env         = "EXAMPLE_API_KEY"
auth_header = "Authorization"
auth_format = "Bearer {secret}"
```

### What the workload holds

The workload holds `placeholder`, in the variable `env` names. That is not
decoration: many SDKs refuse to send a request without a key, and fail inside
the workload, before any packet, in a way that looks nothing like a policy
problem. The broker discards whatever authorisation the request carries and
sets the real key, so the placeholder never reaches the provider. It must not
be the real key: the broker refuses to start if the two are equal, because
that means a key was pasted into a world-readable `workload.toml`.

A container gets the variable in its environment. A VM gets it from its
built-in seed, once per instance, so editing `placeholder` later does not
reach a running guest (its requests keep working, since the broker replaces
whatever arrives). A VM with its own seed must export the variable itself.

`env` is yours to pick, separately from `name`, so that a provider renaming
its variable never forces a re-seal. It must be a shell variable name, may
not be one of the five CA variables, and may not be shared by two
credentials.

### The provider's header convention

`auth_header` and `auth_format` say how the provider expects the key. They
default to `x-api-key` and `{secret}`, which is Anthropic's convention. A
provider that wants a bearer token needs `auth_header = "Authorization"` and
`auth_format = "Bearer {secret}"`, and Gemini wants
`auth_header = "x-goog-api-key"` with the default format. Get this wrong and
the provider answers 401 to a request every layer here allowed.

`auth_format` must contain `{secret}` exactly once and nothing else in
braces. A header that frames the message or is stripped on the way out
(`Content-Length`, `Host`, `Connection` and the other hop-by-hop headers)
cannot carry the key and is refused.

### Rules the declaration must follow

A credential widens nothing. The entry's `methods` and `paths` are applied
first, exactly as for any other host, so naming a credential changes only
who attaches the authorisation. A brokered host needs no `allow` entry: the
inspector never connects to the provider for it, so the provider's
reachability from the workload does not matter.

`validate` refuses a declaration that could not work:

- A credential needs the request decrypted, so it is refused on a spliced
  host, under `tls = "splice"`, on an open VM and on a bridged VM.
- A credential is attached per exact host. An entry with a wildcard `host`
  cannot select one, since the broker has no patterns and would refuse every
  request the wildcard admitted.
- A `credential` naming no block is an error, and so is a block no entry
  selects. Either way, material would be sealed and loaded for a host it is
  never attached to, while the file read as though a credential were in use.
- Where entries overlap on a host, they must not select different
  credentials, and a brokered entry may not overlap one that selects none,
  or a request could leave unbrokered carrying the placeholder. Adding the
  credential to the wider entry is not the fix: that brokers everything the
  wider entry admits. Narrow the wider entry, or make it a `hosts` pattern.

### What the broker refuses

A client inside the workload may see these from the broker:

| Status | Why |
|---|---|
| 403 | The connection did not come from this workload's user, or the request's `Host` matches no brokered host. |
| 400 | A request naming a full URL as its target, which is a proxy's job and not this one's, or a malformed or doubled `Content-Length`. |
| 411 | A chunked request body. Send `Content-Length`. |
| 413 | A request body over 64 MiB. |
| 503 | The broker is already holding 256 MiB of request bodies. Retry. |
| 502 | The provider could not be reached. If it fails after its response has started, the connection is cut instead, leaving a short body the client reports as an error. |

Every refusal closes the connection. A connection that makes no progress for
60 seconds is dropped, and past 128 concurrent connections the broker closes
new ones without a reply rather than queue them.

### Running it

The broker reads its keys when it starts and does not reread them. After
re-sealing a key, restart the workload, which restarts its broker with it.
`secret rotate` does not do this for a broker key:

```bash
sudo workloadctl secret rotate broker/agent-vm/anthropic
sudo workloadctl restart agent-vm
```

The broker can connect only to the addresses the provider's name resolved to
when its unit was generated. If a provider's addresses change, `recreate` the
workload.

`backup` does not carry broker keys, by design. They are sealed to the host's
TPM or host key, so the ciphertext would not decrypt elsewhere anyway; seal
them again on the restored host with `secret create`.

`doctor` and `diagnose` count brokered requests the provider refused with 401
or 403. Every layer here succeeded on those, so the cause is the key or the
header convention, not the policy. They also count requests that failed
because the broker did not answer, which points at the broker's unit, not at
the provider.

### What it does not protect

The broker keeps the key out of the workload. It does not stop an agent that
talks to a model provider from writing anything it can read into a prompt;
that channel exists by design. Once a workload's network is filtered, its
mounts are the real boundary around its secrets: whatever you mount into it,
it can send to every host it is allowed to reach.

The broker's own connection to the provider runs under the broker's user, not
the workload's, so a capture of the workload does not show it.

## Applying a change

Apply an edit to any key in this chapter with
`sudo workloadctl recreate <name>`, which regenerates the units. A `restart`
does not, and some changes add or remove units: the inspector, the DNS
responder and a broker each exist only when the configuration calls for
them. `workloadctl drift <name>` shows when the running units are behind the
TOML.

A restart does resolve the names in `allow` and `internal` again, so it is
enough after a destination's address has moved.

## Reading a filter

Four commands answer the questions you have about a filter. Run them as
root: the policy, the record and the counters are readable only by root and
the workload user.

### What may it do: `rules`

```bash
sudo workloadctl rules myvm api.example.com   # what applies to one name
sudo workloadctl rules myvm                   # every literal name in the policy
```

`rules` reports the effective rules, which reading the TOML does not give
you: host patterns combine, and a host any `policy` entry matches ignores
`hosts`. It calls the same matcher the inspector does, so it cannot disagree
with the filter. Asked about one name, it answers even for a name the file
never mentions, which is the form for "why was this refused". Asked with no
name, it goes through every literal host name in the policy and reports how
many wildcard patterns it could not expand.

It says which document it read: the one the inspector was given at its last
start, under `/run/workload-vm/_policy/<name>/`, or a rendering of the TOML for
a workload that has not started this boot. Neither is proof of what the
running inspector holds; `diagnose` checks that. `--json` prints the report
as JSON.

### What did it do: `egress`

```bash
sudo workloadctl egress myvm -n 20             # the last 20 requests
sudo workloadctl egress myvm --decision drop   # only what was refused
sudo workloadctl egress myvm -g --host '*.github.com'
```

`egress` reads the inspector's per-request record: host, method, path,
status, the address actually dialled, timing and a connection id, for allowed
requests as well as refused ones, because what a workload sent cannot be read
from its refusals alone. Filters select by `--decision`, `--mode`
(`forward`, `terminate` or `splice`), `--plane` (`cleartext` or `tls`),
`--reason`, `--host`, `--method`, `--status`, `--id` and a `--since` and
`--until` window; `-g` groups records by connection.

The record lives in `/var/log/workloadctl/egress/<name>/`, readable by root
and the workload user only. It is not in the journal, the workload cannot read
it, and bodies are never recorded. The journal keeps a line per decision, with
the host and the remedy, for watching live.

The record belongs to the workload, not to a container. Every container in a
pod or bridge workload runs as the same user, so the inspector cannot tell
them apart, and a line says this workload asked for that. When the
distinction has to be real, move the container into a workload of its own,
with its own user, policy, record and broker.

### Is it in force: `diagnose`

```bash
sudo workloadctl diagnose myvm
```

The failure `diagnose` exists for is a workload whose configuration says
filtered while the host is not filtering it. Every other signal looks right
when that happens: the unit is active, the workload has network, `status` is
green. So `diagnose` checks that the workload's uid is under the default
deny, that the redirect to its inspector is armed in both families, and that
the inspector's socket is listening. It also checks that the inspector is
enforcing the policy now on disk, and that the CA it presents is the one on
disk.

It reports what the file cannot tell you: hosts whose connections were closed
for not speaking HTTP (the `splice` list), with those named in `policy`
counted apart; requests answered 421, split into allowed names (a client
reusing a connection, which it retries) and unlisted ones (a workload trying
to reach somewhere it was not given); dials to the workload's own inspector on
a port it does not serve; `allow` names that now resolve elsewhere than what
is armed; and a running packet capture. For a VM it prints the management
address and capture group derived from the uid.

The drop counter it prints is shared by every filtered workload on the host,
and `diagnose` says so.

### The counters: `doctor` and Prometheus

`sudo workloadctl doctor <name>` adds an **Egress (inspected)** section for a
filtered workload: connections by disposition, refusals by reason, the
certificate figures, the brokered requests, and the DNS responder's answers
where there is one. They are evidence, never a verdict. A workload being
refused is the filter working, so none of them count as a problem; the
inspector's real faults arrive through the checks.

`workload-exporter` publishes the same figures for Prometheus, labelled
`workload="<name>"`, for filtered VMs and containers alike. The series names
begin `workload_vm_inspect_` and `workload_vm_resolve_`; for instance
`workload_vm_inspect_dropped_total`,
`workload_vm_inspect_drop_events_total{reason="..."}`,
`workload_vm_inspect_record_failures_total` (non-zero means the `egress`
record is incomplete) and `workload_vm_resolve_unlisted_total`. The full list,
with help text, is the `FIGURES` table in `lib/inspect_figures.py`.

## Capturing packets

`workloadctl pcap` captures a workload's traffic. Its surface is tcpdump's,
and the one new idea is that a vantage point is an interface:

```bash
sudo workloadctl pcap -D myvm                          # what this workload offers
sudo workloadctl pcap myvm                             # decode to the terminal
sudo workloadctl pcap -w /var/tmp/cap.pcap myvm
sudo workloadctl pcap -i host -i guest --detach -w /var/tmp/cap myvm
sudo workloadctl pcap --list                           # running captures
sudo workloadctl pcap --stop myvm
```

There are two vantages, and they see different traffic. **host**, the
default, sees the host sockets opened on the workload's behalf, which are the
only place a per-workload capture can come from: once a packet is on the wire
it no longer says which user sent it. **guest** sees the workload's own
packets before passt or pasta translated them, including the DHCP, neighbour
discovery and DNS that passt and pasta answer themselves and that never
become host sockets. For a filtered workload the host vantage shows 80 and
443 already redirected: the destination is the inspector's address, the host
the workload asked for appears only in the TLS server name or the HTTP
request line, and each packet appears twice.

`-D` lists the vantages a workload has and why any are missing: a bridged VM
has no host vantage, and a host-network container has no guest vantage. In a
bridge-mode workload, name the container for a guest capture as
`<workload>/<container>`.

A filter expression works only on a container's guest vantage, which is an
ordinary packet capture. The host vantage reads an nflog device, for which no
filter can be compiled, and a VM's guest vantage is a QEMU dump that takes
only a file and a length; it cannot honour `-Q` or rotate either. A request
that applies a filter, a direction or rotation to a vantage that cannot honour
it is refused, and so is one that would narrow two vantages differently.
Capture unfiltered and narrow when you read the file.

Nothing is written without `-w`; with more than one vantage, `-w` names a
directory. A capture stops after 5 minutes or 100 MB, whichever comes first,
and both vantages stop together so their files cover the same window;
`--duration` and `--max-size` change the bounds. Each packet is cut to 1500
bytes by default, which keeps the TLS server name and the HTTP request line;
`-s 0` keeps whole packets, which a VM's large segments make expensive. The
host vantage can lose packets under load without saying so, so `pcap`
compares the kernel's count with the file when it stops. Timestamps from a
VM's guest vantage are corrected, so the two files line up.

`pcap` adds a logging rule to the host's egress table, which is why it needs
root. `--dry-run` prints the plan, including that rule, before anything is
installed. The capture runs as a transient unit,
`workload-pcap-<name>.service`, which removes the rule when it stops, so an
interrupted session or a reboot leaves nothing behind. The host vantage needs
`tcpdump` installed.

## When a request is refused

The symptom usually says which layer refused. The inspector answers with a
bare status and puts the reason in the journal and the record, so
`sudo workloadctl egress <name> --decision drop` is the first place to look.

| Symptom | Likely cause | What to do |
|---|---|---|
| 403 for a host you meant to allow | the name matches no pattern (often an apex under a wildcard), or a `policy` entry governs the host and refused the method or path | `rules <name> <host>` |
| A closed connection right after the TLS hello | under splice, an unlisted name; or the certificate ration ran out | `egress --decision drop` |
| Certificate errors inside the workload | the workload does not trust its CA: a VM provisioned before it was filtered, a custom seed, a wrong `ca_delivery`, a client with its own root store | `recreate` a VM; fix `ca_delivery`; or splice the host |
| 502 from an allowed host | the origin is down, its certificate fails the host's trust store, it requires a client certificate, or it resolves into private space | the record names which; for private space, an `internal` entry |
| A connection closed after the handshake on an inspected host | the client is not speaking HTTP/1.1 | a `splice` entry; `diagnose` lists the hosts |
| The host answers its own 401 or 403 only when inspected | it offers optional client authentication | a `splice` entry |
| 401 from the provider on a brokered host | the sealed key is wrong or stale, or `auth_header`/`auth_format` is wrong | re-seal the key and restart the workload; check the convention |
| 502 on a brokered host | the broker is not running | `systemctl status workload-<name>-broker.service` |
| A timeout to a port other than 80 or 443 | no `allow` entry, or the entry's name now resolves elsewhere | add the entry; `diagnose`, then restart |
| A filtered container's image pull fails | the registry is not in `hosts` | see [The image pull](#the-image-pull) |
| A bridge-mode container resolves nothing | its LAN resolver meets the default deny | an `allow` entry for the resolver on port 53 |
| "No appropriate name servers" for a `.local` name | the guest sends `.local` to mDNS | a unicast name in the LAN's DNS |
| Some sites are slow | HTTP/3 is dropped and the client falls back to TCP | nothing; it is counted separately |
| The workload will not start, and the journal names an `internal` entry | that name does not resolve, or resolves to a public address | fix the name or drop the entry |

## Break-glass

If the filter itself is the problem, you can remove it from the host. There
are two tables:

```bash
sudo nft delete table inet workload_filter   # the default deny and its guards
sudo nft delete table inet workload_redirect # the redirect to the inspectors
```

Deleting `workload_filter` stops all dropping: the default deny goes, but 80
and 443 are still redirected and still checked by name. Deleting
`workload_redirect` stops the redirect, and with the filter still in place a
filtered workload's 80 and 443 then meet the default deny instead of getting
out. To let everything out, delete both.

Either affects every filtered workload on the host, and the elements each
workload armed go with the table. The next start of a filtered workload
recreates both tables, but only with that workload's own elements. Every
other workload runs without its elements until it is restarted: unfiltered
if the filter table was deleted, cut off from 80 and 443 if the redirect table
was. `diagnose` reports each one as not in force. Workloads that are not
filtered are unaffected either way.
