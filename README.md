# ngbridge

FreeBSD netgraph bridges for jails: create and query `ng_bridge(4)` bridges,
set `ng_bpf(4)` filters from pcap-style expressions, a CNI plugin for podman and
a netavark for the podman network backend of the same name. The classic BPF
programs that `ng_bpf(4)` nodes run are built here too.

The BPF compiler is native Go. Netgraph is driven by executing `ngctl(8)` and
`ifconfig(8)`; a netgraph binding or a native control socket client can replace
that layer later without touching the filter compiler or the command line.

## Status

- pure Go classic BPF compiler (`golang.org/x/net/bpf`), no cgo, no libpcap,
  no tcpdump at runtime; cross-compiles to FreeBSD amd64 and arm64 with
  `CGO_ENABLED=0`
- `ngctl` and `ifconfig` are executed per command
- IPv4 only: IPv6 match criteria are rejected with an error
- no BPF optimizer, so programs are a bit longer than tcpdump's
- the CNI plugin implements `ADD`, `DEL`, `CHECK` and `GC`; `hairpinMode` is
  accepted but not implemented, and `tuning` is Linux-only and out of scope
  (`portmap` works on the result this plugin reports)
- the netavark command implements the `bridge` network driver only: `create`
  fills in the parts netavark fills in as well (the bridge interface, a subnet
  out of the configured pools when none was given, the gateways and the address
  driver), `setup` creates the bridge, moves a port into the jail, installs the
  anti-spoofing filters the CNI plugin installs (`isForceGateway` and
  `isRestrictMulticast` are not implemented), sets the addresses and routes
  podman allocated, and enters them in the `cni-nat` pf table that a masquerading
  rule matches, unless the network is internal or names another table with the
  `nat_table` option (an empty value turns masquerading off), and `teardown`
  removes the port again. Port mappings, DNS and IPv6 are not implemented, and
  there is no IPAM because podman allocates the addresses itself

## Build

```sh
cd ngbridge
go build ./...

go build -o ngbridge .                        # the command, on FreeBSD
go build -o ngbridge-cni ./cmd/ngbridge-cni    # the CNI plugin
go build -o netavark ./cmd/ngbridge-netavark   # the netavark for podman

GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' .
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o ngbridge-cni ./cmd/ngbridge-cni
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o netavark ./cmd/ngbridge-netavark
```

All three binaries are static and cross-compile the same way. `ngbridge-cni` is
what `"type"` names in the CNI configuration, so it goes where the runtime looks
for plugins. The netavark is installed under the name `netavark`, which is what
podman looks for when its network backend is netavark.

## Bridges and ports

```sh
ngbridge bridge list
ngbridge bridge create br0                      # host interface br0, brought up
ngbridge bridge create br1 --iface lan1 --up=false
ngbridge bridge destroy br0

ngbridge port list
ngbridge port list br0
ngbridge port create br0          # next free number above 100
ngbridge port create br0 105      # that number, or fail if taken
ngbridge port destroy br0 3
ngbridge port destroy br0 105 --force   # succeed when the port is already gone

ngbridge filter list
ngbridge filter list br0
ngbridge filter list br0 105
```

A bridge is a `bridge` node named after the bridge plus an `eiface` node named
`<bridge>-if` whose host interface carries the bridge name. A port is an
`eiface` node connected to the bridge through `linkN`, where `N` may be as large
as 999999999 so that a jail id can be used as one; `port create` takes one past
the highest port in use and never a number at or below 100, which is left to
whoever numbers its own ports there (vm-bhyve starts at `link0`). A created port
keeps the name the kernel assigns (`ngethN`) and is left down, ready for
`ifconfig <iface> vnet <jid>`. Port `0` is the host interface and is refused.
`--force` turns "already gone" into success, which is what a repeated CNI `DEL`
looks like.

Discovery goes through `ngctl list` and `ngctl show`, so bridges and ports
created by other tools show up as long as they follow the same `link0` host
interface convention. The interface column is only filled in when the interface
belongs to the network stack `ngbridge` runs in.

Bridges are listed by name, ports by bridge and then by port number:

```
NAME  ID        PORTS  PEER    PEER_ID   INTERFACE  FILTER   FILTER_ID
br0   00000002  1      br0-if  00000001  br0        -        -
br1   00000006  0      ngeth0  00000004  -          bpfhost  00000005
```

```
BRIDGE  PORT  PEER    PEER_ID   INTERFACE  FILTER     FILTER_ID
br0     2     jail0   00000005  -          -          -
br0     3     ngeth0  00000007  ngeth0     bpfngeth3  00000009
```

## Filters

```sh
ngbridge filter set br0 105 --in 'ip src host 10.88.0.23' --out 'ip dst host 10.88.0.23'
ngbridge filter del br0 105
ngbridge filter del br0 105 --force     # succeed when there is no filter
```

`filter set` puts an `ng_bpf` node in front of the port:

```
bridge0:  bridge0 --link2-- [member] ng_bpf [bridge] --link2-- device
                                 |
                               debug
```

`--in` filters what arrives from the port, `--out` what goes out to it. A frame
that is not accepted goes to the `debug` hook instead of being dropped, which
leaves a place to attach a dump later. A direction without an expression
accepts every frame. The node is named `bpf<device node name>`. A port that
already has a filter is reconfigured in place, and a `filter set` that fails
puts the port back as it was. Port `0`, the host interface, is not filtered.

`filter list` prints the decompiled programs, and the expressions it prints are
accepted by `filter set` again:

```
BRIDGE   PORT  FILTER     FILTER_ID  HOOK    PEER     PEER_ID   IFMATCH  IFNOTMATCH  INSNS  EXPRESSION
bridge0  106   bpfngeth1  00000005   bridge  bridge0  00000002  member   debug       26     ip dst host 10.88.0.23
bridge0  106   bpfngeth1  00000005   member  ngeth1   00000004  bridge   debug       26     ip src host 10.88.0.23
```

### Filter expressions

Expressions are the subset of pcap-filter(7) that `internal/cbpf` compiles:

- `ip`, `arp`, `rarp`, `ip multicast`, `ether broadcast`, `ether multicast`,
  and `broadcast` and `multicast` alone for the ethernet ones
- `[ip|arp|rarp] [src|dst] host <ipv4>`, `[src|dst] host <ipv4>` and
  `host <ipv4>` for IPv4, ARP and RARP frames alike, as in libpcap
- `[ip|arp|rarp] [src|dst] net <cidr>` and `[src|dst] net <cidr>`
- `[ether] [src|dst] host <mac>`
- `and`, `or`, `not`, `&&`, `||`, `!` and parentheses
- `len >= 0` for every frame and `len < 0` for none, the two spellings
  `filter list` uses; other length comparisons are refused

Everything else libpcap understands, `port`, `tcp`, `udp`, `proto`, `vlan` and
the like, is rejected with an error naming the keyword. The tests run every one
of these forms through `tcpdump -ddd` and check that both programs accept the
same frames.

## CNI plugin

`cmd/ngbridge-cni` is the CNI plugin that gives a jail its port. It is built
from the same packages as the command but calls them in process, so no table has
to be parsed and one binary does the whole job. A ready-to-use network
configuration is in `etc/bridge0.conflist`:

```json
{
  "cniVersion": "1.0.0",
  "name": "bridge0",
  "plugins": [
    {
      "type": "loopback"
    },
    {
      "type": "ngbridge-cni",
      "bridge": "bridge0",
      "isGateway": true,
      "ipam": {
        "type": "host-local",
        "routes": [{ "dst": "0.0.0.0/0" }],
        "ranges": [[{
          "subnet": "10.89.0.0/16",
          "rangeStart": "10.89.0.21",
          "rangeEnd": "10.89.0.199",
          "gateway": "10.89.0.1"
        }]]
      }
    }
  ]
}
```

- `CNI_CONTAINERID` is the jail name, which `ifconfig -j` and `vnet` accept, and
  `CNI_IFNAME` the name the interface gets inside the jail
- the result names two interfaces, the bridge first and the container interface
  second with the jail as its sandbox, and puts the addresses on the second one.
  Chained plugins that forward ports rely on that shape: the freebsd `portmap`
  forwards through the first interface and only takes an address of an
  interface it can put in a sandbox. A result that names the container
  interface alone leaves it without a host interface and without an address, and
  it then installs no rules at all
- put a loopback plugin in front of this one, so that the jail's `lo0` gets
  `127.0.0.1/8`
- the `bridge` is created when it is needed; the `ipam` plugin is executed for
  `ADD`, `DEL` and `CHECK` and its result is handed on, addresses, routes and
  DNS servers included
- the container side is configured by this plugin, since nothing else does it on
  FreeBSD: address and routes inside the jail, rename, MTU and up. The gateway
  goes on the bridge interface, so the container default route has something to
  resolve. `isGateway` is accepted for compatibility but not needed
- `ipMasq` enters the container address in the pf table a masquerading rule
  matches (`cni-nat`, or `natTable` when it is set); the pf rule itself is not
  created by this plugin
- the container MAC is derived from `name` and the container id (or `mac` from
  the configuration), so it is known before the interface exists; `mtu` defaults
  to the bridge's
- the port is filtered in both directions against spoofing, in two stages: MAC
  only before an address is known, MAC and address afterwards. Rejected frames
  go to the `debug` hook. `isForceGateway` and `isRestrictMulticast` change the
  addresses and the filters accordingly
- without an `ipam` section the plugin falls back to two passes: the first `ADD`
  filters the MAC, a second one after IPAM has given the container its address
  upgrades the filters and reports the address
- what the plugin did is recorded in the atomically written
  `/var/run/cni-ngbridge/<network>/<container>-<ifname>.json`, which `DEL` and
  `CHECK` read; `GC` removes what a `GC` invocation does not name as still valid
- `NGBRIDGE_CNI_STATE_DIR`, `NGBRIDGE_NGCTL`, `NGBRIDGE_IFCONFIG` and `CNI_PATH`
  move the state, the two binaries and the IPAM plugin, which the tests use

IPv6 is not implemented.

## Output

Tables by default, `--json` for the same rows as JSON objects:

```sh
ngbridge --json port list br0
```

```json
[
  {
    "bridge": "br0",
    "port": "105",
    "peer": "ngeth1",
    "peer_id": "00000004",
    "interface": "ngeth1",
    "filter": "bpfngeth3",
    "filter_id": "00000005"
  }
]
```

`bridge create` and `port create` print a single object, `filter list` and
`filter set` print one object per hook, and the destroy commands print nothing.

## Layout

- `internal/cbpf`: filters, `Parse` (pcap filter expressions), code generation,
  `Program` (disassembly, bytes, `ngctl` ASCII form, decompilation) and
  `HookProgram` (parsing `getprogram` replies)
- `internal/ngctl`: `ngctl` invocation, `Script` (several commands in one
  process through `-f -`) and output parsing
- `internal/bridge`: bridges and ports on top of `ngctl`
- `internal/cni`: the CNI plugin, its state files and its environment handling
- `internal/ngsim`: simulated netgraph used by the tests and by `--dry-run`
- `main.go`: command line, output formats
- `cmd/ngbridge-cni`: the CNI plugin binary, see `etc/bridge0.conflist`

## Tests

```sh
go test ./...
```

`internal/cbpf` compares compiled programs against libpcap through `tcpdump
-ddd` for every expression form `filter set` accepts, and the bridge and CNI
tests run against `internal/ngsim`. `--dry-run` seeds that simulation from the
live netgraph, prints every command it would run and applies it to the
simulation only, leaving the live system alone.
