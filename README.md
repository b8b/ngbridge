# ngbridge

Creates and filters netgraph bridges on FreeBSD, and builds the classic BPF
programs `ng_bpf(4)` nodes run.

The BPF compiler is native Go. Netgraph is driven by executing `ngctl(8)` and
`ifconfig(8)`; a netgraph binding or a native control socket client can replace
that layer later without touching the filter compiler or the command line.

## Status

- pure Go classic BPF compiler (`golang.org/x/net/bpf`), no cgo, no libpcap,
  no tcpdump at runtime; cross-compiles from Linux to FreeBSD for amd64 and
  arm64 with `CGO_ENABLED=0`
- `ngctl` and `ifconfig` are executed per command
- IPv4 only: IPv6 match criteria are rejected with an error
- no BPF optimizer, so programs are a bit longer than tcpdump's; the
  `ng_bpf(4)` limit is `net.bpf.maxinsns` (512 by default)
- no CNI code yet

## Build

```sh
cd ngbridge
go build ./...
GOOS=freebsd GOARCH=amd64 go build -ldflags='-s -w' .
```

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

ngbridge filter set br0 105 --in 'ip src host 10.88.0.23' --out 'ip dst host 10.88.0.23'
ngbridge filter del br0 105
ngbridge filter del br0 105 --force     # succeed when there is no filter
```

The layout each command produces:

- a bridge is a `bridge` node named after the bridge, plus an `eiface` node
  named `<bridge>-if` whose host interface carries the bridge name, connected
  through the bridge hook `link0`
- a port is an `eiface` node connected to the bridge through `linkN`, where `N`
  is the port number, which may be as large as 999999999 so that a jail id can
  be used as one. `port create br0` takes one past the highest port in use
  and never a number at or below 100, which is left to whoever numbers its own
  ports there (vm-bhyve starts at `link0`); on an empty bridge the first
  allocated port is therefore 101. `port create br0 105` takes that number
  explicitly and fails when it is taken, and `port create br0 5` is still
  allowed. An allocated number is retried up to five times when another process
  takes it between looking and connecting, so concurrent creates on one bridge
  do not fail. The interface keeps the name the kernel assigns (`ngethN`), no filter
  is created, and port `0` is the host interface and refused
- `port create` leaves the interface down, ready to be moved into a vnet jail
  with `ifconfig <iface> vnet <jid>`
- the ethernet node is created by one `ngctl -f -` invocation that runs
  `mkpeer . eiface <hook> ether` and `show -n .:<hook>` together, so the node
  this tool created is found through the hook on its own temporary socket node
  rather than by diffing the node list, which other processes share
- `bridge destroy` shuts down the bridge node and its host interface node;
  `port destroy <bridge> <port>` shuts down the port node, its filter and the
  device behind that filter, so nothing has to be deleted in a particular order
  and a filter that `AnalyzeFilter` does not understand does not keep the port
  alive. `--force` turns "already gone" into success, which is what a repeated
  CNI DEL looks like. Ports are named by the number `port list` shows, `2` or `link2` both
  work; port `0` is the host interface and is refused, destroy the bridge
  instead
- `bridge list` reports the bridge node name and id, the number of ports, and
  for the `link0` side the peer node name and id, its interface name and the
  `ng_bpf` node filtering it with its id, each `-` when it does not apply or
  cannot be resolved The peer behind `link0` is resolved like a port: through an
  `ng_bpf` node when one sits on `link0`, and its interface is only reported
  when it belongs to this network stack
- `port list [bridge]` reports one row per bridge hook: the bridge node name, the port
  number (the hook with its `link` prefix stripped, so `link2` is port 2), the
  node name and id of the device behind the port, its interface name and the
  name and id of the `ng_bpf` node filtering the port, each `-` when it does not
  apply or cannot be resolved
- a peer that is neither an ethernet node nor a filter, for example a `socket`
  node, is reported by its name and id, with no interface and no filter
- a port filtered by an `ng_bpf` node is reported as the device behind the
  filter: the filter's hooks are walked, the hook that leads back to the bridge
  is skipped, the `debug` hook is skipped because what is attached there
  receives the frames the programs rejected, and the first ethernet node found
  is the device. A filter with no
  ethernet node behind it leaves the name and id empty, shown as `-`. The same
  applies to `link0`, so a filtered host interface is still found
- the interface column is only filled in when the interface belongs to the
  network stack `ngbridge` runs in. Interfaces are enumerated with
  `ifconfig -a -D`, which names the driver each interface was created with, and
  the name recorded on the ethernet node is only shown when an interface of
  that name exists locally *and* its driver is an ethernet node driver
  (`ngeth*`). An interface moved into a jail is absent from that list, so it
  shows `-` instead of a name that would point at another network stack. Where
  `-D` is unavailable (13.x), `ifconfig -l` provides plain local names
- `filter list [bridge] [port]` lists the programs of every `ng_bpf` node in
  front of the selected ports, one row per hook of the filter: the bridge and
  port it sits in front of, the filter node and its id, the hook, its peer, the
  program's `ifMatch`/`ifNotMatch`, the instruction count and the decompiled
  filter. `link0` is included and reported as port 0, so a filtered host
  interface shows up as well; ports and host hooks without a filter contribute
  no rows
- a hook without a program of its own carries the kernel default `ret #0`,
  which decompiles to `len < 0` with 1 instruction and no `ifMatch`/`ifNotMatch`
- bridges are listed by name, ports by bridge and then by port number

The lists, and the bridge and port that a create command makes, are printed as
a table: a bridge, a port, and the filter hooks of a port:

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

```
BRIDGE  PORT  HOOK  PEER    PEER_ID
br0     3     jail  ngeth0  00000007
```

```
BRIDGE  PORT  FILTER     FILTER_ID  HOOK    PEER     PEER_ID   IFMATCH  IFNOTMATCH  INSNS  EXPRESSION
br0     105   bpfngeth3  00000005   bridge  br0      00000002  jail     -           28     (ip dst host 10.88.0.23) or ...
br0     105   bpfngeth3  00000005   jail    ngeth1   00000004  bridge   -           28     (ip src host 10.88.0.23) or ...
```

Discovery goes through `ngctl list` and `ngctl show`, so bridges and ports
created by other tools show up as long as they follow the same `link0` host
interface convention.

## Filters

`filter set <bridge> <port> --in <expression> --out <expression>` filters a
port: it puts an `ng_bpf` node in front of one that has none,

```
bridge0:  bridge0 --link2-- [member] ng_bpf [bridge] --link2-- device
                                 |
                               debug
```

- the device is disconnected from the bridge (`ngctl rmhook`), the filter is
  created attached to the device (`ngctl mkpeer <device>: bpf <device hook>
  member`) and the bridge follows (`ngctl connect <filter>: <bridge>: bridge
  linkN`), so the device has a hook again after a single command. Netgraph has
  no operation that replaces a connection: `mkpeer` and `connect` reject a hook
  name that is taken, and a hook is destroyed together with its peer, so a
  disconnected hook never lingers. That leaves one unavoidable gap while the
  device has no hook at all, which `eiface` survives because ng_eiface(4) does
  not go away when all hooks are disconnected. Devices of a node type that does
  shut down on the last hook (ng_bpf, ng_hub, ng_vlan, ...) would not survive
  it
- `ng_bpf(4)` filters what arrives on a hook, so `--in` is the program of the
  member hook (frames coming from the port into the bridge) and `--out` the
  program of the bridge hook (frames going out to the port)
- a program that accepts a frame hands it to the hook facing the other side; a
  frame that is not accepted goes to the `debug` hook instead of being dropped,
  which leaves a place to attach a dump later
- a direction without an expression accepts every frame, so
  `filter set br0 105 --in 'ip src host 10.88.0.23'` only filters what comes in.
  To say so in the text, where a command line needs one, `len >= 0` is accepted;
  it is also what `filter list` prints for a program that accepts everything,
  just as `len < 0` is what it prints for a hook that accepts nothing
- the node is named `bpf<device node name>`, so `bpfngeth3` for `ngeth3`; a
  device without a name keeps its filter unnamed, and the filter is then only
  reachable by id
- a filter node has exactly three kinds of hooks and `AnalyzeFilter` reads them
  that way, for `port list`, `filter list`, `filter set` and `port destroy`
  alike: one hook towards the bridge (the out hook), one hook towards the device
  (the in hook, whose peer is the device), and optionally one hook named
  `debug`, which receives the frames the programs rejected and is otherwise
  ignored. A node with a second hook towards the bridge, no hook towards a
  device or more than one hook towards a device is refused rather than guessed
  at
- only an ethernet node can be put behind a filter: a port whose device is a
  `socket`, `vlan`, `one2many` or any other node type is refused, because
  netgraph cannot move a connection and only `ng_eiface(4)` survives the moment
  its last hook is gone. A filter whose in hook is connected to something other
  than an ethernet node is reported with that peer and type but without an
  interface, and is not reconfigured
- a port that already has an `ng_bpf` node is reconfigured instead: the
  topology is left alone and the programs are installed on the out and in hooks
  the filter has, whatever they are called, with `--out` on the hook facing the
  bridge and `--in` on the hook facing the device
- port `0`, the host interface, is not filtered
- the insertion is undone when a step fails: the filter node is shut down and
  the device is reconnected to the bridge, so a failed `filter set` leaves the
  port as it was

`filter del <bridge> <port>` is the way back (though `port destroy` already
takes the filter with it), and `--force` makes it succeed when there is no
filter to remove: it shuts the filter node down,
which takes both of its connections with it, and connects the device to the
bridge hook the filter used. The device has no hook between those two commands,
which again only `ng_eiface(4)` survives, and whatever was attached to the
filter's `debug` hook is left without one. A port without a filter, a filter
`AnalyzeFilter` does not understand, and a filter whose device is not an
ethernet node are refused, so the command never removes something it cannot put
back together.

`filter list` shows what is installed, and the expressions it prints are
accepted by `filter set` again. `filter set` prints the rows it produced, the
same ones `filter list <bridge> <port>` shows afterwards:

```
# ngbridge filter set bridge0 106 --in 'ip src host 10.88.0.23' --out 'ip dst host 10.88.0.23'
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

The compiler compares against libpcap: the tests run every one of these forms
through `tcpdump -ddd` and check that both programs accept the same frames.
Everything else libpcap understands, `port`, `tcp`, `udp`, `proto`, `vlan` and the like, is rejected with an error
naming the keyword. Raw byte
predicates such as `ether[0:1] & 0x1 = 0`, which the decompiler prints for
filters it cannot name, are not compiled.

## CNI plugin

`cmd/ngbridge-cni` is the CNI plugin that gives a jail its port. It is built from
the same packages as the command but calls them in process, so no table has to
be parsed and one binary does the whole job.

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
- put a loopback plugin in front of this one, so that the jail's `lo0` gets
  `127.0.0.1/8`. Before FreeBSD 15 podman set the loopback up itself, but with
  15 its netmask ended up as `0x0`, which turns the loopback into a route for
  `0.0.0.0/0` and sends everything that is not on-link into `lo0`
- `bridge` is created when it is needed, with its host interface named after it
  and brought up. Whether it is there is decided by `ngctl list`, because
  looking a missing node up by name reports `No such file or directory` on
  FreeBSD rather than naming the node that is missing
- the `ipam` plugin of the configuration is executed for `ADD`, `DEL` and
  `CHECK`, with the configuration as it came in, and its result is handed on:
  the addresses, the routes and the DNS servers all appear in the result of this
  plugin, with the interface index filled in. The first IPv4 address of that
  result is what the anti-spoofing filters allow
- the container side is configured by the plugin, since nothing else does it on
  FreeBSD: the address of the IPAM result is put on the interface inside the
  jail (`ifconfig -j <jail> <ifname> inet <address>/<prefix>`), the routes of
  that result are added there (`route -j <jail> add default <gateway>`), and the
  interface is renamed, gets its MTU and comes up
- the gateway of that result is put on the bridge interface, so the container
  default route has something to resolve. `isGateway` is accepted for
  compatibility but not needed: either there is a gateway or there is not
- `ipMasq` enters the container address in the pf table a masquerading rule
  matches (`pfctl -t cni-nat -T add <address>`), `cni-nat` by default and
  `natTable` when it is set; `DEL` takes the address out again. The pf rule
  itself is not created by this plugin. `hairpinMode` is accepted but not
  implemented, because `ng_bridge(4)` has no hairpin mode
- the container interface gets a locally administered address derived from
  `name` and the container id (or `mac` from the configuration), which is
  deterministic, known before the interface exists and therefore usable in the
  filter right away
- `mtu` is taken from the bridge interface when it is zero, so the container
  never sees a different MTU than the bridge
- the port is filtered in both directions, in two stages. Before an address is
  known only the two ends are pinned (`ether src <container> and ether dst
  <bridge>` in, the reverse out), so the container can reach the host interface
  and nothing else. Once an address exists the incoming filter becomes
  `ether src <container> and src host <ip>`, which pins the MAC and the address
  of the container, ARP sender included, and the outgoing one becomes a list of
  alternatives: `(ether src <bridge> or dst host <ip> or ip multicast)`. The
  outgoing side is deliberately not pinned to the bridge, because another
  container sends with its own MAC and containers may talk to each other.
  Several addresses are joined with `or`; there is never a constant term in the
  expressions. Everything else goes to the `debug` hook
- `isForceGateway` makes everything go through the gateway: the containers get
  `address/32`, a host route to the gateway over the interface, their own subnet
  behind the gateway and then the routes of the IPAM result (so the default
  route resolves its gateway over the interface and not over the loopback), and
  the filters add `and (ether dst <bridge> or dst host <gateway>)` to the
  incoming direction.
  `isRestrictMulticast` replaces the blanket `ip multicast` out and adds
  broadcast/unicast with the multicast networks of the IPAM result in
- without an `ipam` section the plugin falls back to two passes: the first
  `ADD` filters the MAC, a second one after IPAM has given the container its
  address upgrades the filters and reports the address, which is also where the
  address is read from when it is not in the configuration
- what the plugin did is recorded in
  `/var/db/cni-ngbridge/<network>/<container>-<ifname>.json` (port, bridge,
  device, MAC, MTU, address), written atomically before `ADD` returns. `DEL`
  reads it, removes the port and gives the address back to the IPAM plugin, and
  it succeeds when there is nothing left to do; `CHECK` compares the state with
  the port and its filters. Nothing is looked up the other way round, from an
  interface name to a port
- `NGBRIDGE_CNI_STATE_DIR`, `NGBRIDGE_NGCTL`, `NGBRIDGE_IFCONFIG` and `CNI_PATH`
  move the state, the two binaries and the IPAM plugin, which the tests use

- `GC` removes what belongs to attachments that a `GC` invocation does not name
  as still valid: the port with its filter, the address in the masquerading
  table, the reservation of the IPAM plugin and the state file. A configuration
  that carries no `cni.dev/valid-attachments` removes nothing, because guessing
  would delete the ports of running containers; an empty list removes
  everything. Failures are collected so that one broken port does not keep the
  rest of the garbage in place, and the call is forwarded to the IPAM plugin,
  falling back to one `DEL` per stale attachment for plugins that predate `GC`

IPv6 is not implemented. The `portmap` and `tuning` plugins of a typical list are
Linux-only and have to be replaced by whatever does the same on FreeBSD;
`firewall` plugins are outside this one's scope.

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
`filter set` prints exactly what `filter list` shows for the same bridge and
port afterwards.

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
- `cmd/ngbridge-cni`: the CNI plugin binary, see etc/10-ngbridge.conf

## Tests

```sh
go test ./...
```

`internal/cbpf` compares compiled programs against libpcap: for every filter,
and for every expression form `filter set` accepts, it runs `tcpdump -ddd` on
the expression and checks that both programs accept and drop the same synthetic
frames, and that the decompiled expression selects the same frames. Those tests
skip when tcpdump is not installed.

`internal/bridge` drives the bridge, port and filter lifecycle against
`internal/ngsim`, which mimics the parts of netgraph and `ifconfig` these
commands rely on: node naming, hook creation, interface naming and the kernel
default program every `ng_bpf` hook carries.

`--dry-run` seeds a simulated netgraph from the live one (`ngctl list` and
`show`, `getifname` for ethernet nodes), prints every command it would run and
applies it to the simulation only. So commands that change existing nodes print
the right sequence, `ngbridge --dry-run port destroy br0 106` included, and the
live system is left alone. If the live netgraph cannot be read the simulation
starts empty, which still covers commands that only create a bridge, and a note
is printed.
