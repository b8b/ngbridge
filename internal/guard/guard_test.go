package guard

import "testing"

func TestInAndOut(t *testing.T) {
	const jailMAC = "02:00:00:00:00:05"
	const bridgeMAC = "02:00:00:00:00:01"
	addresses := []Address{{Address: "10.89.0.21", Gateway: "10.89.0.1"}}
	for _, test := range []struct {
		name string
		rule Rule
		in   string
		out  string
	}{
		{
			name: "only the mac, no address yet",
			rule: Rule{JailMAC: jailMAC, BridgeMAC: bridgeMAC},
			in:   "ether src " + jailMAC + " and ether dst " + bridgeMAC,
			out:  "ether src " + bridgeMAC + " and ether dst " + jailMAC,
		},
		{
			name: "with an address",
			rule: Rule{JailMAC: jailMAC, BridgeMAC: bridgeMAC, Addresses: addresses},
			in:   "ether src " + jailMAC + " and src host 10.89.0.21",
			out:  "(ether src " + bridgeMAC + " or dst host 10.89.0.21 or ip multicast)",
		},
		{
			name: "without the mac of the bridge",
			rule: Rule{JailMAC: jailMAC, Addresses: addresses},
			in:   "ether src " + jailMAC + " and src host 10.89.0.21",
			out:  "(dst host 10.89.0.21 or ip multicast)",
		},
		{
			name: "several addresses",
			rule: Rule{JailMAC: jailMAC, BridgeMAC: bridgeMAC, Addresses: []Address{
				{Address: "10.89.0.21", Gateway: "10.89.0.1"},
				{Address: "10.90.0.21", Gateway: "10.90.0.1"},
			}},
			in: "ether src " + jailMAC + " and (src host 10.89.0.21 or src host 10.90.0.21)",
			out: "(ether src " + bridgeMAC + " or dst host 10.89.0.21 or dst host 10.90.0.21" +
				" or ip multicast)",
		},
		{
			name: "force gateway",
			rule: Rule{JailMAC: jailMAC, BridgeMAC: bridgeMAC, Addresses: addresses, ForceGateway: true},
			in: "ether src " + jailMAC + " and src host 10.89.0.21" +
				" and (ether dst " + bridgeMAC + " or dst host 10.89.0.1)",
			out: "(ether src " + bridgeMAC + " or dst host 10.89.0.21 or ip multicast)",
		},
		{
			name: "restricted multicast",
			rule: Rule{JailMAC: jailMAC, BridgeMAC: bridgeMAC, Addresses: addresses,
				RestrictMulticast: true, Networks: []string{"224.0.0.0/4"}},
			in: "ether src " + jailMAC + " and src host 10.89.0.21" +
				" and (ether broadcast or not ether multicast or dst net 224.0.0.0/4)",
			out: "(ether src " + bridgeMAC + " or dst host 10.89.0.21 or dst net 224.0.0.0/4)",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.rule.In(); got != test.in {
				t.Errorf("in %q, want %q", got, test.in)
			}
			if got := test.rule.Out(); got != test.out {
				t.Errorf("out %q, want %q", got, test.out)
			}
		})
	}
}
