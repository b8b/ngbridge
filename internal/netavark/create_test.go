package netavark

import (
	"strings"
	"testing"
)

// createRequestFor is what podman sends for "create" with the given network.
func createRequestFor(network network) *createRequest {
	return &createRequest{
		Network: network,
		Used: usedNetworks{
			Interfaces: []string{},
			Names:      map[string]string{"podman": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9"},
			Subnets:    []string{"10.88.0.0/16"},
		},
		Options: createOptions{
			SubnetPools: []subnetPool{
				{Base: "10.88.0.0/16", Size: 24},
				{Base: "10.89.0.0/16", Size: 24},
				{Base: "10.90.0.0/16", Size: 24},
			},
			DefaultInterfaceName: "podman",
			CheckUsedSubnets:     true,
		},
	}
}

// newNetworkRequest is a network as podman builds it for "podman network
// create", before netavark fills in the rest.
func newNetworkRequest(name string) network {
	return network{
		Name:        name,
		ID:          strings.Repeat("ab", 32),
		Driver:      bridgeDriver,
		Labels:      map[string]string{},
		Options:     map[string]string{},
		IPAMOptions: map[string]string{},
		DNSEnabled:  true,
	}
}

func TestCreateFillsInInterfaceSubnetAndGateway(t *testing.T) {
	plugin, _ := newTestPlugin(t)

	created, err := plugin.create(createRequestFor(newNetworkRequest("test")))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Name != "test" || len(created.ID) != 64 || created.Driver != bridgeDriver {
		t.Errorf("unexpected network %+v", created)
	}
	if created.NetworkInterface != "podman1" {
		t.Errorf("interface %q, want podman1", created.NetworkInterface)
	}
	if len(created.Subnets) != 1 {
		t.Fatalf("subnets %+v", created.Subnets)
	}
	if created.Subnets[0].Subnet != "10.89.0.0/24" {
		t.Errorf("subnet %q, want the first free pool block", created.Subnets[0].Subnet)
	}
	if created.Subnets[0].Gateway != "10.89.0.1" {
		t.Errorf("gateway %q", created.Subnets[0].Gateway)
	}
	if created.IPAMOptions["driver"] != homeLocalIPAM {
		t.Errorf("address driver %v", created.IPAMOptions)
	}
	if created.Created == "" {
		t.Error("the network has no creation time")
	}
}

func TestCreateKeepsWhatItIsGiven(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	request := createRequestFor(newNetworkRequest("test"))
	request.Network.NetworkInterface = "br7"
	request.Network.Subnets = []subnet{{Subnet: "10.99.0.0/24"}}
	request.Used.Interfaces = []string{"podman1", "podman2"}

	created, err := plugin.create(request)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.NetworkInterface != "br7" {
		t.Errorf("interface %q", created.NetworkInterface)
	}
	if len(created.Subnets) != 1 || created.Subnets[0].Subnet != "10.99.0.0/24" {
		t.Errorf("subnets %+v", created.Subnets)
	}
	if created.Subnets[0].Gateway != "10.99.0.1" {
		t.Errorf("gateway %q", created.Subnets[0].Gateway)
	}
}

func TestCreateNumbersTheNextFreeInterface(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	request := createRequestFor(newNetworkRequest("test"))
	request.Used.Interfaces = []string{"podman1"}
	request.Used.Names = map[string]string{"other": "id", "podman2": "id"}

	created, err := plugin.create(request)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.NetworkInterface != "podman3" {
		t.Errorf("interface %q, want podman3", created.NetworkInterface)
	}
}

func TestCreateWithoutGatewayForAnInternalNetwork(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	request := createRequestFor(newNetworkRequest("test"))
	request.Network.Internal = true
	request.Network.DNSEnabled = false
	request.Network.Subnets = []subnet{{Subnet: "10.99.0.0/24"}}

	created, err := plugin.create(request)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Subnets[0].Gateway != "" {
		t.Errorf("gateway %q, want none on an internal network", created.Subnets[0].Gateway)
	}
}

func TestCreateWithoutAddresses(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	request := createRequestFor(newNetworkRequest("test"))
	request.Network.IPAMOptions = map[string]string{"driver": ipamNone}

	created, err := plugin.create(request)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(created.Subnets) != 0 || created.NetworkInterface != "podman1" {
		t.Errorf("unexpected network %+v", created)
	}
}

func TestCreateUsesDockerOptions(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	request := createRequestFor(newNetworkRequest("test"))
	request.Network.Options = map[string]string{
		"com.docker.network.bridge.name": "br9",
		"com.docker.network.driver.mtu":  "1400",
	}

	created, err := plugin.create(request)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.NetworkInterface != "br9" {
		t.Errorf("interface %q, want the one the docker option names", created.NetworkInterface)
	}
	if created.Options[mtuOption] != "1400" {
		t.Errorf("options %v, want the mtu", created.Options)
	}
}

func TestCreateRejectsRequests(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(*createRequest)
		want  string
	}{
		{
			name:  "no_name",
			build: func(r *createRequest) { r.Network.Name = "" },
			want:  "no name",
		},
		{
			name:  "bad_name",
			build: func(r *createRequest) { r.Network.Name = "not/a/name" },
			want:  "invalid characters in network name",
		},
		{
			name:  "existing_name",
			build: func(r *createRequest) { r.Network.Name = "podman" },
			want:  "network already exists",
		},
		{
			name:  "short_id",
			build: func(r *createRequest) { r.Network.ID = "abcd" },
			want:  "64 characters",
		},
		{
			name:  "id_not_hex",
			build: func(r *createRequest) { r.Network.ID = strings.Repeat("zz", 32) },
			want:  "hexadecimal",
		},
		{
			name:  "unsupported_driver",
			build: func(r *createRequest) { r.Network.Driver = "macvlan" },
			want:  "is not implemented",
		},
		{
			name:  "IPv6",
			build: func(r *createRequest) { r.Network.IPv6Enabled = true },
			want:  "IPv6 is not implemented",
		},
		{
			name: "interface_in_use",
			build: func(r *createRequest) {
				r.Network.NetworkInterface = "podman1"
				r.Used.Interfaces = []string{"podman1"}
			},
			want: "already in use",
		},
		{
			name:  "interface_too_long",
			build: func(r *createRequest) { r.Network.NetworkInterface = "abcdefghijklmnop" },
			want:  "longer than 15 characters",
		},
		{
			name:  "no_default_interface_name",
			build: func(r *createRequest) { r.Options.DefaultInterfaceName = "" },
			want:  "default interface name",
		},
		{
			name:  "no_pools",
			build: func(r *createRequest) { r.Options.SubnetPools = nil },
			want:  "no free subnet",
		},
		{
			name: "all_pools_used",
			build: func(r *createRequest) {
				r.Used.Subnets = []string{"10.88.0.0/16", "10.89.0.0/16", "10.90.0.0/16"}
			},
			want: "no free subnet",
		},
		{
			name: "ipam_none_with_subnets",
			build: func(r *createRequest) {
				r.Network.IPAMOptions = map[string]string{"driver": ipamNone}
				r.Network.Subnets = []subnet{{Subnet: "10.99.0.0/24"}}
			},
			want: "subnets are given",
		},
		{
			name: "gateway_outside_the_subnet",
			build: func(r *createRequest) {
				r.Network.Subnets = []subnet{{Subnet: "10.99.0.0/24", Gateway: "10.98.0.1"}}
			},
			want: "is not in subnet",
		},
		{
			name: "bad_mtu",
			build: func(r *createRequest) {
				r.Network.Options = map[string]string{mtuOption: "big"}
			},
			want: "not an MTU",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			plugin, _ := newTestPlugin(t)
			request := createRequestFor(newNetworkRequest("test"))
			test.build(request)
			_, err := plugin.create(request)
			if err == nil {
				t.Fatal("create succeeded")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error %q, want %q", err, test.want)
			}
		})
	}
}

func TestCreateDoesNotCheckUsedSubnets(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	request := createRequestFor(newNetworkRequest("test"))
	request.Options.CheckUsedSubnets = false

	created, err := plugin.create(request)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Subnets[0].Subnet != "10.88.0.0/24" {
		t.Errorf("subnet %q, want the first block of the first pool", created.Subnets[0].Subnet)
	}
}
