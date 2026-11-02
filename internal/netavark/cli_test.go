package netavark

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/b8b/libjail/ngbridge/internal/bridge"
	"github.com/b8b/libjail/ngbridge/internal/ngctl"
	"github.com/b8b/libjail/ngbridge/internal/ngsim"
)

// runCLI runs one invocation the way podman does, with a simulated netgraph.
func runCLI(t *testing.T, args []string, stdin string) (stdout, stderr string, err error) {
	t.Helper()
	sim := ngsim.New()
	manager := &bridge.Manager{Ng: &ngctl.Ngctl{Runner: sim}, Ifconfig: "ifconfig"}
	var out, errs bytes.Buffer
	err = Run(context.Background(), args, strings.NewReader(stdin), &out, &errs, manager)
	return out.String(), errs.String(), err
}

// requestJSON is the request podman writes to the standard input.
func requestJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal the request: %v", err)
	}
	return string(data)
}

// podmanArgs are the options podman puts in front of a subcommand.
func podmanArgs(configDir string, command ...string) []string {
	args := []string{"--config", configDir, "--rootless=false", "--aardvark-binary="}
	return append(args, command...)
}

func TestRunSetup(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, err := runCLI(t, podmanArgs(dir, "setup", "jail1"), requestJSON(t, testRequest()))
	if err != nil {
		t.Fatalf("setup: %v (stderr %q)", err, stderr)
	}
	status := map[string]statusBlock{}
	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		t.Fatalf("decode the status %q: %v", stdout, err)
	}
	iface, ok := status["podman"].Interfaces["eth0"]
	if !ok {
		t.Fatalf("no interface in the status %q", stdout)
	}
	if iface.MacAddress != "02:11:22:33:44:55" {
		t.Errorf("mac %q", iface.MacAddress)
	}
	if len(iface.Subnets) != 1 || iface.Subnets[0].IPNet != "10.88.0.2/16" {
		t.Errorf("addresses %+v", iface.Subnets)
	}
	if _, exists, err := loadState(dir, "podman", "c0ffee"); err != nil || !exists {
		t.Errorf("the state was not written: %v", err)
	}
}

func TestRunSetupListForm(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := runCLI(t, podmanArgs(dir, "setup", "jail1"), requestJSONList)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	status := map[string]statusBlock{}
	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		t.Fatalf("decode the status %q: %v", stdout, err)
	}
	if _, ok := status["podman"].Interfaces["eth0"]; !ok {
		t.Errorf("no interface in the status %q", stdout)
	}
	if _, exists, err := loadState(dir, "podman", "c0ffee"); err != nil || !exists {
		t.Errorf("the state was not written: %v", err)
	}
}

func TestRunCreate(t *testing.T) {
	request := createRequestFor(newNetworkRequest("test"))
	stdout, _, err := runCLI(t, podmanArgs(t.TempDir(), "create"), requestJSON(t, request))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	created := network{}
	if err := json.Unmarshal([]byte(stdout), &created); err != nil {
		t.Fatalf("decode the network %q: %v", stdout, err)
	}
	if created.Name != "test" || created.NetworkInterface != "podman1" {
		t.Errorf("unexpected network %q", stdout)
	}
	if len(created.Subnets) != 1 || created.Subnets[0].Gateway != "10.89.0.1" {
		t.Errorf("subnets %+v", created.Subnets)
	}
}

func TestRunCreateReportsErrors(t *testing.T) {
	request := createRequestFor(newNetworkRequest("test"))
	request.Network.Driver = "macvlan"
	stdout, _, err := runCLI(t, podmanArgs(t.TempDir(), "create"), requestJSON(t, request))
	if err == nil {
		t.Fatal("create succeeded")
	}
	message := errorMessage{}
	if err := json.Unmarshal([]byte(stdout), &message); err != nil {
		t.Fatalf("decode the error %q: %v", stdout, err)
	}
	if !strings.Contains(message.Error, "not implemented") {
		t.Errorf("error %q", message.Error)
	}
}

func TestRunTeardown(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := runCLI(t, podmanArgs(dir, "setup", "jail1"), requestJSON(t, testRequest())); err != nil {
		t.Fatalf("setup: %v", err)
	}
	stdout, _, err := runCLI(t, podmanArgs(dir, "teardown", "jail1"), requestJSON(t, testRequest()))
	if err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if stdout != "" {
		t.Errorf("teardown wrote %q to stdout", stdout)
	}
	if _, exists, err := loadState(dir, "podman", "c0ffee"); err != nil || exists {
		t.Errorf("the state was not removed: %v", err)
	}
}

func TestRunReportsErrorsAsJSON(t *testing.T) {
	for _, test := range []struct {
		name  string
		args  []string
		stdin string
	}{
		{
			name:  "unknown_command",
			args:  podmanArgs(t.TempDir(), "frobnicate"),
			stdin: "{}",
		},
		{
			name:  "no_command",
			args:  podmanArgs(t.TempDir()),
			stdin: "{}",
		},
		{
			name:  "unknown_flag",
			args:  podmanArgs(t.TempDir(), "--no-such-flag", "setup", "jail1"),
			stdin: "{}",
		},
		{
			name:  "broken_request",
			args:  podmanArgs(t.TempDir(), "setup", "jail1"),
			stdin: "{",
		},
		{
			name:  "no_jail",
			args:  podmanArgs(t.TempDir(), "setup"),
			stdin: requestJSON(t, testRequest()),
		},
		{
			name: "unsupported_driver",
			args: podmanArgs(t.TempDir(), "setup", "jail1"),
			stdin: `{"container_id":"c0ffee","networks":{"podman":{"static_ips":["10.88.0.2"]}},` +
				`"network_info":{"podman":{"driver":"macvlan","network_interface":"podman0"}}}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, _, err := runCLI(t, test.args, test.stdin)
			if err == nil {
				t.Fatal("the invocation succeeded")
			}
			message := errorMessage{}
			if err := json.Unmarshal([]byte(stdout), &message); err != nil {
				t.Fatalf("decode the error %q: %v", stdout, err)
			}
			if message.Error == "" {
				t.Errorf("no error message in %q", stdout)
			}
			if strings.Count(strings.TrimSpace(stdout), "\n") != 0 {
				t.Errorf("more than one object on stdout: %q", stdout)
			}
		})
	}
}

func TestRunVersion(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"version"}} {
		stdout, _, err := runCLI(t, args, "")
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if got := strings.TrimSpace(stdout); got != version {
			t.Errorf("%v printed %q, want %q", args, got, version)
		}
	}
}

func TestRunUpdate(t *testing.T) {
	stdout, _, err := runCLI(t, podmanArgs(t.TempDir(), "update", "podman", "--network-dns-servers", "1.1.1.1"), "")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if stdout != "" {
		t.Errorf("update wrote %q to stdout", stdout)
	}
	if _, _, err := runCLI(t, podmanArgs(t.TempDir(), "update"), ""); err == nil {
		t.Error("update without a network succeeded")
	}
}

func TestRunAcceptsRepeatedPluginDirectories(t *testing.T) {
	args := []string{"--config", t.TempDir(), "--plugin-directory", "/usr/local/libexec/cni",
		"--plugin-directory", "/opt/cni/bin", "setup", "jail1"}
	if _, _, err := runCLI(t, args, requestJSON(t, testRequest())); err != nil {
		t.Fatalf("setup: %v", err)
	}
}
