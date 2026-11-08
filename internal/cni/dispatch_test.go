package cni

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

const dispatchConf = `{
  "cniVersion": "1.0.0",
  "name": "jailnet",
  "type": "ngbridge-cni",
  "bridge": "bridge0"
}`

func newDispatchManager() *bridge.Manager {
	return &bridge.Manager{Ng: &ngctl.Ngctl{Runner: ngsim.New()}, Ifconfig: "ifconfig"}
}

func runDispatch(t *testing.T, manager *bridge.Manager, dir, command, stdin string) (string, error) {
	t.Helper()
	t.Setenv("NGBRIDGE_CNI_STATE_DIR", dir)
	t.Setenv("CNI_COMMAND", command)
	t.Setenv("CNI_CONTAINERID", "jail1")
	t.Setenv("CNI_IFNAME", "eth0")
	stdout := &bytes.Buffer{}
	err := Run(context.Background(), strings.NewReader(stdin), stdout, manager)
	return stdout.String(), err
}

func TestDispatchVersion(t *testing.T) {
	out, err := runDispatch(t, newDispatchManager(), t.TempDir(), "VERSION", dispatchConf)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	var info struct {
		CNIVersion        string   `json:"cniVersion"`
		SupportedVersions []string `json:"supportedVersions"`
	}
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("version output %q: %v", out, err)
	}
	if info.CNIVersion == "" || len(info.SupportedVersions) == 0 {
		t.Errorf("unexpected version output %q", out)
	}
}

func TestDispatchAddDelCheck(t *testing.T) {
	dir := t.TempDir()
	manager := newDispatchManager()
	out, err := runDispatch(t, manager, dir, "ADD", dispatchConf)
	if err != nil {
		t.Fatalf("add: %v\n%s%s", err, out, "")
	}
	var result struct {
		Interfaces []struct {
			Name    string `json:"name"`
			Mac     string `json:"mac"`
			Sandbox string `json:"sandbox"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("add output %q: %v", out, err)
	}
	if len(result.Interfaces) != 2 {
		t.Fatalf("unexpected add output %q", out)
	}
	if result.Interfaces[0].Name != "bridge0" || result.Interfaces[0].Sandbox != "" {
		t.Errorf("the bridge interface is not the first one in %q", out)
	}
	container := result.Interfaces[1]
	if container.Name != "eth0" || container.Mac == "" || container.Sandbox != "jail1" {
		t.Errorf("the container interface is not the second one in %q", out)
	}

	out, err = runDispatch(t, manager, dir, "CHECK", dispatchConf)
	if err != nil {
		t.Errorf("check: %v\n%s", err, out)
	}
	out, err = runDispatch(t, manager, dir, "DEL", dispatchConf)
	if err != nil {
		t.Errorf("del: %v\n%s", err, out)
	}
	if out != "" {
		t.Errorf("del printed %q", out)
	}
}

func TestDispatchErrors(t *testing.T) {
	sim := ngsim.New()
	manager := &bridge.Manager{Ng: &ngctl.Ngctl{Runner: sim}, Ifconfig: "ifconfig"}
	t.Setenv("NGBRIDGE_CNI_STATE_DIR", t.TempDir())
	t.Setenv("CNI_COMMAND", "ADD")
	t.Setenv("CNI_CONTAINERID", "jail1")
	t.Setenv("CNI_IFNAME", "eth0")
	stdout := &bytes.Buffer{}
	err := Run(context.Background(), strings.NewReader(`{"cniVersion":"1.0.0","name":"x","type":"ngbridge-cni"}`), stdout, manager)
	if err == nil {
		t.Fatalf("a configuration without a bridge was accepted")
	}
	var reported struct {
		Code uint   `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &reported); err != nil {
		t.Fatalf("error output %q: %v", stdout.String(), err)
	}
	if reported.Code == 0 || !strings.Contains(reported.Msg, "bridge") {
		t.Errorf("unexpected error object %+v", reported)
	}

	t.Setenv("CNI_COMMAND", "")
	stdout.Reset()
	if err := Run(context.Background(), strings.NewReader(dispatchConf), stdout, manager); err == nil {
		t.Errorf("a missing CNI_COMMAND was accepted")
	}
}

func TestDispatchGC(t *testing.T) {
	dir := t.TempDir()
	manager := newDispatchManager()
	if out, err := runDispatch(t, manager, dir, "ADD", dispatchConf); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	// GC needs neither a container id nor an interface name.
	t.Setenv("CNI_CONTAINERID", "")
	t.Setenv("CNI_IFNAME", "")
	t.Setenv("CNI_COMMAND", "GC")
	t.Setenv("NGBRIDGE_CNI_STATE_DIR", dir)
	withList := `{
  "cniVersion": "1.0.0",
  "name": "jailnet",
  "type": "ngbridge-cni",
  "bridge": "bridge0",
  "cni.dev/valid-attachments": []
}`
	stdout := &bytes.Buffer{}
	if err := Run(context.Background(), strings.NewReader(withList), stdout, manager); err != nil {
		t.Fatalf("gc: %v\n%s", err, stdout.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("gc printed %q", stdout.String())
	}
	if ports, err := manager.Ports(context.Background(), "bridge0"); err != nil || len(ports) != 0 {
		t.Errorf("the port survived: %+v, %v", ports, err)
	}
}
