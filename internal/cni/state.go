package cni

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// State is what the plugin recorded for one container interface, so that DEL
// and CHECK do not have to look for the port again.
type State struct {
	Network   string `json:"network"`
	Container string `json:"container"`
	IfName    string `json:"ifname"`
	Bridge    string `json:"bridge"`
	Port      string `json:"port"`
	Device    string `json:"device"`
	MAC       string `json:"mac"`
	MTU       int    `json:"mtu"`
	IP        string `json:"ip,omitempty"`
}

// StateDir is where the state files live, one per container interface.
const defaultStateDir = "/var/db/cni-ngbridge"

// statePath is the file that belongs to one container interface of a network.
func statePath(dir, network, container, ifName string) string {
	return filepath.Join(dir, sanitize(network), sanitize(container)+"-"+sanitize(ifName)+".json")
}

// loadState reports the state of one container interface and whether it exists.
func loadState(dir, network, container, ifName string) (State, bool, error) {
	data, err := os.ReadFile(statePath(dir, network, container, ifName))
	if os.IsNotExist(err) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	state := State{}
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, false, fmt.Errorf("%s: %w", statePath(dir, network, container, ifName), err)
	}
	return state, true, nil
}

// saveState writes the state of one container interface, replacing it when it
// is already there. The file is written next to its final name and renamed, so
// that a crash leaves either the old or the new state and never half of one.
func saveState(dir string, state State) error {
	path := statePath(dir, state.Network, state.Container, state.IfName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// statesIn reports the state of every container interface of a network.
func statesIn(dir, network string) ([]State, error) {
	entries, err := os.ReadDir(filepath.Join(dir, sanitize(network)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	states := []State{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, sanitize(network), entry.Name()))
		if err != nil {
			return nil, err
		}
		state := State{}
		if err := json.Unmarshal(data, &state); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		states = append(states, state)
	}
	return states, nil
}

// removeState drops the state of one container interface.
func removeState(dir, network, container, ifName string) error {
	err := os.Remove(statePath(dir, network, container, ifName))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// sanitize reduces a name to what a file name can carry.
func sanitize(value string) string {
	clean := make([]rune, 0, len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			clean = append(clean, r)
		default:
			clean = append(clean, '_')
		}
	}
	if len(clean) == 0 {
		return "empty"
	}
	return string(clean)
}

// deriveMAC reports the address the plugin gives an interface when the network
// configuration does not ask for one: a locally administered unicast address
// derived from the network name and the container id, so that the same
// container gets the same address again after a restart.
func deriveMAC(network, container string) (string, error) {
	sum := sha256.Sum256([]byte(network + "/" + container))
	address := net.HardwareAddr{0x02, sum[0], sum[1], sum[2], sum[3], sum[4]}
	return address.String(), nil
}
