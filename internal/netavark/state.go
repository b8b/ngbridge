package netavark

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// State is what the command recorded for one network of one container, so that
// teardown does not have to look for the port again.
type State struct {
	Network   string       `json:"network"`
	Container string       `json:"container"`
	IfName    string       `json:"ifname"`
	Bridge    string       `json:"bridge"`
	Port      string       `json:"port"`
	Device    string       `json:"device"`
	MAC       string       `json:"mac"`
	Addresses []netAddress `json:"addresses,omitempty"`
	NatTable  string       `json:"nat_table,omitempty"`
}

// stateDir is the directory the state files live in, which is below the netavark
// run directory so that it goes away with it.
func stateDir(configDir string) string {
	return filepath.Join(configDir, "netavark-ngbridge")
}

// statePath is the file that belongs to one network of one container.
func statePath(configDir, network, container string) string {
	return filepath.Join(stateDir(configDir), sanitize(network)+"-"+sanitize(container)+".json")
}

// loadState reports the state of one network of one container and whether it
// exists.
func loadState(configDir, network, container string) (State, bool, error) {
	path := statePath(configDir, network, container)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	state := State{}
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, false, fmt.Errorf("%s: %w", path, err)
	}
	return state, true, nil
}

// saveState writes the state of one network of one container, replacing it when
// it is already there. The file is written next to its final name and renamed,
// so that a crash leaves either the old or the new state and never half of one.
func saveState(configDir string, state State) error {
	path := statePath(configDir, state.Network, state.Container)
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
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// removeState drops the state of one network of one container.
func removeState(configDir, network, container string) error {
	err := os.Remove(statePath(configDir, network, container))
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

// derivedMAC reports the address an interface gets when the request names none:
// a locally administered unicast address derived from the network name and the
// container id, so that a container gets the same address again after a restart.
func derivedMAC(network, container string) string {
	sum := sha256.Sum256([]byte(network + "/" + container))
	address := net.HardwareAddr{0x02, sum[0], sum[1], sum[2], sum[3], sum[4]}
	return address.String()
}
