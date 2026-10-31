package cni

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	current "github.com/containernetworking/cni/pkg/types/100"
	version2 "github.com/containernetworking/cni/pkg/version"
)

// defaultPluginPath is where the CNI plugins live on FreeBSD, used when the
// runtime does not set CNI_PATH.
const defaultPluginPath = "/usr/local/libexec/cni"

// ipam runs the IPAM plugin the configuration names with the given command and
// reports its result, which is empty when the configuration has no IPAM.
//
// The delegation is done here instead of in the library, because the library's
// helper for it is not part of the module this plugin can build for FreeBSD.
func (p *Plugin) ipam(ctx context.Context, req Request, command string) (*current.Result, error) {
	if req.Config.IPAM.Type == "" {
		return nil, nil
	}
	path, err := findPlugin(req.Path, req.Config.IPAM.Type)
	if err != nil {
		return nil, fmt.Errorf("ipam %q: %w", req.Config.IPAM.Type, err)
	}
	stdout, err := runPlugin(ctx, path, req, command)
	if err != nil {
		return nil, fmt.Errorf("ipam %q %s: %w", req.Config.IPAM.Type, command, err)
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, nil
	}
	version := req.Config.CNIVersion
	if version == "" {
		version = "1.0.0"
	}
	parsed, err := parseResult(version, stdout)
	if err != nil {
		return nil, fmt.Errorf("ipam %q %s: %w", req.Config.IPAM.Type, command, err)
	}
	return parsed, nil
}

// runPlugin executes a CNI plugin the way the specification describes.
func runPlugin(ctx context.Context, path string, req Request, command string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = bytes.NewReader(req.Raw)
	cmd.Env = append(os.Environ(),
		"CNI_COMMAND="+command,
		"CNI_CONTAINERID="+req.ContainerID,
		"CNI_NETNS="+req.NetNS,
		"CNI_IFNAME="+req.IfName,
		"CNI_ARGS="+req.Args,
		"CNI_PATH="+req.Path,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = strings.TrimSpace(stdout.String())
		}
		if message == "" {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", err, message)
	}
	return stdout.Bytes(), nil
}

// findPlugin looks the plugin up in the paths the runtime provides.
func findPlugin(paths, name string) (string, error) {
	if paths == "" {
		paths = defaultPluginPath
	}
	searched := []string{}
	for _, dir := range filepath.SplitList(paths) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		searched = append(searched, candidate)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("not found in %s", strings.Join(searched, ", "))
}

// parseResult reads the result of a delegated plugin and reports it in the
// version this package works with.
func parseResult(version string, data []byte) (*current.Result, error) {
	parsed, err := version2.NewResult(version, data)
	if err != nil {
		return nil, err
	}
	return current.NewResultFromResult(parsed)
}

// removeIPAM gives the address of a container back, which is part of DEL.
func (p *Plugin) removeIPAM(ctx context.Context, req Request) error {
	result, err := p.ipam(ctx, req, "DEL")
	_ = result
	if err != nil && !ipamNotSupported(err) {
		return err
	}
	return nil
}

// checkIPAM asks the IPAM plugin whether the address is still there. Plugins
// that do not implement CHECK are not an error, since the specification leaves
// it optional.
func (p *Plugin) checkIPAM(ctx context.Context, req Request) error {
	_, err := p.ipam(ctx, req, "CHECK")
	if err != nil && !ipamNotSupported(err) {
		return err
	}
	return nil
}

// ipamNotSupported recognises the answer a plugin gives for a command it does
// not implement.
func ipamNotSupported(err error) bool {
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"unknown cni_command", "not implemented", "not supported",
		"convert: unknown result version", "unsupported version",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
