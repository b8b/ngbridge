package cni

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/b8b/libjail/ngbridge/internal/bridge"
	"github.com/b8b/libjail/ngbridge/internal/ngctl"
)

// environment is what the container runtime tells a CNI plugin.
type environment struct {
	Command     string
	ContainerID string
	NetNS       string
	IfName      string
	Args        string
	Path        string
}

func environmentFromEnv() (environment, error) {
	env := environment{
		Command:     os.Getenv("CNI_COMMAND"),
		ContainerID: os.Getenv("CNI_CONTAINERID"),
		NetNS:       os.Getenv("CNI_NETNS"),
		IfName:      os.Getenv("CNI_IFNAME"),
		Args:        os.Getenv("CNI_ARGS"),
		Path:        os.Getenv("CNI_PATH"),
	}
	if env.Command == "" {
		return env, fmt.Errorf("CNI_COMMAND is not set")
	}
	return env, nil
}

// Run runs one CNI invocation: it reads the network configuration from stdin,
// calls the command Handler and writes the result to stdout. Errors are
// reported as the error object the specification asks for.
func Run(ctx context.Context, stdin io.Reader, stdout io.Writer, manager *bridge.Manager) error {
	env, err := environmentFromEnv()
	if err != nil {
		return printError(stdout, types.NewError(types.ErrInvalidEnvironmentVariables, err.Error(), ""))
	}
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return printError(stdout, types.NewError(types.ErrIOFailure, "read the configuration", err.Error()))
	}
	conf := &Config{}
	if err := json.Unmarshal(raw, conf); err != nil {
		return printError(stdout, types.NewError(types.ErrDecodingFailure, "network configuration", err.Error()))
	}
	if env.Command == "VERSION" {
		return versionInfo(stdout)
	}
	plugin := &Plugin{Manager: manager, StateDir: stateDirFromEnv()}
	switch env.Command {
	case "ADD", "DEL", "CHECK", "GC":
	default:
		return printError(stdout, types.NewError(types.ErrInvalidEnvironmentVariables,
			"unknown CNI_COMMAND "+env.Command, ""))
	}
	if err := conf.Validate(); err != nil {
		return printError(stdout, types.NewError(types.ErrInvalidNetworkConfig, err.Error(), ""))
	}
	req := Request{
		Config: conf, ContainerID: env.ContainerID, IfName: env.IfName,
		NetNS: env.NetNS, Args: env.Args, Path: env.Path, Raw: raw,
	}
	if env.Command == "GC" {
		if err := plugin.GC(ctx, req); err != nil {
			return printError(stdout, types.NewError(types.ErrInternal, err.Error(), ""))
		}
		return nil
	}
	if env.ContainerID == "" || env.IfName == "" {
		return printError(stdout, types.NewError(types.ErrInvalidEnvironmentVariables,
			"CNI_CONTAINERID and CNI_IFNAME are needed", ""))
	}
	var result *current.Result
	switch env.Command {
	case "ADD":
		result, err = plugin.Add(ctx, req)
	case "DEL":
		err = plugin.Del(ctx, req)
	case "CHECK":
		err = plugin.Check(ctx, req)
	}
	if err != nil {
		return printError(stdout, types.NewError(types.ErrInternal, err.Error(), ""))
	}
	if result == nil {
		return nil
	}
	requested := conf.CNIVersion
	if requested == "" {
		requested = version.Current()
	}
	if err := printResult(stdout, result, requested); err != nil {
		return printError(stdout, types.NewError(types.ErrInternal, "print the result", err.Error()))
	}
	return nil
}

// printResult writes the result in the version the runtime asked for.
func printResult(w io.Writer, result *current.Result, requested string) error {
	converted, err := result.GetAsVersion(requested)
	if err != nil {
		return err
	}
	return converted.PrintTo(w)
}

// versionInfo reports the specification versions this plugin speaks.
func versionInfo(stdout io.Writer) error {
	info, err := json.Marshal(map[string]any{
		"cniVersion": version.Current(),
		"supportedVersions": []string{
			"0.4.0", "1.0.0", "1.1.0",
		},
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(info))
	return err
}

// printError writes the CNI error object and reports the error, so that the
// caller can exit with a failure status.
func printError(stdout io.Writer, cniErr *types.Error) error {
	data, err := json.Marshal(cniErr)
	if err != nil {
		return cniErr
	}
	fmt.Fprintln(stdout, string(data))
	return cniErr
}

// NewManager returns the manager the plugin drives, with ngctl and ifconfig
// from the environment when they are set.
func NewManager() *bridge.Manager {
	ng := ngctl.New()
	if path := strings.TrimSpace(os.Getenv("NGBRIDGE_NGCTL")); path != "" {
		ng.Path = path
	}
	manager := bridge.New(ng)
	if path := strings.TrimSpace(os.Getenv("NGBRIDGE_IFCONFIG")); path != "" {
		manager.Ifconfig = path
	}
	return manager
}
