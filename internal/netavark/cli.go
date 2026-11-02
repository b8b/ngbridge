package netavark

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/b8b/libjail/ngbridge/internal/bridge"
)

// version is what --version reports, which podman shows as the version of the
// network backend.
const version = "ngbridge-netavark 0.1"

// errorMessage is what a failure is reported as. Podman decodes it into the
// error it shows, and it refuses any other key.
type errorMessage struct {
	Error string `json:"error"`
}

// Run implements one invocation of the netavark command line as podman issues
// it: its options, a subcommand, and the request as JSON on the standard input.
// A result and a failure are written as JSON to stdout, the way netavark
// reports them, so that podman can show them.
//
// manager drives netgraph and ifconfig; nil runs ngctl and ifconfig as child
// processes.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, manager *bridge.Manager) error {
	if err := run(ctx, args, stdin, stdout, stderr, manager); err != nil {
		_ = json.NewEncoder(stdout).Encode(errorMessage{Error: err.Error()})
		return err
	}
	return nil
}

// run is Run without the error reporting, which keeps the one place that writes
// an error to stdout.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, manager *bridge.Manager) error {
	flags := flag.NewFlagSet("netavark", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configDir := flags.String("config", "", "directory the runtime state is kept in")
	flags.Bool("rootless", false, "accepted, rootless networking is not implemented")
	flags.String("aardvark-binary", "", "accepted, DNS is not implemented")
	directories := stringList{}
	flags.Var(&directories, "plugin-directory", "accepted, network plugins are not implemented")
	wantedVersion := flags.Bool("version", false, "print the version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *wantedVersion {
		fmt.Fprintln(stdout, version)
		return nil
	}
	commands := flags.Args()
	if len(commands) == 0 {
		return errors.New("no command given")
	}
	p := newPlugin(manager, *configDir)
	switch commands[0] {
	case "setup":
		namespace, err := namespaceOf(commands)
		if err != nil {
			return err
		}
		request, err := readRequest(stdin)
		if err != nil {
			return err
		}
		status, err := p.setup(ctx, request, namespace)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(status)
	case "teardown":
		namespace, err := namespaceOf(commands)
		if err != nil {
			return err
		}
		request, err := readRequest(stdin)
		if err != nil {
			return err
		}
		return p.teardown(ctx, request, namespace)
	case "update":
		if len(commands) < 2 {
			return errors.New("update needs the name of a network")
		}
		return nil
	case "version":
		fmt.Fprintln(stdout, version)
		return nil
	}
	return fmt.Errorf("unknown command %q", commands[0])
}

// namespaceOf reports the jail a subcommand was given, which is what netavark
// calls the path of the network namespace.
func namespaceOf(commands []string) (string, error) {
	if len(commands) < 2 {
		return "", fmt.Errorf("%s needs the jail to work on", commands[0])
	}
	return commands[1], nil
}

// readRequest reads the request podman writes to the standard input.
func readRequest(stdin io.Reader) (*request, error) {
	request := &request{}
	if err := json.NewDecoder(stdin).Decode(request); err != nil {
		return nil, fmt.Errorf("read the request: %w", err)
	}
	return request, nil
}

// stringList collects a flag that may be given more than once.
type stringList []string

// String implements flag.Value.
func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

// Set implements flag.Value.
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}
