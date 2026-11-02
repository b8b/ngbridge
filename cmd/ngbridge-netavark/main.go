// Command ngbridge-netavark is the netavark podman runs on FreeBSD: it connects
// a jail to a netgraph bridge, so that podman works with its netavark network
// backend. It is installed as "netavark", which is the name podman looks for.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/b8b/libjail/ngbridge/internal/netavark"
)

func main() {
	if err := netavark.Run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "netavark: %v\n", err)
		os.Exit(1)
	}
}
