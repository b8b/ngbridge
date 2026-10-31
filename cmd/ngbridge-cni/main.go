// Command ngbridge-cni is the CNI plugin that gives a jail a bridged port on a
// netgraph bridge, with anti-spoofing filters for the MAC and the address of
// the container.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/b8b/libjail/ngbridge/internal/cni"
)

func main() {
	if err := cni.Run(context.Background(), os.Stdin, os.Stdout, cni.NewManager()); err != nil {
		fmt.Fprintf(os.Stderr, "ngbridge-cni: %v\n", err)
		os.Exit(1)
	}
}
