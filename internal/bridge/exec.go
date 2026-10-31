package bridge

import (
	"context"
	"strconv"
	"strings"

	"github.com/b8b/libjail/ngbridge/internal/ngctl"
)

// eifaceDriver is the driver name of the interfaces netgraph ethernet nodes
// create, NG_EIFACE_EIFACE_NAME in sys/netgraph/ng_eiface.h.
const eifaceDriver = "ngeth"

// localInterfaces reports the interfaces of the network stack this tool runs
// in, mapped to the driver name they were created with. Interfaces that live
// in another stack, because they were moved into a jail, are absent.
func (m *Manager) localInterfaces(ctx context.Context) map[string]string {
	if out, err := m.run(ctx, m.ifconfigPath(), "-a", "-D"); err == nil {
		if interfaces := parseInterfaceStatus(out); len(interfaces) > 0 {
			return interfaces
		}
	}
	out, err := m.run(ctx, m.ifconfigPath(), "-l")
	if err != nil {
		return nil
	}
	interfaces := make(map[string]string, 16)
	for _, name := range strings.Fields(out) {
		interfaces[name] = ""
	}
	return interfaces
}

// parseInterfaceStatus reads "ifconfig -a -D" output, which is one block per
// interface starting with "name: flags=..." and, when ifconfig can tell, a
// "\tdrivername: name" line naming the interface as it was created.
func parseInterfaceStatus(out string) map[string]string {
	interfaces := make(map[string]string, 16)
	var current string
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			name, _, ok := strings.Cut(line, ":")
			if !ok {
				current = ""
				continue
			}
			current = strings.TrimSpace(name)
			if current != "" {
				interfaces[current] = ""
			}
			continue
		}
		driver, ok := strings.CutPrefix(strings.TrimSpace(line), "drivername:")
		if ok && current != "" {
			interfaces[current] = strings.TrimSpace(driver)
		}
	}
	return interfaces
}

// localInterfaceName reports name when an interface with that name is part of
// this network stack. The driver name, when ifconfig reports one, has to be an
// ethernet node driver, so that an unrelated local interface that happens to
// carry the name an ethernet node remembers is not mistaken for the node.
func localInterfaceName(interfaces map[string]string, name string) string {
	if name == "" {
		return ""
	}
	driver, ok := interfaces[name]
	if !ok {
		return ""
	}
	if driver != "" && !strings.HasPrefix(driver, eifaceDriver) {
		return ""
	}
	return name
}

// RunIfconfig runs ifconfig with the arguments given, so that a caller that owns
// the interface policy of a port can use the same runner as this package. The
// output is returned as it is.
func (m *Manager) RunIfconfig(ctx context.Context, args ...string) (string, error) {
	return m.run(ctx, m.ifconfigPath(), args...)
}

// InterfaceMTU reports the MTU of the interface named name in the network stack
// this tool runs in, or zero when it cannot be read.
func (m *Manager) InterfaceMTU(ctx context.Context, name string) int {
	out, err := m.RunIfconfig(ctx, name)
	if err != nil {
		return 0
	}
	return parseMTU(out)
}

// parseMTU reads the MTU out of the first line of ifconfig output, which reads
// "name: flags=... metric 0 mtu 1500".
func parseMTU(out string) int {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "mtu" {
			continue
		}
		if mtu, err := strconv.Atoi(fields[i+1]); err == nil {
			return mtu
		}
	}
	return 0
}

func (m *Manager) ifconfigPath() string {
	if m.Ifconfig == "" {
		return "ifconfig"
	}
	return m.Ifconfig
}

func (m *Manager) run(ctx context.Context, binary string, args ...string) (string, error) {
	runner := m.Ng.Runner
	if runner == nil {
		runner = ngctl.ExecRunner{}
	}
	out, err := runner.Run(ctx, binary, args...)
	return string(out), err
}
