package cni

import (
	"context"
	"errors"
	"fmt"

	"github.com/b8b/libjail/ngbridge/internal/bridge"
)

// GC removes what belongs to container interfaces that are no longer there: the
// port with its filter, the address in the masquerading table, the address
// reservation of the IPAM plugin and the state file itself.
//
// The invocation names the attachments that are still valid. Without that list
// nothing is removed, because a configuration that does not carry it may come
// from a runtime that does not know about garbage collection, and guessing
// would remove ports of running containers.
//
// Everything that fails is collected and reported at the end, so that one
// broken port does not keep the rest of the garbage in place.
func (p *Plugin) GC(ctx context.Context, req Request) error {
	conf := req.Config
	if conf.ValidAttachments == nil {
		return nil
	}
	valid := map[string]bool{}
	for _, attachment := range *conf.ValidAttachments {
		valid[attachment.ContainerID+"/"+attachment.IfName] = true
	}
	states, statesErr := statesIn(p.stateDir(), conf.Name)
	failures := []error{}
	if statesErr != nil {
		failures = append(failures, statesErr)
	}
	// The reservation of an address is the IPAM plugin's business, which the
	// specification asks to forward to. Older plugins have no GC of their own,
	// so their reservations are given back one attachment at a time.
	_, gcErr := p.ipam(ctx, req, "GC")
	if gcErr != nil && !ipamNotSupported(gcErr) {
		failures = append(failures, gcErr)
	}
	releaseEach := gcErr != nil
	for _, state := range states {
		if valid[state.Container+"/"+state.IfName] {
			continue
		}
		if err := p.Manager.DestroyPort(ctx, state.Bridge, state.Port); err != nil &&
			!errors.Is(err, bridge.ErrNotFound) {
			failures = append(failures, fmt.Errorf("remove port %s of bridge %q: %w", state.Port, state.Bridge, err))
		}
		p.removeFromNatTable(ctx, conf, state)
		if releaseEach {
			p.releaseIPAM(ctx, Request{
				Config: conf, ContainerID: state.Container, IfName: state.IfName,
				Path: req.Path, Raw: req.Raw,
			})
		}
		if err := removeState(p.stateDir(), conf.Name, state.Container, state.IfName); err != nil {
			failures = append(failures, fmt.Errorf("remove the state of %s: %w", state.IfName, err))
		}
	}
	return errors.Join(failures...)
}
