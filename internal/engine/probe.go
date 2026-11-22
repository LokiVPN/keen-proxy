package engine

import (
	"context"
	"errors"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
)

// WithProbeOutbound starts an isolated profile for one diagnostic. The caller
// supplies profile-only options and bounds how many test engines can run.
func WithProbeOutbound(ctx context.Context, raw []byte, tag string, probe func(adapter.Outbound, context.Context)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(Context(ctx))
	defer cancel()
	options, err := decodeOptions(ctx, raw)
	if err != nil {
		return err
	}
	if len(options.Inbounds) != 0 {
		return errors.New("diagnostic engine cannot open listeners")
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return err
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		return err
	}
	outbound, ok := instance.Outbound().Outbound(tag)
	if !ok {
		return errors.New("diagnostic outbound is unavailable")
	}
	probe(outbound, ctx)
	return nil
}
