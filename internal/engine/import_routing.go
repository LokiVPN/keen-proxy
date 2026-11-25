package engine

import (
	"context"
	"reflect"

	"github.com/sagernet/sing-box/option"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// ValidateImportedProfileRouting checks the options decoded by the current
// core. The wizard retains one outbound or endpoint and assigns its tag, so
// the imported options have no tags they can explicitly reference.
func ValidateImportedProfileRouting(ctx context.Context, config []byte) error {
	options, err := decodeOptions(ctx, config)
	if err != nil {
		return err
	}
	for _, profile := range options.Outbounds {
		if hasImportedRoutingOverride(reflect.ValueOf(profile.Options)) {
			return model.ErrConnectionRoutingOverride
		}
	}
	for _, profile := range options.Endpoints {
		if hasImportedRoutingOverride(reflect.ValueOf(profile.Options)) {
			return model.ErrConnectionRoutingOverride
		}
	}
	return nil
}

// Walk decoded option values so sing-box's schema annotations also cover
// references nested inside dialers and transports. Map keys are data.
func hasImportedRoutingOverride(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		return hasImportedRoutingOverride(value.Elem())
	case reflect.Struct:
		return hasImportedRoutingField(value)
	case reflect.Slice, reflect.Array:
		for i := range value.Len() {
			if hasImportedRoutingOverride(value.Index(i)) {
				return true
			}
		}
	case reflect.Map:
		for entries := value.MapRange(); entries.Next(); {
			if hasImportedRoutingOverride(entries.Value()) {
				return true
			}
		}
	}
	return false
}

func hasImportedRoutingField(value reflect.Value) bool {
	switch options := value.Interface().(type) {
	case option.AbstractDialerOptions:
		// Interface binding and host routing belong to KeenProxy.
		if options.BindInterface != "" || options.Inet4BindAddress != nil || options.Inet6BindAddress != nil ||
			options.BindAddressNoPort || options.ProtectPath != "" || options.RoutingMark != 0 ||
			options.NetworkStrategy != nil || len(options.NetworkType) > 0 || len(options.FallbackNetworkType) > 0 {
			return true
		}
	case option.HTTPClientOptions:
		// The string form is decoded into Tag by the option's unmarshaler.
		if options.Tag != "" {
			return true
		}
	case option.CertificateProviderOptions:
		if options.IsShared() {
			return true
		}
	}
	for i := range value.NumField() {
		field := value.Type().Field(i)
		if !field.IsExported() {
			continue
		}
		optionValue := value.Field(i)
		// sing-box annotates references on strings and lists of strings.
		if field.Tag.Get("reference") != "" && optionValue.Len() > 0 || hasImportedRoutingOverride(optionValue) {
			return true
		}
	}
	return false
}
