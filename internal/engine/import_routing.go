package engine

import (
	"context"
	"reflect"
	"slices"

	"github.com/sagernet/sing-box/option"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// ValidateImportedProfileRouting checks the options decoded by the current
// core. The wizard retains one outbound or endpoint and assigns its tag, so
// the imported options have no tags they can explicitly reference.
func ValidateImportedProfileRouting(ctx context.Context, config []byte) error {
	found, err := anyProfileField(ctx, config, hasImportedRoutingField)
	if err != nil {
		return err
	}
	if found {
		return model.ErrConnectionRoutingOverride
	}
	return nil
}

// ProfileReferencesOutbound recognizes concrete outbound references in saved
// raw profiles, including selectors and dialers nested within other options.
func ProfileReferencesOutbound(ctx context.Context, config []byte, tags []string) (bool, error) {
	return anyProfileField(ctx, config, func(value reflect.Value) bool {
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if !field.IsExported() || field.Tag.Get("reference") != "outbound" {
				continue
			}
			f := value.Field(i)
			switch f.Kind() {
			case reflect.String:
				if slices.Contains(tags, f.String()) {
					return true
				}
			case reflect.Slice:
				for j := range f.Len() {
					if slices.Contains(tags, f.Index(j).String()) {
						return true
					}
				}
			}
		}
		return false
	})
}

func anyProfileField(ctx context.Context, config []byte, match func(reflect.Value) bool) (bool, error) {
	options, err := decodeOptions(ctx, config)
	if err != nil {
		return false, err
	}
	for _, profile := range options.Outbounds {
		if walkProfileOptions(reflect.ValueOf(profile.Options), match) {
			return true, nil
		}
	}
	for _, profile := range options.Endpoints {
		if walkProfileOptions(reflect.ValueOf(profile.Options), match) {
			return true, nil
		}
	}
	return false, nil
}

// Walk decoded option values so sing-box's schema annotations also cover
// references nested inside dialers and transports. Map keys are data.
func walkProfileOptions(value reflect.Value, match func(reflect.Value) bool) bool {
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		return walkProfileOptions(value.Elem(), match)
	case reflect.Struct:
		if match(value) {
			return true
		}
		for i := range value.NumField() {
			if value.Type().Field(i).IsExported() && walkProfileOptions(value.Field(i), match) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range value.Len() {
			if walkProfileOptions(value.Index(i), match) {
				return true
			}
		}
	case reflect.Map:
		for entries := value.MapRange(); entries.Next(); {
			if walkProfileOptions(entries.Value(), match) {
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
		if field.Tag.Get("reference") != "" && optionValue.Len() > 0 {
			return true
		}
	}
	return false
}
