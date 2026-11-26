package api

import (
	"runtime"
	"runtime/debug"

	"github.com/ordo-systems/keen-proxy/internal/engine"
)

// Release builds link the tag and commit from the same checked-out source.
var releaseVersion, releaseRevision string

// BuildIdentity contains only public metadata about the running executable.
type BuildIdentity struct {
	Version  string `json:"version,omitempty"`
	Variant  string `json:"variant"`
	Arch     string `json:"arch"`
	Revision string `json:"revision,omitempty"`
	Dirty    bool   `json:"dirty,omitempty"`
}

var runningBuild = func() BuildIdentity {
	info, _ := debug.ReadBuildInfo()
	return readRunningBuild(info)
}()

// RunningBuild also supplies the build identity displayed by the operator UI.
func RunningBuild() BuildIdentity { return runningBuild }

func readRunningBuild(info *debug.BuildInfo) BuildIdentity {
	build := BuildIdentity{Version: releaseVersion, Variant: engine.BuildVariant, Arch: runtime.GOARCH, Revision: releaseRevision}
	if info != nil && build.Revision == "" {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				build.Revision = setting.Value
			case "vcs.modified":
				build.Dirty = setting.Value == "true"
			}
		}
	}
	build.Revision = build.Revision[:min(7, len(build.Revision))]
	return build
}
