//go:build !molepiperotationprobe

package api

import "net/http"

// registerRotationProbe is a no-op in normal builds. The Phase-A feasibility
// probe is compiled in only under the `molepiperotationprobe` build tag (see
// rotation_probe.go), so no dev endpoint ships in a release build.
func (s *Server) registerRotationProbe(mux *http.ServeMux) {}
