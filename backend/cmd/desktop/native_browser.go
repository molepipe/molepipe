//go:build !desktop

package main

// nativeWindow reports that this binary was built WITHOUT the Wails desktop
// build tags. It still runs — which is why `go build ./...` and `go test ./...`
// keep working across the whole module — but it is not the packaged app.
const nativeWindow = false
