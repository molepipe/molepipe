//go:build desktop

package main

// nativeWindow reports that this binary was built with the tags Wails needs to
// draw a real window. Without them Wails still compiles, but falls back to
// opening a browser — a difference worth naming at startup rather than leaving
// someone to discover that the "desktop app" is a browser tab.
const nativeWindow = true
