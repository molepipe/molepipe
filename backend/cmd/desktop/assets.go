package main

import "embed"

// bootAssets is a holding page, and deliberately nothing more.
//
// The application's real HTML, CSS and JS are served by api.Server over
// loopback HTTP and are never copied here — one copy of the frontend, and a
// page whose origin the existing guards already accept. See onStartup.
//
//go:embed boot
var bootAssets embed.FS
