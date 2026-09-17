# Contributing to Molepipe

## Development Setup

### Prerequisites

- **Go 1.26+**
- **Rust** (for the torhost crate on Android)
- **Android Studio + NDK** (for Android builds)
- **Node.js** (for material-color-utilities theme generation only)

### Desktop Development

```sh
cd backend

# Run unit tests
go test ./...

# Run end-to-end self-test
go run ./cmd/tormsg selftest

# Run headless server (opens browser)
go run ./cmd/server

# Run desktop build (requires GTK/WebKit dev packages)
CGO_ENABLED=1 go run -tags "desktop production webkit2_41" ./cmd/desktop
```

### Android Development

```sh
# Build the gomobile AAR (requires Rust, cargo-ndk, Android NDK)
./android/build-aar.sh

# Open in Android Studio
open android/
```

## Project Structure

```
backend/
├── cmd/              Entry points
│   ├── server/       Headless HTTP server
│   ├── desktop/      Wails native window + tray
│   ├── tormsg/       CLI test harness
│   ├── mailbox/      Standalone mailbox server
│   └── update-manifest/  Offline signing tool
├── internal/         Core packages
│   ├── crypto/       BIP39, SLIP-0010, AES-GCM, XChaCha20, Argon2id
│   ├── protocol/     Peer protocol (handshake, messages, groups)
│   ├── api/          HTTP API + embedded UI
│   ├── chatstore/    Encrypted contacts + messages
│   ├── tor/          Onion service interface
│   ├── mailbox/      Store-and-forward server
│   └── ...           Other internal packages
├── mobile/           gomobile bindings for Android
└── go.mod

android/              Kotlin/Compose Android app
torhost/              Rust crate (Arti C-ABI shim)
docs/                 Architecture, protocol, threat model
tools/                Build scripts
```

## Code Style

- Follow existing patterns in the codebase
- Use standard Go conventions (`gofmt`, `go vet`)
- Keep internal packages truly internal — no leaking implementation details
- Cryptographic context strings (`"onion-chat/v1 ..."`) are frozen and must not be changed without versioning

## Testing

```sh
# Unit tests
cd backend && go test ./...

# End-to-end self-test
go run ./cmd/tormsg selftest

# Android instrumented tests
cd android && ./gradlew connectedAndroidTest
```

## Pull Requests

1. Fork the repository and create a feature branch
2. Make your changes following the code style
3. Add tests for new functionality
4. Ensure all tests pass (`go test ./...`)
5. Update documentation if your change affects the public API or protocol
6. Submit a pull request with a clear description

## Security-Related Contributions

If your contribution relates to security (crypto, authentication, protocol changes):

- Explain the security rationale in the PR description
- Note any protocol compatibility implications
- Ensure backward compatibility or clearly document the breaking change
- Do not commit secrets, private keys, or credentials

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- For security vulnerabilities, see [`SECURITY.md`](SECURITY.md)
- Include steps to reproduce for bug reports
- Mention your OS, Go version, and build method

## License

By contributing, you agree that your contributions will be licensed under the project's license (to be determined).
