import Foundation
import Mobile

/// Backend wraps the gomobile-bound Go server (backend/mobile).
///
/// The XCFramework is built by ios/build-xcframework.sh as `Mobile.xcframework`,
/// so the Swift module is `Mobile`. gomobile exposes each exported Go function as
/// a package-prefixed free function — `Start` -> `MobileStart`, `Stop` ->
/// `MobileStop`, `SetDormant` -> `MobileSetDormant` — not as methods on a
/// namespace. A Go `(T, error)` return becomes a Swift throwing function, and Go
/// `int` maps to Swift `Int`.
///
/// BackendService is the single owner of the lifecycle — it is the only thing
/// that calls start/stop. The view only observes via statePublisher, so a
/// re-render can never race the service into a second start.
final class Backend: ObservableObject {

    enum State: Equatable {
        case stopped
        case starting
        case running(url: String)
        case failed(message: String)
    }

    static let shared = Backend()

    @Published private(set) var state: State = .stopped

    private let queue = DispatchQueue(label: "org.molepipe.backend", qos: .userInitiated)
    private var starting = false

    private init() {}

    /// Bring the backend up. Idempotent: a call while starting or already
    /// running is a no-op. MobileStart binds a loopback listener and returns
    /// its URL quickly (no Argon2 / no Tor at this point), but it does file I/O,
    /// so it runs off the main thread.
    func start(dataDir: String) {
        queue.async { [weak self] in
            guard let self = self else { return }
            guard !self.starting, case .stopped = self.state else { return }
            self.starting = true
            DispatchQueue.main.async { self.state = .starting }
            do {
                // Hand the backend our zone before it opens its log: Go's
                // runtime reports UTC for time.Local on mobile regardless of
                // the device setting, so the run log would otherwise be stamped
                // hours from the clock on screen. The offset is a fallback for
                // when the zone itself can't be loaded.
                let tz = TimeZone.current
                MobileSetTimeZone(tz.identifier, tz.secondsFromGMT())
                let url = try MobileStart(dataDir)
                DispatchQueue.main.async {
                    self.state = .running(url: url)
                    self.starting = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.state = .failed(message: error.localizedDescription)
                    self.starting = false
                }
            }
        }
    }

    /// Shut the backend down. Called only from BackendService teardown, and
    /// deliberately blocking: shutdown must finish before the process tears down.
    func stop() {
        do {
            try MobileStop(5000)
        } catch {
            // Best-effort: the process is on its way out regardless.
        }
        DispatchQueue.main.async { self.state = .stopped }
    }

    /// Toggle arti-client's dormant mode. When dormant, proactive background
    /// tasks (preemptive circuit building, directory fetches) are suspended to
    /// conserve CPU and battery. Existing Tor connections stay alive.
    func setDormant(_ dormant: Bool) {
        MobileSetDormant(dormant)
    }
}
