import Foundation

/// Backend wraps the gomobile-bound Go server (backend/mobile).
///
/// The XCFramework is built by ios/build-xcframework.sh; Go's package `mobile`
/// binds to Swift class `Mobile`; exported funcs bind with a lowercased first
/// letter (Start -> start, Stop -> stop, IsRunning -> isRunning); and Go `int`
/// binds to Swift `Int32`.
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
    /// running is a no-op. Mobile.start binds a loopback listener and returns
    /// its URL quickly (no Argon2 / no Tor at this point), but it does file I/O,
    /// so it runs off the main thread.
    func start(dataDir: String) {
        queue.async { [weak self] in
            guard let self = self else { return }
            guard !self.starting, case .stopped = self.state else { return }
            self.starting = true
            DispatchQueue.main.async { self.state = .starting }
            do {
                let url = Mobile.start(dataDir)
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
            try Mobile.stop(5000)
        } catch {
            // Best-effort: the process is on its way out regardless.
        }
        DispatchQueue.main.async { self.state = .stopped }
    }

    /// Toggle arti-client's dormant mode. When dormant, proactive background
    /// tasks (preemptive circuit building, directory fetches) are suspended to
    /// conserve CPU and battery. Existing Tor connections stay alive.
    func setDormant(_ dormant: Bool) {
        Mobile.setDormant(dormant)
    }
}
