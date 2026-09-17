import Foundation
import UIKit
import UserNotifications
import Mobile

/// BackendService manages the background lifecycle of the Go backend, mirroring
/// Android's BackendService (foreground service + wake lock). On iOS we use
/// BGTaskScheduler for Tor maintenance and beginBackgroundTask for short-lived
/// shutdown work.
///
/// Load-bearing lifecycle rule (mirrors Android's BackendService):
/// the user closing the app (scenePhase → background) does NOT stop the backend
/// — a messenger must keep receiving. The ONLY path that stops it is when the
/// OS reclaims background time or the user explicitly kills the app.
final class BackendService {

    static let shared = BackendService()

    private var backgroundTaskID: UIBackgroundTaskIdentifier = .invalid
    private var isRunning = false

    private init() {}

    /// Start the backend and register the message listener. Call from
    /// scenePhase == .active or app launch.
    func start() {
        guard !isRunning else { return }
        isRunning = true

        let backend = Backend.shared
        backend.start(dataDir: Self.dataDir())

        // Register the message listener for system notifications.
        Mobile.setMessageListener(NotificationHandler.shared)
    }

    /// Tear down the backend. Must be called synchronously — the shutdown must
    /// complete before the process is allowed to die, exactly as Android runs
    /// Backend.stop() in onDestroy().
    func stop() {
        guard isRunning else { return }
        isRunning = false
        Backend.shared.stop()
        NotificationHandler.shared.clearAll()
    }

    /// Notify the service that the app moved to background. Starts a short
    /// background task to let any in-flight Tor operations finish, then goes
    /// dormant.
    func didEnterBackground() {
        Backend.shared.setDormant(true)

        backgroundTaskID = UIApplication.shared.beginBackgroundTask(
            withName: "molepipe-shutdown"
        ) { [weak self] in
            // OS is about to reclaim us — stop cleanly now.
            self?.stop()
            UIApplication.shared.endBackgroundTask(self?.backgroundTaskID ?? .invalid)
            self?.backgroundTaskID = .invalid
        }
    }

    /// Notify the service that the app returned to foreground. Cancel any
    /// background task and wake arti from dormant mode.
    func didEnterForeground() {
        Backend.shared.setDormant(false)

        if backgroundTaskID != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTaskID)
            backgroundTaskID = .invalid
        }
    }

    /// App is being terminated — stop synchronously.
    func willTerminate() {
        stop()
    }

    // MARK: - Helpers

    private static func dataDir() -> String {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        let base = paths[0].appendingPathComponent("Backend")
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base.path
    }
}
