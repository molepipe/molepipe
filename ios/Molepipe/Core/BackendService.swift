import Foundation
import UIKit
import UserNotifications
import Mobile

/// BackendService manages the lifecycle of the Go backend. It is the iOS
/// counterpart of Android's BackendService, but it CANNOT match its core
/// guarantee, and that difference is load-bearing:
///
///   Android runs a foreground service, so the backend — and the Tor onion
///   service — keep running with the app backgrounded, indefinitely. iOS has no
///   equivalent. Once the app is backgrounded the system suspends the process
///   within seconds; `beginBackgroundTask` buys only a short grace window
///   (historically up to ~30s) and then execution is frozen. There is no
///   supported way to keep a long-lived Tor onion service reachable in the
///   background.
///
///   Practical consequence: the onion service answers only while the app is in
///   the foreground (plus that brief grace window). A message sent while this
///   device is suspended is held by the SENDER's mailbox/relay and syncs on next
///   foreground — it does not arrive live, and no local notification fires until
///   then. See HANDOFF.md → "Platform divergences" and the APNs item in Future
///   Work.
///
/// What this class does on background: flip arti to dormant to save battery, then
/// take a short background task so in-flight Tor work can finish (and, if the OS
/// reclaims us during it, shut down cleanly). Foreground wakes arti back up. The
/// only clean stop paths are OS reclamation and explicit termination.
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
        MobileSetMessageListener(NotificationHandler.shared)
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

        // Never stack background tasks: end any previous one first so a repeated
        // background transition can't orphan its identifier.
        if backgroundTaskID != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTaskID)
            backgroundTaskID = .invalid
        }

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

    /// The Go backend's data directory — it holds `identity.enc` (the BIP39 seed,
    /// password-encrypted) and the message store. Two protections are applied
    /// here, because iOS otherwise backs Documents up to iCloud and the seed would
    /// leave the device:
    ///
    ///   • isExcludedFromBackup — the directory never enters an iCloud / Finder
    ///     backup, so the seed can't be lifted from a backup (the analogue of
    ///     Android's android:allowBackup=false).
    ///   • FileProtectionType.completeUntilFirstUserAuthentication — the OS keeps
    ///     the files encrypted at rest under a key tied to the device passcode
    ///     until the first unlock after boot, then readable so the backend can run
    ///     while foregrounded. New files the Go core writes inherit the directory's
    ///     class. This is the iOS analogue of Android's file-based encryption of
    ///     app-private storage. (No device passcode ⇒ no data protection is
    ///     possible, on either platform.)
    ///
    /// Application Support (not Documents) is used: this is app-managed data, never
    /// surfaced through the Files app.
    ///
    /// Note: this protects the seed FILE. The seed itself is not moved into the
    /// Keychain — its single root of truth is the recovery phrase, and it must stay
    /// recoverable on any device, so binding it to this device's Keychain would
    /// break cross-device recovery. See Keychain.swift.
    private static func dataDir() -> String {
        let fm = FileManager.default
        let root = (try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                appropriateFor: nil, create: true))
            ?? fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        var base = root.appendingPathComponent("Backend", isDirectory: true)

        try? fm.createDirectory(at: base, withIntermediateDirectories: true, attributes: [
            .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        ])

        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? base.setResourceValues(values)

        return base.path
    }
}
