import Foundation
import UserNotifications
import Mobile

/// NotificationHandler manages system notifications for inbound messages, friend
/// requests, and group invites. Mirrors Android's MessageNotifier.kt.
///
/// Implements the MessageListener protocol (from gomobile) so the Go backend can
/// post notifications while the app is backgrounded or the window is closed.
final class NotificationHandler: NSObject {

    static let shared = NotificationHandler()

    private let center = UNUserNotificationCenter.current()
    private var isForeground = false

    private override init() {
        super.init()
        center.delegate = self
        createNotificationChannel()
    }

    /// Mark the app as foreground — notifications are suppressed while visible.
    func setForeground(_ foreground: Bool) {
        isForeground = foreground
        if foreground {
            clearAll()
        }
    }

    /// Remove all pending and delivered notifications. Called when the app
    /// enters foreground or when the backend stops.
    func clearAll() {
        center.removeAllDeliveredNotifications()
        center.removeAllPendingNotificationRequests()
    }

    // MARK: - Notification channel (iOS equivalent of Android's channel)

    private func createNotificationChannel() {
        // iOS doesn't have channels, but we configure the notification center
        // at request time. Just ensure authorization is granted.
        center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    // MARK: - Helpers

    private func postNotification(title: String, body: String, id: String) {
        guard !isForeground else { return }

        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: id,
            content: content,
            trigger: nil  // deliver immediately
        )
        center.add(request)
    }
}

// MARK: - UNUserNotificationCenterDelegate

extension NotificationHandler: UNUserNotificationCenterDelegate {

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // Show the notification even while foregrounded (banner + sound).
        completionHandler([.banner, .sound])
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        // Could deep-link based on the notification identifier; for now just
        // bring the app to foreground (default iOS behavior).
        completionHandler()
    }
}

// MARK: - MessageListener (gomobile)

extension NotificationHandler: MessageListener {

    /// Called by the Go backend for each newly delivered inbound message.
    func onMessage(fromName: String, preview: String, atMillis: Int64, avatarBytes: Data?) {
        let id = "msg-\(atMillis)"
        postNotification(
            title: fromName,
            body: preview,
            id: id
        )
    }

    /// Called by the Go backend for each incoming friend request.
    func onFriendRequest(fromName: String) {
        let id = "friend-\(fromName)-\(Date().timeIntervalSince1970)"
        postNotification(
            title: "Friend request",
            body: "\(fromName) wants to connect",
            id: id
        )
    }

    /// Called by the Go backend for each incoming group invite.
    func onGroupInvite(inviterName: String, groupName: String) {
        let id = "group-\(inviterName)-\(groupName)-\(Date().timeIntervalSince1970)"
        postNotification(
            title: "Group invite",
            body: "\(inviterName) invited you to \(groupName)",
            id: id
        )
    }
}
