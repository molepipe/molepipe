import Foundation
import UIKit
import WebKit

/// ShellBridge is the single, deliberately tiny bridge the loopback UI can call
/// back into via WKScriptMessageHandler. The WebView only ever loads our own
/// 127.0.0.1 first-party content, and the exposed methods just handle OS-level
/// tasks (gallery save, share sheet, open URLs), so this adds no meaningful
/// attack surface.
///
/// Mirrors Android's ShellBridge inner class in MainActivity.kt.
final class ShellBridge: NSObject, WKScriptMessageHandler {

    private weak var webView: WKWebView?

    init(webView: WKWebView) {
        self.webView = webView
        super.init()
    }

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
        guard let body = message.body as? [String: Any],
              let action = body["action"] as? String else {
            return
        }

        switch action {
        case "setBarAppearance":
            if let light = body["light"] as? Bool {
                setBarAppearance(lightBackground: light)
            }
        case "openUrl":
            if let url = body["url"] as? String {
                openUrl(url)
            }
        case "saveImage":
            if let base64 = body["base64"] as? String,
               let mime = body["mime"] as? String {
                let result = saveImageToGallery(base64: base64, mime: mime)
                reply(result: result, callback: body["callback"] as? String)
            }
        case "shareImage":
            if let base64 = body["base64"] as? String,
               let mime = body["mime"] as? String {
                shareImage(base64: base64, mime: mime)
            }
        case "systemPalette":
            let palette = systemPalette()
            reply(result: palette, callback: body["callback"] as? String)
        default:
            break
        }
    }

    // MARK: - Actions

    /// Flips the status bar / navigation bar icon contrast based on the page
    /// theme. Mirrors Android's setBarAppearance via WindowInsetsControllerCompat.
    private func setBarAppearance(lightBackground: Bool) {
        DispatchQueue.main.async {
            let style: UIStatusBarStyle = lightBackground ? .darkContent : .lightContent
            UIApplication.shared.statusBarStyle = style
            // Force root view controller to prefer the style.
            if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene {
                scene.statusBarManager?.statusBarStyle = style
            }
            // Set the user interface style on the window so the system bars adapt.
            if let window = UIApplication.shared.windows.first {
                window.overrideUserInterfaceStyle = lightBackground ? .light : .dark
            }
        }
    }

    /// Opens an external http(s) link in the system browser. Mirrors Android's
    /// openUrl via Intent.ACTION_VIEW. Only http/https is honoured.
    private func openUrl(_ urlString: String) {
        let trimmed = urlString.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("https://") || trimmed.hasPrefix("http://") else { return }
        guard let url = URL(string: trimmed) else { return }
        DispatchQueue.main.async {
            UIApplication.shared.open(url)
        }
    }

    /// Saves an image (base64-encoded) to the shared photo library under
    /// Pictures/Molepipe. Mirrors Android's saveImageToGallery via MediaStore.
    /// Returns "" on success or a human-readable error message.
    private func saveImageToGallery(base64: String, mime: String) -> String {
        guard let data = Data(base64Encoded: base64) else {
            return "Couldn't decode the image."
        }
        guard data.count <= 10 * 1024 * 1024 else {
            return "Image too large."
        }
        guard let image = UIImage(data: data) else {
            return "Couldn't read the image."
        }

        var imageSaved = false
        var saveError: String?

        let group = DispatchGroup()
        group.enter()

        PHPhotoLibrary.shared().performChanges({
            PHAssetCreationRequest.creationRequestForAsset(for: image)
                .addResource(with: .photo, data: data)
        }, completionHandler: { success, error in
            imageSaved = success
            if let error = error {
                saveError = error.localizedDescription
            }
            group.leave()
        })

        group.wait()

        if imageSaved { return "" }
        return saveError ?? "Couldn't save to the gallery."
    }

    /// Shares an image via the OS share sheet (UIActivityViewController).
    /// Mirrors Android's shareImage via Intent.ACTION_SEND + FileProvider.
    private func shareImage(base64: String, mime: String) {
        guard let data = Data(base64Encoded: base64) else { return }
        guard data.count <= 10 * 1024 * 1024 else { return }
        guard let image = UIImage(data: data) else { return }

        DispatchQueue.main.async {
            let activityVC = UIActivityViewController(
                activityItems: [image],
                applicationActivities: nil
            )
            if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
               let rootVC = windowScene.windows.first?.rootViewController {
                rootVC.present(activityVC, animated: true)
            }
        }
    }

    /// Returns the device's system accent color as a hex string. iOS doesn't
    /// have Material You dynamic color, so we return the system tint color.
    /// Returns "" for consistency with Android's pre-12 path.
    private func systemPalette() -> String {
        // iOS dynamic colors are resolved at display time, not statically.
        // Return empty to let the web layer fall back to its default palette.
        return ""
    }

    // MARK: - Reply helper

    private func reply(result: String, callback: String?) {
        guard let callback = callback, !callback.isEmpty else { return }
        let escaped = result.replacingOccurrences(of: "'", with: "\\'")
        let js = "\(callback)('\(escaped)')"
        DispatchQueue.main.async {
            self.webView?.evaluateJavaScript(js)
        }
    }
}
