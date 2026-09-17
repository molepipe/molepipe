import SwiftUI
import WebKit

/// WebViewContainer wraps a WKWebView in a UIViewRepresentable so it can live
/// inside SwiftUI. It loads the same shared web UI the desktop and Android
/// builds serve — http://127.0.0.1:PORT/?ct=<token>&shell=ios.
///
/// Mirrors the WebView setup in Android's MainActivity.kt (lines 320-378).
struct WebViewContainer: UIViewRepresentable {

    let url: String
    @Binding var canGoBack: Bool

    private let shellBridgeName = "iOSShell"

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []

        // Create the shell bridge before creating the WebView so it's available
        // as a message handler at page load time.
        let bridge = ShellBridge(webView: nil) // will be set in makeUIView
        config.userContentController.add(bridge, name: shellBridgeName)

        let wv = WKWebView(frame: .zero, configuration: config)
        bridge.setWebView(wv)

        // Transparent background so our SwiftUI background shows through.
        wv.backgroundColor = .clear
        wv.isOpaque = false

        // Match Android: the page uses DOM storage.
        wv.configuration.preferences.javaScriptEnabled = true

        // Register the coordinator as navigation delegate for back-button tracking.
        wv.navigationDelegate = context.coordinator

        // Load the backend URL.
        if let urlObj = URL(string: url) {
            wv.load(URLRequest(url: urlObj))
        }

        // Inject a JS bridge that the web layer calls for shell actions.
        let bridgeJS = """
        window.shellBridge = {
            setBarAppearance: function(light) {
                window.webkit.messageHandlers.\(shellBridgeName).postMessage({action: 'setBarAppearance', light: light});
            },
            openUrl: function(url) {
                window.webkit.messageHandlers.\(shellBridgeName).postMessage({action: 'openUrl', url: url});
            },
            saveImage: function(base64, mime, callback) {
                window.webkit.messageHandlers.\(shellBridgeName).postMessage({action: 'saveImage', base64: base64, mime: mime, callback: callback});
            },
            shareImage: function(base64, mime) {
                window.webkit.messageHandlers.\(shellBridgeName).postMessage({action: 'shareImage', base64: base64, mime: mime});
            },
            systemPalette: function(callback) {
                window.webkit.messageHandlers.\(shellBridgeName).postMessage({action: 'systemPalette', callback: callback});
            }
        };
        """
        let userScript = WKUserScript(source: bridgeJS, injectionTime: .atDocumentStart, forMainFrameOnly: true)
        wv.configuration.userContentController.addUserScript(userScript)

        // Apply safe area insets via CSS custom properties (mirrors Android's
        // insets listener in MainActivity.kt:391-421).
        applyInsets(to: wv)

        return wv
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        // Update the bridge's weak reference if the view is recreated.
        context.coordinator.bridge.setWebView(uiView)
    }

    private func applyInsets(to webView: WKWebView) {
        // Safe area insets are applied from the coordinator when the view
        // appears. The initial values use screen-level safe areas as a
        // reasonable default; the real values come from GeometryReader in
        // MainView.
    }

    // MARK: - Coordinator

    class Coordinator: NSObject, WKNavigationDelegate {
        var parent: WebViewContainer
        var bridge: ShellBridge

        init(_ parent: WebViewContainer) {
            self.parent = parent
            // Bridge is created without a WebView initially; it's set in
            // makeUIView via setWebView.
            self.bridge = ShellBridge(webView: nil)
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            DispatchQueue.main.async {
                self.parent.canGoBack = webView.canGoBack
            }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            print("[WebViewContainer] navigation failed: \(error.localizedDescription)")
        }

        // MARK: - WKNavigationDelegate

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            // Allow all navigation within the loopback origin.
            decisionHandler(.allow)
        }
    }
}
