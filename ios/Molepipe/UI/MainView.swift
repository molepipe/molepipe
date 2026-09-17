import SwiftUI

/// MainView is the root SwiftUI view hosting the WebView. It observes the
/// Backend state and renders accordingly.
///
/// Mirrors Android's MainActivity render() function.
struct MainView: View {

    @StateObject private var backend = Backend.shared
    @State private var canGoBack = false
    @State private var loadedUrl: String?

    var body: some View {
        ZStack {
            switch backend.state {
            case .stopped, .starting:
                // Blank white screen while starting — Android does the same
                // (no splash for the shell).
                Color(.systemBackground)

            case .running(let url):
                if loadedUrl != url {
                    // Defer to next run loop so the state update completes first.
                    Color(.systemBackground)
                        .onAppear {
                            loadedUrl = url
                        }
                } else {
                    WebViewContainer(url: url, canGoBack: $canGoBack)
                        .ignoresSafeArea(edges: .bottom)
                        .onAppear {
                            applyInsets()
                        }
                }

            case .failed(let message):
                VStack(spacing: 16) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("Failed to start")
                        .font(.headline)
                    Text(message)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(.systemBackground))
            }
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .active:
                BackendService.shared.didEnterForeground()
                NotificationHandler.shared.setForeground(true)
            case .inactive:
                break
            case .background:
                BackendService.shared.didEnterBackground()
                NotificationHandler.shared.setForeground(false)
            @unknown default:
                break
            }
        }
        .onAppear {
            BackendService.shared.start()
            NotificationHandler.shared.setForeground(true)
        }
        .onDisappear {
            NotificationHandler.shared.setForeground(false)
        }
    }

    @Environment(\.scenePhase) private var scenePhase

    private func applyInsets() {
        // The safe area insets are communicated to the web layer via the
        // shellBridge after the WebView loads. For now, rely on the
        // WKWebView's built-in safe area handling.
    }
}
