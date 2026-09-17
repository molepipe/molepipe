import SwiftUI

/// MolepipeApp is the @main entry point. It configures the scene and
/// provides the root view.
@main
struct MolepipeApp: App {

    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            MainView()
                .onAppear {
                    // Ensure the backend starts on first launch.
                    BackendService.shared.start()
                }
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .active:
                BackendService.shared.didEnterForeground()
            case .background:
                BackendService.shared.didEnterBackground()
            case .inactive:
                break
            @unknown default:
                break
            }
        }
    }
}
