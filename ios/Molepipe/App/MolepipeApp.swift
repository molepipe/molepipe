import SwiftUI

/// MolepipeApp is the @main entry point. It only hosts the root view — all
/// backend lifecycle and scene-phase handling lives in MainView, which is the
/// single owner (see MainView's `.onChange(of: scenePhase)` / `.onAppear`).
/// Handling scenePhase here as well would double-fire didEnterBackground /
/// didEnterForeground (and leak a UIBackgroundTaskIdentifier per background).
@main
struct MolepipeApp: App {

    var body: some Scene {
        WindowGroup {
            MainView()
        }
    }
}
