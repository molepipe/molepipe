package org.molepipe.molepipe

import android.content.Context
import android.os.Handler
import android.os.Looper
import mobile.Mobile

/**
 * Backend wraps the gomobile-bound Go server (backend/mobile).
 *
 * The .aar is built by android/build-aar.sh into app/libs/mobile.aar; that
 * script is the source of truth for the generated names. Go's package `mobile`
 * binds to Java class `mobile.Mobile`; exported funcs bind with a lowercased
 * first letter (Start -> start, Stop -> stop, IsRunning -> isRunning); and Go
 * `int` binds to Java `long`, so [Mobile.stop] takes a Long literal (5000L),
 * never an Int. If the build reports a missing/renamed method, open the
 * generated sources and adjust the three call sites below.
 *
 * BackendService is the single owner of the lifecycle — it is the only thing
 * that calls [start]/[stop]. The Activity only observes via [setListener], so a
 * config-change recreation can never race the service into a second start.
 */
object Backend {

    sealed interface State {
        data object Stopped : State
        data object Starting : State
        data class Running(val url: String) : State
        data class Failed(val message: String) : State
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    @Volatile
    private var state: State = State.Stopped

    // Written under the monitor in setListener, read without it from the
    // backend-start worker thread via setState — must be @Volatile or a Running
    // callback can be lost and the WebView never loads.
    @Volatile
    private var listener: ((State) -> Unit)? = null
    private var starting = false

    /** Register the single observer; it is immediately called with the current state. */
    @Synchronized
    fun setListener(l: ((State) -> Unit)?) {
        listener = l
        val current = state
        if (l != null) mainHandler.post { l(current) }
    }

    private fun setState(s: State) {
        state = s
        val l = listener
        if (l != null) mainHandler.post { l(s) }
    }

    /**
     * Bring the backend up. Idempotent: a call while starting or already running
     * is a no-op. Mobile.start binds a loopback listener and returns its URL
     * quickly (no Argon2 / no Tor at this point), but it does file I/O, so it
     * runs off the main thread.
     */
    @Synchronized
    fun start(context: Context) {
        if (starting || state is State.Running) return
        starting = true
        setState(State.Starting)
        val dataDir = context.filesDir.absolutePath
        Thread({
            try {
                // Passing filesDir is what keeps the backend off the desktop
                // config-dir default it would otherwise reject.
                val url = Mobile.start(dataDir)
                setState(State.Running(url))
            } catch (t: Throwable) {
                setState(State.Failed(t.message ?: "the backend failed to start"))
            } finally {
                synchronized(this@Backend) { starting = false }
            }
        }, "backend-start").start()
    }

    /**
     * Shut the backend down (locks the vault, releases the data-dir lock, and —
     * once Tor hosting lands — deletes the onion key). Called only from
     * BackendService.onDestroy, and deliberately BLOCKING: the shutdown must
     * finish before the process is allowed to die, exactly as desktop runs
     * Shutdown() synchronously on quit. A fire-and-forget thread would let the
     * process exit mid-shutdown and leave the key/lock behind. The bound is 5s,
     * well inside a foreground service's onDestroy budget; it is not called on a
     * latency-sensitive path. Not @Synchronized, so it never holds the monitor
     * across the blocking JNI call — Mobile.stop is itself mutex-guarded and
     * idempotent in Go.
     */
    fun stop() {
        try {
            Mobile.stop(5000L) // Go int -> Java long: the L is required.
        } catch (_: Throwable) {
            // Best-effort: the process is on its way out regardless.
        } finally {
            setState(State.Stopped)
        }
    }

    /**
     * Toggle arti-client's dormant mode. When dormant, proactive background
     * tasks (preemptive circuit building, directory fetches) are suspended to
     * conserve CPU and battery. Existing Tor connections stay alive. Called from
     * MainActivity on foreground/background transitions.
     */
    fun setDormant(dormant: Boolean) {
        try {
            Mobile.setDormant(dormant)
        } catch (_: Throwable) {
            // Not running or unsupported; ignore.
        }
    }
}
