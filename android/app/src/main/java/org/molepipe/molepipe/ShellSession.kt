package org.molepipe.molepipe

/**
 * Process-scoped holder for the loopback UI's session token.
 *
 * The page keeps its token in memory only, so that it disappears when the tab
 * closes (see the comment at the top of public/app.js). On Android, though, the
 * tab is rebuilt for reasons the user never thinks of as closing it: any
 * configuration change outside MainActivity's configChanges list — night mode,
 * locale, font scale — destroys the Activity and its WebView, and the fresh
 * page came up with no token and asked for the PIN again, even though the
 * backend's vault was still unlocked the whole time.
 *
 * This holds the token across that rebuild. It is deliberately *just* a process
 * singleton: nothing is written to disk, so the token lives exactly as long as
 * the process does — and the backend's vault, whose keys are in memory in this
 * same process, is zeroed at that same moment. A token that outlived the
 * process could therefore never be worth anything. On Android, process death
 * is what "the tab closed" actually means, so this restores the intent of the
 * memory-only rule rather than relaxing it.
 *
 * Cleared by the page itself on lock, on account removal/wipe, and whenever the
 * backend rejects the token with a 401 — see setSessionToken in app.js.
 */
object ShellSession {
    @Volatile
    private var token: String = ""

    /** The stored token, or "" if there is none. */
    fun get(): String = token

    /** Stores [t], or clears the holder when [t] is empty. */
    fun set(t: String) {
        token = t
    }
}
