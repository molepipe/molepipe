package org.molepipe.molepipe

/**
 * An image another app handed us through the system share sheet, decoded to
 * bytes and waiting for the page to collect it.
 *
 * [mime] is sanitised at construction so it can be interpolated straight into
 * the JSON the bridge hands the page (see ShellBridge.takeSharedImage).
 */
class PendingShare(mime: String, val bytes: ByteArray) {
    val mime: String = mime.lowercase().filter { it in "abcdefghijklmnopqrstuvwxyz0123456789/+.-" }
        .ifEmpty { "image/jpeg" }
}

/**
 * Process-scoped holder for an inbound shared image, between the share-sheet
 * intent arriving and the *unlocked* page collecting it.
 *
 * Why a holder rather than pushing straight into the WebView: a share can land
 * at any point in the app's life — before the page exists at all (cold start,
 * where the intent is handled in onCreate long before the backend is up and
 * loadUrl has been called), while the lock screen is up, or mid-conversation.
 * Parking the bytes here lets all three paths converge on one pull: the page
 * asks for the image at the end of showUnlocked(), and again when onNewIntent
 * pings an already-unlocked page.
 *
 * That pull point is the security boundary the feature turns on. The image
 * stays on this side of the bridge — out of page memory, with no contact list
 * shown and no chat picker to tap — until a session actually exists. Sharing
 * into a locked app therefore puts the user on the PIN screen first, exactly as
 * opening the app from the launcher would, and the picker appears only after
 * the vault is open. Nothing on the locked path may call take().
 *
 * Memory only, and single-slot: a second share replaces an uncollected first
 * (the share sheet's own semantics — the user picked a newer photo), and
 * [take] clears as it reads, so the picker cannot be re-opened by a replayed
 * intent or a double pull. Process death drops it, like [ShellSession].
 */
object SharedImage {
    @Volatile
    private var pending: PendingShare? = null

    /** Parks [share] for the next pull, displacing any uncollected one. */
    fun put(share: PendingShare) {
        pending = share
    }

    /** Returns the parked share and clears the slot, or null if there is none. */
    fun take(): PendingShare? {
        val s = pending
        pending = null
        return s
    }
}
