package org.molepipe.molepipe

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import android.graphics.Typeface
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.Person
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import mobile.MessageListener

/** Whether the app window is currently visible. Set by MainActivity's lifecycle. */
object AppState {
    @Volatile
    var inForeground = false
}

/**
 * Posts a system notification for each newly delivered inbound message so a
 * message can surface while the window is closed. This is the Android answer to
 * the WebView having no web Notification API (which is why the in-page toggle
 * reads "Not supported"): the Go backend keeps running in the foreground
 * service and calls [onMessage] across JNI from a background goroutine
 * (NotificationManager is thread-safe), independent of the paused WebView.
 *
 * Registered once via Mobile.setMessageListener. Suppressed while the app is in
 * the foreground — the open UI already shows the message, and this is also what
 * keeps a mailbox backlog delivered right after unlock from buzzing.
 *
 * Rendered with [NotificationCompat.MessagingStyle] so the sender's profile
 * picture is the prominent avatar on the left (the app icon stays only as the
 * system's small header/status badge — the framework requires a small icon and
 * always tints it, so it can't be replaced by a photo). A sender with no avatar
 * gets a filled-indigo initials monogram matching the in-app avatar. Per-sender
 * coalescing keeps a short backlog of that sender's recent messages under one
 * notification (and one group summary), so an offline backlog can't flood the
 * shade. Content shows in the shade but is hidden on the lock screen (the
 * channel is VISIBILITY_PRIVATE).
 */
object MessageNotifier : MessageListener {

    private const val CHANNEL_ID = "messages"
    private const val REQUESTS_CHANNEL_ID = "requests"
    private const val GROUP_KEY = "org.molepipe.molepipe.messages"
    private const val SUMMARY_ID = 2 // the foreground-service notification is id 1
    private const val PER_SENDER_BASE = 1000
    private const val FRIEND_REQUEST_BASE = 2000
    private const val GROUP_INVITE_BASE = 3000
    private const val ICON_SIZE = 96 // pixels for the circular avatar / monogram
    private const val MAX_MESSAGES = 5 // recent messages kept per sender in the transcript

    // Filled-indigo monogram, mirroring the in-app initials avatar
    // (--md-sys-color-primary-container / on-primary-container, dark variant).
    private const val MONOGRAM_BG = 0xFF424178.toInt()
    private const val MONOGRAM_FG = 0xFFE2DFFF.toInt()

    private var appContext: Context? = null

    /** A sender's coalesced state: recent messages plus their latest avatar. */
    private class Conversation {
        val messages = ArrayDeque<Pair<String, Long>>() // (preview, atMillis), oldest→newest
        var avatar: Bitmap? = null
    }
    private val convs = HashMap<String, Conversation>()

    /** Called once from the service: stores the app context and creates the channel. */
    fun attach(context: Context) {
        appContext = context.applicationContext
        createChannel()
    }

    override fun onMessage(fromName: String, preview: String, atMillis: Long, avatarBytes: ByteArray) {
        val ctx = appContext ?: return
        if (AppState.inForeground) return // the open UI already shows it
        val mgr = NotificationManagerCompat.from(ctx)
        if (!mgr.areNotificationsEnabled()) return
        synchronized(convs) {
            val conv = convs.getOrPut(fromName) { Conversation() }
            conv.messages.addLast(preview to atMillis)
            while (conv.messages.size > MAX_MESSAGES) conv.messages.removeFirst()
            // Refresh the avatar from the latest message (in a group this tracks
            // the most recent author's face; the title stays the group name).
            val decoded = if (avatarBytes.isNotEmpty()) decodeCircularAvatar(avatarBytes) else null
            conv.avatar = decoded ?: monogramBitmap(fromName)

            val icon = conv.avatar?.let { IconCompat.createWithBitmap(it) }
            val sender = Person.Builder()
                .setName(fromName)
                .setKey(fromName)
                .apply { icon?.let { setIcon(it) } }
                .build()
            val self = Person.Builder().setName(ctx.getString(R.string.msg_notif_self)).build()
            val style = NotificationCompat.MessagingStyle(self).setGroupConversation(false)
            for ((text, at) in conv.messages) style.addMessage(text, at, sender)

            // Promote to a conversation notification so the sender's avatar is the
            // prominent icon even while COLLAPSED (Android 12+). Without a matching
            // long-lived dynamic shortcut carrying the Person, MessagingStyle renders
            // as an ordinary notification: the avatar shows only in the expanded
            // transcript and the collapsed row falls back to the tinted app icon.
            val shortcutId = "sender_" + (fromName.hashCode() and 0xffff)
            val shortcut = ShortcutInfoCompat.Builder(ctx, shortcutId)
                .setShortLabel(fromName)
                .setLongLived(true)
                .setPerson(sender)
                .setIntent(Intent(ctx, MainActivity::class.java).setAction(Intent.ACTION_VIEW))
                .apply { icon?.let { setIcon(it) } }
                .build()
            ShortcutManagerCompat.pushDynamicShortcut(ctx, shortcut)

            val builder = NotificationCompat.Builder(ctx, CHANNEL_ID)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setShortcutId(shortcutId)
                .setStyle(style)
                // MessagingStyle fills the sender avatar only in the EXPANDED
                // transcript; the collapsed view's icon slot is the large icon, so
                // set the same clean avatar there too or collapsed falls back to the
                // bare app icon.
                .apply { conv.avatar?.let { setLargeIcon(it) } }
                .setAutoCancel(true)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setGroup(GROUP_KEY)
                .setWhen(atMillis)
                .setContentIntent(openApp(ctx))
                .apply { if (conv.messages.size > 1) setNumber(conv.messages.size) }
            val summary = NotificationCompat.Builder(ctx, CHANNEL_ID)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(ctx.getString(R.string.msg_notif_summary))
                .setGroup(GROUP_KEY)
                .setGroupSummary(true)
                .setAutoCancel(true)
                .setContentIntent(openApp(ctx))
                .build()
            try {
                mgr.notify(perSenderId(fromName), builder.build())
                mgr.notify(SUMMARY_ID, summary)
            } catch (_: SecurityException) {
                // Notification permission revoked between the check and the post.
            }
        }
    }

    /** Cancel all message notifications and reset counts — called when the app is shown. */
    fun clearAll() {
        val ctx = appContext ?: return
        val mgr = NotificationManagerCompat.from(ctx)
        synchronized(convs) {
            for (sender in convs.keys) mgr.cancel(perSenderId(sender))
            convs.clear()
        }
        mgr.cancel(SUMMARY_ID)
    }

    override fun onFriendRequest(fromName: String) {
        val ctx = appContext ?: return
        if (AppState.inForeground) return
        val mgr = NotificationManagerCompat.from(ctx)
        if (!mgr.areNotificationsEnabled()) return
        val monogram = monogramBitmap(fromName)
        val icon = IconCompat.createWithBitmap(monogram)
        val notification = NotificationCompat.Builder(ctx, REQUESTS_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setLargeIcon(monogram)
            .setContentTitle(fromName)
            .setContentText(ctx.getString(R.string.notif_friend_request_text))
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_SOCIAL)
            .setContentIntent(openApp(ctx))
            .build()
        try {
            mgr.notify(friendRequestId(fromName), notification)
        } catch (_: SecurityException) {}
    }

    override fun onGroupInvite(inviterName: String, groupName: String) {
        val ctx = appContext ?: return
        if (AppState.inForeground) return
        val mgr = NotificationManagerCompat.from(ctx)
        if (!mgr.areNotificationsEnabled()) return
        val monogram = monogramBitmap(inviterName)
        val icon = IconCompat.createWithBitmap(monogram)
        val text = ctx.getString(R.string.notif_group_invite_text, inviterName, groupName)
        val notification = NotificationCompat.Builder(ctx, REQUESTS_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setLargeIcon(monogram)
            .setContentTitle(ctx.getString(R.string.notif_group_invite_title))
            .setContentText(text)
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_SOCIAL)
            .setContentIntent(openApp(ctx))
            .build()
        try {
            mgr.notify(groupInviteId(groupName), notification)
        } catch (_: SecurityException) {}
    }

    /**
     * Decodes raw avatar JPEG/PNG bytes into a clean circular [Bitmap] sized for
     * notification avatar use. No app-logo badge is composited in — MessagingStyle
     * shows this as the prominent left avatar and the system draws its own small
     * app badge, so a second logo burned into the corner would clash. Returns null
     * on decode failure (the caller falls back to a monogram).
     */
    private fun decodeCircularAvatar(raw: ByteArray): Bitmap? {
        val opts = BitmapFactory.Options().apply { inSampleSize = 1 }
        // First pass: determine the dimensions without allocating pixels.
        BitmapFactory.decodeByteArray(raw, 0, raw.size, opts)
        if (opts.outWidth <= 0 || opts.outHeight <= 0) return null
        // Down-sample in one decode if the image is larger than needed.
        while (opts.inSampleSize * ICON_SIZE < opts.outWidth && opts.inSampleSize * ICON_SIZE < opts.outHeight) {
            opts.inSampleSize *= 2
        }
        val src = BitmapFactory.decodeByteArray(raw, 0, raw.size, opts) ?: return null
        val size = minOf(src.width, src.height)
        val x = (src.width - size) / 2
        val y = (src.height - size) / 2
        val cropped = Bitmap.createBitmap(src, x, y, size, size)
        if (cropped !== src) src.recycle()
        val circle = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(circle)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        canvas.drawCircle(size / 2f, size / 2f, size / 2f, paint)
        paint.xfermode = PorterDuffXfermode(PorterDuff.Mode.SRC_IN)
        canvas.drawBitmap(cropped, 0f, 0f, paint)
        cropped.recycle()
        return circle
    }

    /**
     * Draws a filled circular initials monogram for a sender with no avatar,
     * matching the in-app initials avatar (indigo fill, light text). Same circular
     * shape as [decodeCircularAvatar] so both feed the Person icon identically.
     */
    private fun monogramBitmap(name: String): Bitmap {
        val size = ICON_SIZE
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        paint.color = MONOGRAM_BG
        canvas.drawCircle(size / 2f, size / 2f, size / 2f, paint)
        val text = initialsOf(name)
        paint.color = MONOGRAM_FG
        paint.textSize = size * 0.4f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        paint.textAlign = Paint.Align.CENTER
        // Center vertically: baseline offset from the middle by the text metrics.
        val fm = paint.fontMetrics
        val baseline = size / 2f - (fm.ascent + fm.descent) / 2f
        canvas.drawText(text, size / 2f, baseline, paint)
        return bmp
    }

    /**
     * Derives a 1–2 letter uppercase monogram, mirroring the frontend's
     * initialsOf(): first letter of the first and last whitespace-separated word,
     * or "?" for an empty name.
     */
    private fun initialsOf(name: String): String {
        val parts = name.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (parts.isEmpty()) return "?"
        val a = parts.first().first()
        val b = if (parts.size > 1) parts.last().first().toString() else ""
        return (a + b).uppercase()
    }

    // A stable per-sender id kept clear of the foreground-service id (1) and the
    // group summary (2), so each sender owns exactly one notification.
    private fun perSenderId(sender: String) = PER_SENDER_BASE + (sender.hashCode() and 0xffff)
    private fun friendRequestId(name: String) = FRIEND_REQUEST_BASE + (name.hashCode() and 0xffff)
    private fun groupInviteId(group: String) = GROUP_INVITE_BASE + (group.hashCode() and 0xffff)

    private fun openApp(ctx: Context) = PendingIntent.getActivity(
        ctx,
        0,
        Intent(ctx, MainActivity::class.java).setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE,
    )

    private fun createChannel() {
        val ctx = appContext ?: return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val mgr = ctx.getSystemService(NotificationManager::class.java)
        val msgChannel = NotificationChannel(
            CHANNEL_ID,
            ctx.getString(R.string.msg_channel_name),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = ctx.getString(R.string.msg_channel_desc)
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            setShowBadge(true)
        }
        mgr.createNotificationChannel(msgChannel)
        val reqChannel = NotificationChannel(
            REQUESTS_CHANNEL_ID,
            ctx.getString(R.string.req_channel_name),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = ctx.getString(R.string.req_channel_desc)
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setShowBadge(true)
        }
        mgr.createNotificationChannel(reqChannel)
    }
}
