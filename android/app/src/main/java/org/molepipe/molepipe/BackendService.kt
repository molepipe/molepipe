package org.molepipe.molepipe

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import mobile.Mobile

/**
 * The always-on foreground service. It exists so messages can arrive while the
 * window is closed, and it is the single owner of the backend lifecycle.
 *
 * Load-bearing lifecycle rule (mirrors the desktop tray's "quit vs. close"
 * distinction, which the threat model flags as one line that matters): a
 * task-swipe deliberately does NOT stop the backend — a messenger must keep
 * receiving. The ONLY path that stops it is the notification's Stop action ->
 * stopSelf() -> onDestroy() -> Backend.stop(). Once Tor hosting lands, that is
 * also the only path that deletes the onion key and releases the data-dir lock,
 * so if that path is wrong those never happen.
 */
class BackendService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    // A partial wakelock keeps the CPU running Arti's onion-service maintenance
    // (intro-point upkeep, descriptor republish) while the screen is off. The
    // foreground service already exempts us from Doze's NETWORK restrictions, but
    // not from CPU suspension, so without this the maintenance timers can be
    // deferred and the onion decays until nobody can reach us. Held for the
    // entire lifetime of the service — the CPU cost is negligible next to the
    // Tor process itself, and the OS auto-releases it on process death.
    private var wakeLock: PowerManager.WakeLock? = null

    // Keeps the process bound to whatever is CURRENTLY the default network.
    //
    // bindProcessToNetwork pins every socket the process opens to one Network
    // handle, and that pin outlives the network it names. This used to be a
    // single call in onCreate, so the process stayed pinned to whichever
    // network happened to be up when the service started. A phone left alone
    // for hours almost always changes network at least once — Wi-Fi sleeps and
    // re-associates with a new handle, the cell hands over, the user walks out
    // of range — and from that moment the pin names a dead network: no socket
    // can connect, Tor can't build a circuit, the onion is unreachable, and no
    // message (so no notification) arrives. Nothing recovers it either, because
    // the pin outlives the network and only process death clears it — which is
    // exactly why the app appears to need "reconnecting" after a long spell in
    // the background, while the foreground service and the wakelock make it
    // look perfectly healthy.
    private var netCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    private var boundNetwork: Network? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        val type = if (Build.VERSION.SDK_INT >= 34) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIF_ID, buildNotification(), type)

        // Bind the process to the default network so Doze cannot silently revoke
        // network access for this foreground service on OEM-tweaked builds, and
        // follow that default for the service's whole life (see netCallback).
        try {
            val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    boundNetwork = network
                    try { cm.bindProcessToNetwork(network) } catch (_: Throwable) { }
                    // One line per network change, which is rare. Worth keeping:
                    // "the socket layer went dead hours ago" is otherwise
                    // invisible from outside the process.
                    Log.i(TAG, "bound to default network $network")
                }

                override fun onLost(network: Network) {
                    // Only drop the pin if the network that went away is the one
                    // we are actually pinned to. During a handover the NEW
                    // default arrives before the old one is reported lost, so an
                    // unconditional unbind here would undo the fresh bind we
                    // just made. Unbinding (null) falls back to the system
                    // default, which is always better than a handle we know is
                    // dead.
                    if (boundNetwork == network) {
                        boundNetwork = null
                        try { cm.bindProcessToNetwork(null) } catch (_: Throwable) { }
                        Log.i(TAG, "default network lost; unbound from $network")
                    }
                }
            }
            cm.registerDefaultNetworkCallback(cb)
            netCallback = cb
            // Bind right away too: the first onAvailable can lag service start,
            // and the backend begins reaching for the network immediately.
            cm.activeNetwork?.let {
                boundNetwork = it
                cm.bindProcessToNetwork(it)
            }
        } catch (_: Throwable) { }

        // Route newly delivered inbound messages to a system notification while
        // the window is closed. Order-independent with Backend.start: the Go side
        // reads the listener live, so a later (idempotent) service recreation just
        // re-registers the same object.
        MessageNotifier.attach(applicationContext)
        Mobile.setMessageListener(MessageNotifier)

        Backend.start(applicationContext)

        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKELOCK_TAG).apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        // Restart if the OS reclaims us; onCreate re-establishes the notification
        // and re-attaches to the (idempotent) backend.
        return START_STICKY
    }

    override fun onDestroy() {
        // The backend is stopping, so pull any lingering message notifications —
        // they name contacts and must not outlive a Stop (or an account wipe).
        wakeLock?.let { if (it.isHeld) it.release() }
        netCallback?.let { cb ->
            try {
                val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
                cm.unregisterNetworkCallback(cb)
                cm.bindProcessToNetwork(null)
            } catch (_: Throwable) { }
        }
        netCallback = null
        MessageNotifier.clearAll()
        Backend.stop()
        super.onDestroy()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notif_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notif_channel_desc)
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, BackendService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text))
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, getString(R.string.notif_stop), stop)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    companion object {
        private const val TAG = "MolepipeService"
        private const val CHANNEL_ID = "backend"
        private const val NOTIF_ID = 1
        const val ACTION_STOP = "org.molepipe.molepipe.action.STOP"

        private const val WAKELOCK_TAG = "molepipe:tor-serving"

        /** Start the service in the foreground from an app-visible context. */
        fun start(context: Context) {
            val intent = Intent(context, BackendService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }
}
