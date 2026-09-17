package org.molepipe.molepipe

import android.Manifest
import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.MediaStore
import android.provider.Settings
import android.util.Base64
import android.app.AlertDialog
import android.webkit.JavascriptInterface
import android.webkit.PermissionRequest
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.addCallback
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import java.io.File
import java.io.FileOutputStream
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

/**
 * Hosts a full-screen WebView pointed at the backend's own loopback URL — the
 * exact same internal/api/public UI the desktop build serves, unchanged. The
 * page therefore has a genuine http://127.0.0.1:PORT origin, so the backend's
 * host allowlist and fail-closed origin guard accept its requests without any
 * weakening (the same reasoning that let the desktop packaging keep its guards).
 *
 * This Activity does not own the backend; BackendService does. Here we start
 * that service and observe [Backend] to know when to load the URL.
 */
class MainActivity : ComponentActivity() {

    private lateinit var webView: WebView
    private var loadedUrl: String? = null

    // The most recent system-bar insets, as a JS snippet that writes them into
    // the page's CSS custom properties. Cached because the insets are delivered
    // during layout — before the WebView has loaded the UI — so the snippet has
    // to be re-run once the page exists (see onPageFinished) or the values are
    // lost and the CSS falls back to 0 on every cold start.
    private var insetsJs: String? = null

    /**
     * The single, deliberately tiny bridge the loopback UI can call back into.
     * The WebView only ever loads our own 127.0.0.1 first-party content, and the
     * one exposed method just flips the system-bar icon contrast, so this adds no
     * meaningful attack surface (and minSdk 24 is clear of the old pre-17 hole).
     */
    private inner class ShellBridge {
        // lightBackground = the app is showing a light theme, so the status/nav
        // bar icons must be dark to stay visible (and vice-versa). Called from
        // the WebView's JS thread, so hop to the UI thread before touching the
        // window's insets controller.
        @JavascriptInterface
        fun setBarAppearance(lightBackground: Boolean) {
            runOnUiThread {
                WindowInsetsControllerCompat(window, webView).apply {
                    isAppearanceLightStatusBars = lightBackground
                    isAppearanceLightNavigationBars = lightBackground
                }
            }
        }

        /**
         * Opens an external http(s) link (Donate, Report a bug) in the system
         * browser. The loopback UI must never navigate the WebView itself to an
         * outside URL — that would replace the whole app with a web page and leave
         * the user no way back. Only http/https is honoured, so the bridge can't be
         * steered into arbitrary intents (tel:, intent:, file:, …).
         */
        @JavascriptInterface
        fun openUrl(url: String) {
            val u = url.trim()
            if (!u.startsWith("https://") && !u.startsWith("http://")) return
            runOnUiThread {
                try {
                    startActivity(
                        Intent(Intent.ACTION_VIEW, Uri.parse(u))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                } catch (_: Throwable) {}
            }
        }

        /**
         * The device's wallpaper-derived Material You tonal palettes (Android 12+),
         * as JSON the web layer maps onto the M3 color roles for a "Dynamic" accent.
         * Returns "" when unsupported (pre-12), so the JS side simply omits the
         * Dynamic swatch and never shows a dead control.
         *
         * Keyed by M3 TONE (0 = black … 100 = white). Android's own resource
         * suffixes run the opposite way (system_accent1_0 is the LIGHTEST), so we
         * translate here via toneToSuffix — getting that backwards would invert
         * every palette, which is why the mapping is explicit rather than computed.
         * Pure read of framework resources; safe to run on the JS thread.
         */
        @JavascriptInterface
        fun systemPalette(): String {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return ""
            val toneToSuffix = linkedMapOf(
                100 to 0, 99 to 10, 95 to 50, 90 to 100, 80 to 200, 70 to 300,
                60 to 400, 50 to 500, 40 to 600, 30 to 700, 20 to 800, 10 to 900, 0 to 1000,
            )
            val palettes = linkedMapOf(
                "a1" to "system_accent1", "a2" to "system_accent2", "a3" to "system_accent3",
                "n1" to "system_neutral1", "n2" to "system_neutral2",
            )
            val res = resources
            val out = StringBuilder("{")
            var firstPalette = true
            for ((key, base) in palettes) {
                if (!firstPalette) out.append(",")
                firstPalette = false
                out.append("\"").append(key).append("\":{")
                var firstTone = true
                for ((tone, suffix) in toneToSuffix) {
                    val id = res.getIdentifier("${base}_$suffix", "color", "android")
                    if (id == 0) continue
                    val argb = ContextCompat.getColor(this@MainActivity, id)
                    val hex = String.format("#%06x", argb and 0xFFFFFF)
                    if (!firstTone) out.append(",")
                    firstTone = false
                    out.append("\"").append(tone).append("\":\"").append(hex).append("\"")
                }
                out.append("}")
            }
            out.append("}")
            return out.toString()
        }

        /**
         * Saves an image the loopback UI hands us (base64) to the shared gallery
         * via MediaStore, under Pictures/Molepipe. Returns "" on success or a
         * short human message on failure, which the web layer shows as a toast in
         * the viewer. The bytes originate from our own first-party page (a photo
         * the user is already viewing in-app), so this only writes the user's own
         * content to their own gallery — no new inbound attack surface.
         *
         * Runs on the WebView's JS-bridge thread, not the UI thread, so the stream
         * write is fine here. MediaStore needs no runtime permission on API 29+
         * (scoped storage); on older devices we decline rather than ship a control
         * that would need WRITE_EXTERNAL_STORAGE and fail silently.
         */
        @JavascriptInterface
        fun saveImageToGallery(base64: String, mime: String): String {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                return "Saving to the gallery needs Android 10 or newer."
            }
            return try {
                val bytes = Base64.decode(base64, Base64.DEFAULT)
                // Limit decoded size to 10 MiB to prevent memory/storage abuse.
                if (bytes.size > 10 * 1024 * 1024) {
                    return "Image too large."
                }
                // Extension + stored MIME follow the actual type, so an animated GIF
                // isn't saved as a static-looking .jpg (it must land as image/gif to
                // animate in the gallery). Types match the backend allowlist.
                val (ext, safeMime) = when {
                    mime.contains("png", ignoreCase = true) -> "png" to "image/png"
                    mime.contains("gif", ignoreCase = true) -> "gif" to "image/gif"
                    mime.contains("webp", ignoreCase = true) -> "webp" to "image/webp"
                    else -> "jpg" to "image/jpeg"
                }
                val name = "molepipe_${System.currentTimeMillis()}.$ext"
                val resolver = contentResolver
                val values = ContentValues().apply {
                    put(MediaStore.Images.Media.DISPLAY_NAME, name)
                    put(MediaStore.Images.Media.MIME_TYPE, safeMime)
                    put(MediaStore.Images.Media.RELATIVE_PATH, "Pictures/Molepipe")
                    put(MediaStore.Images.Media.IS_PENDING, 1)
                }
                val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)
                    ?: return "Couldn't save to the gallery."
                resolver.openOutputStream(uri)?.use { it.write(bytes) }
                    ?: return "Couldn't write the photo."
                values.clear()
                values.put(MediaStore.Images.Media.IS_PENDING, 0)
                resolver.update(uri, values, null, null)
                ""
            } catch (t: Throwable) {
                "Couldn't save that photo."
            }
        }

        /**
         * Shares an image via the OS share sheet (Intent.ACTION_SEND).
         *
         * Writes the decoded bytes to a temp file, obtains a content URI from
         * the existing FileProvider, and launches a chooser. Runs on the
         * WebView's JS-bridge thread — the intent launch is async so the UI
         * thread is never blocked.
         */
        @JavascriptInterface
        fun shareImage(base64: String, mime: String) {
            try {
                val bytes = Base64.decode(base64, Base64.DEFAULT)
                if (bytes.size > 10 * 1024 * 1024) return
                val (ext, safeMime) = when {
                    mime.contains("png", ignoreCase = true) -> "png" to "image/png"
                    mime.contains("gif", ignoreCase = true) -> "gif" to "image/gif"
                    mime.contains("webp", ignoreCase = true) -> "webp" to "image/webp"
                    else -> "jpg" to "image/jpeg"
                }
                val tmpFile = File(cacheDir, "share_${System.currentTimeMillis()}.$ext")
                tmpFile.outputStream().use { it.write(bytes) }
                val uri = FileProvider.getUriForFile(this@MainActivity, "$packageName.fileprovider", tmpFile)
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = safeMime
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                startActivity(Intent.createChooser(intent, "Share image"))
            } catch (_: Throwable) {}
        }
    }

    // The notification is nice-to-have; a denied permission does not block the
    // service, it just means the persistent notice is not shown on 13+.
    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    // A getUserMedia() call in the WebView (the QR scanner) asks for the camera
    // via onPermissionRequest. If we don't yet hold the runtime CAMERA permission
    // we stash the WebView's request, fire the system prompt, and grant/deny it
    // from the result — so the first tap on "Scan" just works instead of failing
    // and needing a second tap.
    private var pendingCameraRequest: PermissionRequest? = null
    private val requestCamera =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            val req = pendingCameraRequest ?: return@registerForActivityResult
            pendingCameraRequest = null
            if (granted) req.grant(arrayOf(PermissionRequest.RESOURCE_VIDEO_CAPTURE)) else req.deny()
        }

    // Backs the photo <input type="file"> in the WebView: onShowFileChooser hands
    // us the page's callback, we launch the system picker, and feed the chosen
    // URI(s) back. A null result (cancel) must be delivered too, or the WebView's
    // file input stays wedged and won't reopen.
    private var filePathCallback: ValueCallback<Array<Uri>>? = null
    private val pickFile =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val cb = filePathCallback ?: return@registerForActivityResult
            filePathCallback = null
            val parsed = WebChromeClient.FileChooserParams.parseResult(result.resultCode, result.data)
            if (parsed == null) {
                cb.onReceiveValue(null)
                return@registerForActivityResult
            }
            // The WebView's Chromium can't decode HEIC/HEIF (iPhone photos), so
            // transcode any picked HEIC to a JPEG our web layer can read. Off the
            // main thread — decode + JPEG encode can take 100ms+ on a big photo.
            Thread {
                val out = try { transcodeHeicUris(parsed) } catch (_: Throwable) { parsed }
                cb.onReceiveValue(out)
            }.start()
        }

    // transcodeHeicUris replaces any HEIC/HEIF picks with a freshly-written JPEG
    // (via FileProvider) and passes everything else through untouched.
    private fun transcodeHeicUris(uris: Array<Uri>): Array<Uri> =
        Array(uris.size) { i -> transcodeHeicOne(uris[i]) ?: uris[i] }

    // transcodeHeicOne returns a content:// URI to a JPEG copy of a HEIC/HEIF
    // pick, or null to leave the original untouched (non-HEIC, pre-API-28, or any
    // decode failure — the web layer then shows a friendly "couldn't read" error).
    private fun transcodeHeicOne(uri: Uri): Uri? {
        val type = contentResolver.getType(uri)?.lowercase() ?: ""
        val isHeic = type == "image/heic" || type == "image/heif" ||
            type == "image/heic-sequence" || type == "image/heif-sequence"
        if (!isHeic) return null
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null // ImageDecoder HEIF is API 28+
        return try {
            val src = ImageDecoder.createSource(contentResolver, uri)
            val bmp = ImageDecoder.decodeBitmap(src) { decoder, info, _ ->
                decoder.isMutableRequired = false
                // Bound decode cost; the web layer downscales to 1600px anyway.
                val longest = maxOf(info.size.width, info.size.height)
                val sample = maxOf(1, longest / 2048)
                if (sample > 1) decoder.setTargetSampleSize(sample)
            }
            val out = File(cacheDir, "picked_${System.currentTimeMillis()}.jpg")
            FileOutputStream(out).use { bmp.compress(Bitmap.CompressFormat.JPEG, 90, it) }
            bmp.recycle()
            FileProvider.getUriForFile(this, "$packageName.fileprovider", out)
        } catch (_: Throwable) {
            null
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        // WebView remote debugging exposes the live page — and with it the
        // in-page control token — over an adb-reachable DevTools socket
        // (webview_devtools_remote_<pid>). Bind it to the build type so it is on
        // while developing and provably off in a release build, independent of
        // any WebView-version default that keys off the debuggable manifest flag.
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)

        webView = WebView(this).apply {
            setBackgroundColor(Color.TRANSPARENT)
            settings.javaScriptEnabled = true       // the UI is a JS app
            settings.domStorageEnabled = true       // it uses localStorage
            settings.cacheMode = WebSettings.LOAD_DEFAULT
            settings.mediaPlaybackRequiresUserGesture = true
            addJavascriptInterface(ShellBridge(), "AndroidShell")
            // Re-apply the cached insets once the page has actually loaded — the
            // insets listener below usually fires while the WebView is still
            // blank, so its evaluateJavascript lands on a document that is thrown
            // away when the real UI loads.
            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView, url: String) {
                    insetsJs?.let { view.evaluateJavascript(it, null) }
                }
            }
            // Grant the WebView's camera request (QR scanner) only for video
            // capture, and only once the app holds the runtime CAMERA permission —
            // otherwise stash it and prompt (see requestCamera). The page is our
            // own first-party 127.0.0.1 content, so there is no cross-origin
            // camera exposure to worry about.
            webChromeClient = object : WebChromeClient() {
                override fun onPermissionRequest(request: PermissionRequest) {
                    if (PermissionRequest.RESOURCE_VIDEO_CAPTURE !in request.resources) {
                        request.deny()
                        return
                    }
                    if (ContextCompat.checkSelfPermission(this@MainActivity, Manifest.permission.CAMERA)
                        == PackageManager.PERMISSION_GRANTED
                    ) {
                        request.grant(arrayOf(PermissionRequest.RESOURCE_VIDEO_CAPTURE))
                    } else {
                        pendingCameraRequest = request
                        requestCamera.launch(Manifest.permission.CAMERA)
                    }
                }

                override fun onShowFileChooser(
                    view: WebView?,
                    callback: ValueCallback<Array<Uri>>?,
                    params: FileChooserParams?,
                ): Boolean {
                    filePathCallback?.onReceiveValue(null) // unblock any prior chooser
                    filePathCallback = callback
                    val intent = params?.createIntent()
                    if (intent == null) {
                        filePathCallback = null
                        return false
                    }
                    return try {
                        pickFile.launch(intent)
                        true
                    } catch (_: Throwable) {
                        filePathCallback = null
                        false
                    }
                }
            }
        }
        setContentView(webView)

        // Under edge-to-edge the OS otherwise paints a translucent contrast scrim
        // behind the bars; we draw our own header/nav colour up into that space,
        // so turn the scrim off for a seamless look (API 29+).
        if (Build.VERSION.SDK_INT >= 29) {
            window.isStatusBarContrastEnforced = false
            window.isNavigationBarContrastEnforced = false
        }

        // Feed the status-bar / navigation-bar safe-area sizes into the CSS
        // custom properties the stylesheet pads with (--sat/--sab/--sal/--sar).
        ViewCompat.setOnApplyWindowInsetsListener(webView) { _, windowInsets ->
            val bars = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
            val nav = windowInsets.getInsets(WindowInsetsCompat.Type.navigationBars())
            val ime = windowInsets.getInsets(WindowInsetsCompat.Type.ime())
            val density = resources.displayMetrics.density
            val topDp = bars.top / density
            // Use the larger of systemBars bottom and navigationBars bottom
            // to handle 3-button navigation mode correctly.
            val bottomDp = maxOf(bars.bottom, nav.bottom) / density
            val leftDp = bars.left / density
            val rightDp = bars.right / density
            // The soft keyboard's height ABOVE the navigation bar. Under edge-to-edge
            // the window no longer resizes for the IME, so the page must make its own
            // room or the compose box hides behind the keyboard. Only the part above
            // the nav bar is added, because the compose box already pads by --sab —
            // adding the whole IME inset would double-count that strip.
            val kbDp = maxOf(0, ime.bottom - bars.bottom) / density

            // Guard document.documentElement: this listener usually fires while the
            // WebView is still blank (see onPageFinished above), where the root
            // element is null and an unguarded `.style` throws an "Uncaught
            // TypeError: reading 'style'" into the console. The no-op early call is
            // then re-applied for real once the page loads.
            insetsJs =
                "(function(){var e=document.documentElement;if(!e)return;" +
                "e.style.setProperty('--sat', '${topDp}px');" +
                "e.style.setProperty('--sab', '${bottomDp}px');" +
                "e.style.setProperty('--sal', '${leftDp}px');" +
                "e.style.setProperty('--sar', '${rightDp}px');" +
                "e.style.setProperty('--kb', '${kbDp}px');})();"
            webView.evaluateJavascript(insetsJs!!, null)
            windowInsets
        }

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        // Start (or re-attach to) the always-on backend. Idempotent.
        BackendService.start(this)
        maybeAskBatteryExemption()

        onBackPressedDispatcher.addCallback(this) {
            webView.evaluateJavascript("window.handleAndroidBack ? window.handleAndroidBack() : false") { result ->
                if (result != "true") {
                    if (webView.canGoBack()) {
                        webView.goBack()
                    } else {
                        finish()
                    }
                }
            }
        }
    }

    // maybeAskBatteryExemption asks the user, once, to exempt the app from Doze
    // so an aggressive OEM doesn't defer the always-on Tor node's network in deep
    // idle. It shows an explanatory dialog first so the user understands why,
    // then fires the system intent. Declining is fine — it just means the phone
    // may be slower to reach after it's been idle a while.
    @SuppressLint("BatteryLife")
    private fun maybeAskBatteryExemption() {
        val prefs = getSharedPreferences("shell", MODE_PRIVATE)
        if (prefs.getBoolean("asked_battery_exemption", false)) return
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        // Record the ask up front, so a dismissed dialog isn't re-shown every launch.
        prefs.edit().putBoolean("asked_battery_exemption", true).apply()
        AlertDialog.Builder(this)
            .setTitle("Keep connections alive?")
            .setMessage(
                "Some phones pause background apps to save battery. " +
                "Exempting this app lets Tor stay connected so you can " +
                "receive messages even when the app is closed."
            )
            .setPositiveButton("Allow") { _, _ ->
                try {
                    startActivity(
                        Intent(
                            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                            Uri.parse("package:$packageName"),
                        )
                    )
                } catch (_: Throwable) {
                    // Some devices lack this settings screen; ignore.
                }
            }
            .setNegativeButton("Not now", null)
            .show()
    }

    override fun onStart() {
        super.onStart()
        // The window is visible: suppress message notifications and clear any that
        // stacked up while it was away — the UI itself now shows the messages.
        AppState.inForeground = true
        MessageNotifier.clearAll()
        Backend.setListener(::render) // fired immediately with the current state
        // Wake arti from dormant mode so proactive circuit building and directory
        // fetches resume — we need full Tor connectivity while in the foreground.
        Backend.setDormant(false)
        // Re-apply insets in case the navigation mode changed while paused.
        insetsJs?.let { webView.evaluateJavascript(it, null) }
    }

    override fun onStop() {
        AppState.inForeground = false
        Backend.setListener(null)
        // Let arti go dormant while backgrounded: suspend proactive background
        // tasks (preemptive circuits, directory fetches) to conserve CPU and
        // battery. Existing circuits and TCP connections stay alive.
        Backend.setDormant(true)
        super.onStop()
    }

    private fun render(state: Backend.State) {
        when (state) {
            is Backend.State.Running ->
                if (loadedUrl != state.url) {
                    loadedUrl = state.url
                    val targetUrl = if (state.url.contains("?")) "${state.url}&shell=android" else "${state.url}?shell=android"
                    webView.loadUrl(targetUrl)
                }
            is Backend.State.Failed ->
                Toast.makeText(this, state.message, Toast.LENGTH_LONG).show()
            // Starting / Stopped: the WebView stays blank. Start is fast enough
            // that a dedicated splash is not worth the complexity for the shell.
            else -> Unit
        }
    }
}

