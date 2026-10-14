// SPDX-License-Identifier: PolyForm-Shield-1.0.0
package `in`.soderlund.varsto

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.JsPromptResult
import android.webkit.JsResult
import android.webkit.MimeTypeMap
import android.webkit.PermissionRequest
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.FrameLayout
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import android.content.res.Configuration
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat

/** Shows the local Varsto interface served by the background service. */
class MainActivity : AppCompatActivity() {
    private lateinit var web: WebView
    private val handler = Handler(Looper.getMainLooper())
    private var attempts = 0
    private var fileChooser: ValueCallback<Array<Uri>>? = null
    // A varsto:// link the app was opened with, until the page is there to take it.
    private var pendingLink: String? = null
    private var pageLoaded = false
    // The page's QR scanner asked for the camera; answered once Android has.
    private var cameraRequest: PermissionRequest? = null
    private val askCamera: ActivityResultLauncher<String> =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            val r = cameraRequest ?: return@registerForActivityResult
            cameraRequest = null
            if (granted) r.grant(arrayOf(PermissionRequest.RESOURCE_VIDEO_CAPTURE)) else r.deny()
        }
    private val pickFiles: ActivityResultLauncher<Intent> =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val cb = fileChooser ?: return@registerForActivityResult
            fileChooser = null
            cb.onReceiveValue(urisOf(result.resultCode, result.data))
        }
    // Camera upload: the page explained why before asking; it hears back whether access was
    // granted and whether Android will still ask (false once the user chose "don't ask again").
    private val askMedia: ActivityResultLauncher<Array<String>> =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
            val granted = CameraUpload.hasPermission(this)
            val canAsk = CameraUpload.permissions().any { p -> ActivityCompat.shouldShowRequestPermissionRationale(this, p) }
            AppLog.i("activity", "media access: granted=$granted canAskAgain=$canAsk")
            web.evaluateJavascript("window.varstoMediaAccess && window.varstoMediaAccess($granted, ${!granted && !canAsk})", null)
            if (granted) pokeCameraUpload()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AppLog.init(this)
        AppLog.i("activity", "onCreate (restored=${savedInstanceState != null})")
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView?, url: String?) {
                if (url?.startsWith("http://127.0.0.1") != true) return
                pageLoaded = true
                pendingLink?.let { pendingLink = null; openLink(it) }
            }
        }
        web.webChromeClient = chromeClient()
        web.addJavascriptInterface(Bridge(), "VarstoAndroid")
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            // Debug builds can be driven over chrome://inspect (and adb) for tests.
            WebView.setWebContentsDebuggingEnabled(true)
        }
        val root = FrameLayout(this)
        root.addView(web, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        setContentView(root)
        // Edge-to-edge is enforced on Android 15: keep the page below the status bar.
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(0, bars.top, 0, bars.bottom)
            WindowInsetsCompat.CONSUMED
        }
        // Dark status-bar icons on the light theme, light icons on the dark one.
        val night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        WindowCompat.getInsetsController(window, root).apply {
            isAppearanceLightStatusBars = !night
            isAppearanceLightNavigationBars = !night
        }
        if (Build.VERSION.SDK_INT >= 33) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        ContextCompat.startForegroundService(this, Intent(this, VarstoService::class.java))
        pendingLink = linkOf(intent)
        load()
    }

    /** A varsto:// link opened while the app runs: straight to the page. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val link = linkOf(intent) ?: return
        if (pageLoaded) openLink(link) else pendingLink = link
    }

    private fun linkOf(intent: Intent?): String? =
        intent?.data?.takeIf { intent.action == Intent.ACTION_VIEW && it.scheme == "varsto" }?.toString()

    private fun openLink(link: String) {
        web.evaluateJavascript("window.varstoOpenLink && window.varstoOpenLink(${org.json.JSONObject.quote(link)})", null)
    }

    override fun onResume() {
        super.onResume()
        AppLog.d("activity", "onResume")
        // Back from the all-files-access settings screen: let the page re-check.
        if (::web.isInitialized) web.evaluateJavascript("window.varstoResumed && window.varstoResumed()", null)
    }

    /** File inputs, and the page's dialogs should it ever use the window ones. */
    private fun chromeClient() = object : WebChromeClient() {
        /** The QR scanner's getUserMedia: the camera only, for the local page only. */
        override fun onPermissionRequest(request: PermissionRequest) {
            handler.post {
                val local = request.origin?.host == "127.0.0.1"
                if (!local || !request.resources.contains(PermissionRequest.RESOURCE_VIDEO_CAPTURE)) {
                    request.deny()
                } else if (ContextCompat.checkSelfPermission(this@MainActivity, Manifest.permission.CAMERA) == android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    request.grant(arrayOf(PermissionRequest.RESOURCE_VIDEO_CAPTURE))
                } else {
                    cameraRequest?.deny()
                    cameraRequest = request
                    askCamera.launch(Manifest.permission.CAMERA)
                }
            }
        }

        override fun onShowFileChooser(view: WebView?, callback: ValueCallback<Array<Uri>>, params: FileChooserParams): Boolean {
            fileChooser?.onReceiveValue(null)
            fileChooser = callback
            val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
                putExtra(Intent.EXTRA_ALLOW_MULTIPLE, params.mode == FileChooserParams.MODE_OPEN_MULTIPLE)
            }
            return try {
                pickFiles.launch(Intent.createChooser(intent, str(R.string.choose_files)))
                true
            } catch (e: Exception) {
                AppLog.w("activity", "file chooser could not open", e)
                fileChooser = null
                false
            }
        }

        override fun onJsAlert(view: WebView?, url: String?, message: String?, result: JsResult): Boolean {
            AlertDialog.Builder(this@MainActivity).setMessage(message).setCancelable(false)
                .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm() }.show()
            return true
        }

        override fun onJsConfirm(view: WebView?, url: String?, message: String?, result: JsResult): Boolean {
            AlertDialog.Builder(this@MainActivity).setMessage(message).setCancelable(false)
                .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm() }
                .setNegativeButton(android.R.string.cancel) { _, _ -> result.cancel() }.show()
            return true
        }

        override fun onJsPrompt(view: WebView?, url: String?, message: String?, defaultValue: String?, result: JsPromptResult): Boolean {
            val input = EditText(this@MainActivity).apply { setText(defaultValue ?: "") }
            AlertDialog.Builder(this@MainActivity).setMessage(message).setView(input).setCancelable(false)
                .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm(input.text.toString()) }
                .setNegativeButton(android.R.string.cancel) { _, _ -> result.cancel() }.show()
            return true
        }
    }

    /** A string in the language picked in the web UI (see VarstoService.localized). */
    private fun str(id: Int, vararg args: Any): String = VarstoService.localized(this).getString(id, *args)

    private fun urisOf(resultCode: Int, data: Intent?): Array<Uri>? {
        if (resultCode != Activity.RESULT_OK || data == null) return null
        val clip = data.clipData
        AppLog.d("activity", "file chooser returned ${clip?.itemCount ?: if (data.data != null) 1 else 0} item(s)")
        if (clip != null && clip.itemCount > 0) return Array(clip.itemCount) { clip.getItemAt(it).uri }
        return data.data?.let { arrayOf(it) }
    }

    /** What the page may ask the shell for: all files access, camera upload, and handing a file to another app. */
    inner class Bridge {
        @JavascriptInterface
        fun hasAllFilesAccess(): Boolean =
            Build.VERSION.SDK_INT >= 30 && Environment.isExternalStorageManager()

        @JavascriptInterface
        fun requestAllFilesAccess() {
            if (Build.VERSION.SDK_INT < 30) return
            AppLog.i("activity", "asking for all files access")
            handler.post {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName"))
                try {
                    startActivity(intent)
                } catch (e: Exception) {
                    AppLog.d("activity", "app-specific all files access screen missing, opening the general one", e)
                    startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                }
            }
        }

        /** Camera upload settings and status as JSON (see CameraUpload.Settings.json). */
        @JavascriptInterface
        fun cameraUpload(): String = CameraUpload.Settings.json(this@MainActivity)

        @JavascriptInterface
        fun setCameraUpload(json: String) {
            AppLog.i("activity", "camera upload settings changed: $json")
            CameraUpload.Settings.save(this@MainActivity, org.json.JSONObject(json))
            pokeCameraUpload()
        }

        @JavascriptInterface
        fun hasMediaAccess(): Boolean = CameraUpload.hasPermission(this@MainActivity)

        @JavascriptInterface
        fun requestMediaAccess() {
            AppLog.i("activity", "asking for media access")
            handler.post { askMedia.launch(CameraUpload.permissions()) }
        }

        /** This app's page in the system settings, where a refused permission can still be given. */
        @JavascriptInterface
        fun openAppSettings() {
            handler.post { startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))) }
        }

        @JavascriptInterface
        fun openFile(path: String) = handOff(path, false)

        @JavascriptInterface
        fun shareFile(path: String) = handOff(path, true)
    }

    private fun pokeCameraUpload() {
        ContextCompat.startForegroundService(this, Intent(this, VarstoService::class.java).setAction(VarstoService.ACTION_CAMERA_SCAN))
    }

    private fun handOff(path: String, share: Boolean) {
        AppLog.i("activity", "${if (share) "share" else "open"} $path")
        handler.post {
            val file = File(path)
            if (!file.isFile) {
                AppLog.w("activity", "hand-off: $path is not a file")
                AlertDialog.Builder(this).setMessage(str(R.string.file_missing, file.name))
                    .setPositiveButton(android.R.string.ok, null).show()
                return@post
            }
            val uri = try {
                FileProvider.getUriForFile(this, "$packageName.files", file)
            } catch (e: IllegalArgumentException) {
                AppLog.w("activity", "hand-off: $path is outside the shared roots", e)
                AlertDialog.Builder(this).setMessage(str(R.string.file_not_shareable, path))
                    .setPositiveButton(android.R.string.ok, null).show()
                return@post
            }
            val ext = file.extension.lowercase()
            val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
            val intent = if (share) {
                Intent(Intent.ACTION_SEND).apply { type = mime; putExtra(Intent.EXTRA_STREAM, uri) }
            } else {
                Intent(Intent.ACTION_VIEW).apply { setDataAndType(uri, mime) }
            }
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(intent, str(if (share) R.string.share_with else R.string.open_with)))
        }
    }

    /** Load the interface once the service answers with the token in its state file.
     *  The file may still describe a previous run, so the token is checked first. */
    private fun load() {
        // Never logged: the URL carries the session token.
        val url = try {
            VarstoService.serviceUrl(filesDir)
        } catch (e: Exception) {
            AppLog.d("activity", "service.json not readable yet", e)
            null
        }
        if (url == null) {
            retry()
            return
        }
        Thread {
            val ok = try {
                val token = url.substringAfter("token=")
                val c = URL(url.substringBefore("/?") + "/api/state").openConnection() as HttpURLConnection
                c.connectTimeout = 500
                c.readTimeout = 1000
                c.setRequestProperty("X-Varsto-Token", token)
                val code = c.responseCode
                c.disconnect()
                if (code != 200) AppLog.d("activity", "GET /api/state -> $code (attempt $attempts)")
                code == 200
            } catch (e: Exception) {
                AppLog.d("activity", "GET /api/state failed (attempt $attempts)", e)
                false
            }
            if (ok) AppLog.i("activity", "service answered after $attempts attempt(s): loading the interface")
            // The page opens with a one-time start code, not the session token.
            val bootUrl = if (!ok) null else try {
                val c = URL(url.substringBefore("/?") + "/api/session/boot").openConnection() as HttpURLConnection
                c.requestMethod = "POST"
                c.connectTimeout = 500
                c.readTimeout = 1000
                c.setRequestProperty("X-Varsto-Token", url.substringAfter("token="))
                c.setRequestProperty("Content-Type", "application/json")
                c.doOutput = true
                c.outputStream.use { it.write("{}".toByteArray()) }
                val code = org.json.JSONObject(c.inputStream.bufferedReader().readText()).getString("boot")
                c.disconnect()
                url.substringBefore("/?") + "/?boot=" + code
            } catch (e: Exception) {
                AppLog.d("activity", "no start code", e)
                null
            }
            handler.post {
                if (ok && bootUrl != null) {
                    // A link the app was opened with rides along as #link=; the page takes it.
                    val link = pendingLink
                    pendingLink = null
                    web.loadUrl(if (link == null) bootUrl else bootUrl + "#link=" + Uri.encode(link))
                } else retry()
            }
        }.start()
    }

    private fun retry() {
        if (attempts++ < 100) {
            handler.postDelayed({ load() }, 250)
        } else {
            AppLog.e("activity", "service did not answer after $attempts attempts")
            web.loadDataWithBaseURL(null, "<h2>${str(R.string.service_did_not_start)}</h2>", "text/html", "utf-8", null)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        AppLog.d("activity", if (web.canGoBack()) "back: previous page" else "back: leaving")
        if (web.canGoBack()) web.goBack() else super.onBackPressed()
    }
}
