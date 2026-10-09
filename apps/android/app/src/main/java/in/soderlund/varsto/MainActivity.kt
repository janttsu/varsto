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
            web.evaluateJavascript("window.varstoMediaAccess && window.varstoMediaAccess($granted, ${!granted && !canAsk})", null)
            if (granted) pokeCameraUpload()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.webViewClient = WebViewClient()
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
        load()
    }

    override fun onResume() {
        super.onResume()
        // Back from the all-files-access settings screen: let the page re-check.
        if (::web.isInitialized) web.evaluateJavascript("window.varstoResumed && window.varstoResumed()", null)
    }

    /** File inputs, and the page's dialogs should it ever use the window ones. */
    private fun chromeClient() = object : WebChromeClient() {
        override fun onShowFileChooser(view: WebView?, callback: ValueCallback<Array<Uri>>, params: FileChooserParams): Boolean {
            fileChooser?.onReceiveValue(null)
            fileChooser = callback
            val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
                putExtra(Intent.EXTRA_ALLOW_MULTIPLE, params.mode == FileChooserParams.MODE_OPEN_MULTIPLE)
            }
            return try {
                pickFiles.launch(Intent.createChooser(intent, getString(R.string.choose_files)))
                true
            } catch (e: Exception) {
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

    private fun urisOf(resultCode: Int, data: Intent?): Array<Uri>? {
        if (resultCode != Activity.RESULT_OK || data == null) return null
        val clip = data.clipData
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
            handler.post {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName"))
                try {
                    startActivity(intent)
                } catch (e: Exception) {
                    startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                }
            }
        }

        /** Camera upload settings and status as JSON (see CameraUpload.Settings.json). */
        @JavascriptInterface
        fun cameraUpload(): String = CameraUpload.Settings.json(this@MainActivity)

        @JavascriptInterface
        fun setCameraUpload(json: String) {
            CameraUpload.Settings.save(this@MainActivity, org.json.JSONObject(json))
            pokeCameraUpload()
        }

        @JavascriptInterface
        fun hasMediaAccess(): Boolean = CameraUpload.hasPermission(this@MainActivity)

        @JavascriptInterface
        fun requestMediaAccess() {
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
        handler.post {
            val file = File(path)
            if (!file.isFile) {
                AlertDialog.Builder(this).setMessage(getString(R.string.file_missing, file.name))
                    .setPositiveButton(android.R.string.ok, null).show()
                return@post
            }
            val uri = try {
                FileProvider.getUriForFile(this, "$packageName.files", file)
            } catch (e: IllegalArgumentException) {
                AlertDialog.Builder(this).setMessage(getString(R.string.file_not_shareable, path))
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
            startActivity(Intent.createChooser(intent, getString(if (share) R.string.share_with else R.string.open_with)))
        }
    }

    /** Load the interface once the service answers with the token in its state file.
     *  The file may still describe a previous run, so the token is checked first. */
    private fun load() {
        val url = VarstoService.serviceUrl(filesDir)
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
                code == 200
            } catch (e: Exception) {
                false
            }
            handler.post { if (ok) web.loadUrl(url) else retry() }
        }.start()
    }

    private fun retry() {
        if (attempts++ < 100) {
            handler.postDelayed({ load() }, 250)
        } else {
            web.loadData("<h2>Varsto service did not start</h2>", "text/html", "utf-8")
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (web.canGoBack()) web.goBack() else super.onBackPressed()
    }
}
