// SPDX-License-Identifier: PolyForm-Shield-1.0.0
package `in`.soderlund.varsto

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import java.net.HttpURLConnection
import java.net.URL
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import android.content.res.Configuration
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat

/** Shows the local Varsto interface served by the background service. */
class MainActivity : AppCompatActivity() {
    private lateinit var web: WebView
    private val handler = Handler(Looper.getMainLooper())
    private var attempts = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.webViewClient = WebViewClient()
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
