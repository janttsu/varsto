// SPDX-License-Identifier: PolyForm-Shield-1.0.0
package `in`.soderlund.varsto

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import java.io.File

/** Foreground service that runs the Rust `varsto service` binary shipped as a native library. */
class VarstoService : Service() {
    private var process: Process? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, notification())
        ensureRunning()
        return START_STICKY
    }

    private fun ensureRunning() {
        process?.let { if (it.isAlive) return }
        val bin = File(applicationInfo.nativeLibraryDir, "libvarsto.so")
        val home = File(filesDir, "vault")
        home.mkdirs()
        // A state file from a previous run would carry a stale token.
        File(home, "service.json").delete()
        val pb = ProcessBuilder(bin.absolutePath, "--home", home.absolutePath, "service", "run", "--port", "17891", "--interval", "300")
        // Tell the interface it runs on a phone: folders get a place under the
        // app's external storage without asking the user for a path.
        val root = (getExternalFilesDir(null) ?: filesDir).resolve("Varsto")
        root.mkdirs()
        pb.environment()["VARSTO_MOBILE"] = "1"
        pb.environment()["VARSTO_FOLDER_ROOT"] = root.absolutePath
        pb.redirectErrorStream(true)
        pb.redirectOutput(File(home, "service.log"))
        process = pb.start()
        Thread {
            val rc = process?.waitFor() ?: -1
            // 75 = restart after a self-update; otherwise wait a little before restarting.
            Thread.sleep(if (rc == 75) 500 else 3000)
            ensureRunning()
        }.start()
    }

    private fun notification(): Notification {
        val channelId = "varsto"
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(channelId, "Varsto", NotificationManager.IMPORTANCE_LOW))
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, channelId)
            .setContentTitle("Varsto")
            .setContentText(getString(R.string.service_running))
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        process?.destroy()
        super.onDestroy()
    }

    companion object {
        fun serviceUrl(filesDir: File): String? {
            val f = File(File(filesDir, "vault"), "service.json")
            if (!f.exists()) return null
            val json = org.json.JSONObject(f.readText())
            return "http://127.0.0.1:${json.getInt("port")}/?token=${json.getString("token")}"
        }
    }
}
