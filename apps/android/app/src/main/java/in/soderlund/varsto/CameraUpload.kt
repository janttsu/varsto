// SPDX-License-Identifier: PolyForm-Shield-1.0.0
package `in`.soderlund.varsto

import android.Manifest
import android.content.BroadcastReceiver
import android.content.ContentUris
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.HandlerThread
import android.provider.MediaStore
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.Calendar

/**
 * Camera upload: new photos and videos in MediaStore go into one Varsto folder,
 * in YYYY/MM subfolders named after the capture date, through the local service
 * (`POST /api/upload`), so they are encrypted and pushed like any other file.
 *
 * It runs inside [VarstoService], which is a foreground service anyway: a
 * ContentObserver on the image and video collections reacts to new items at
 * once, and power, network and a 30-minute timer retry what had to wait (vault
 * locked, not on Wi-Fi, not charging). WorkManager would add a second
 * scheduler next to a process that already runs for as long as Varsto syncs.
 *
 * Every uploaded item is remembered by its MediaStore id and date added in
 * `camera-upload-done.txt`, so nothing is uploaded twice, also across restarts.
 * Originals are only read, never changed or deleted.
 */
class CameraUpload(private val context: Context, private val progress: (String?) -> Unit) {
    private val thread = HandlerThread("camera-upload").apply { start() }
    private val worker = Handler(thread.looper)
    private val doneFile = File(context.filesDir, "camera-upload-done.txt")
    private var done: MutableSet<String>? = null
    private var started = false
    private val scanTask = Runnable { scanSafely() }
    private val periodic = object : Runnable {
        override fun run() {
            requestScan(0)
            worker.postDelayed(this, 30 * 60 * 1000L)
        }
    }
    private val observer = object : ContentObserver(worker) {
        override fun onChange(selfChange: Boolean) = requestScan(3000)
    }
    private val power = object : BroadcastReceiver() {
        override fun onReceive(c: Context?, i: Intent?) = requestScan(1000)
    }
    private val network = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(n: Network, caps: NetworkCapabilities) = requestScan(5000)
    }

    fun start() {
        if (started) return
        started = true
        val cr = context.contentResolver
        for (uri in collections()) cr.registerContentObserver(uri, true, observer)
        ContextCompat.registerReceiver(context, power, IntentFilter(Intent.ACTION_POWER_CONNECTED), ContextCompat.RECEIVER_NOT_EXPORTED)
        try {
            context.getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(network)
        } catch (e: Exception) {
            // Without network callbacks the timer still retries.
        }
        worker.post(periodic)
    }

    fun stop() {
        if (!started) return
        started = false
        context.contentResolver.unregisterContentObserver(observer)
        try { context.unregisterReceiver(power) } catch (e: Exception) {}
        try { context.getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(network) } catch (e: Exception) {}
        worker.removeCallbacksAndMessages(null)
        thread.quitSafely()
    }

    /** Scan after [delayMs]; bursts of MediaStore changes collapse into one scan. */
    fun requestScan(delayMs: Long) {
        worker.removeCallbacks(scanTask)
        worker.postDelayed(scanTask, delayMs)
    }

    private fun scanSafely() {
        try {
            scan()
        } catch (e: Exception) {
            setStatus("error", e.message ?: e.toString())
        } finally {
            progress(null)
        }
    }

    private fun scan() {
        val s = Settings.load(context)
        if (!s.enabled || s.folder.isEmpty()) return
        if (!hasPermission(context)) return setStatus("waiting", "Allow access to photos and videos")
        if (s.wifiOnly && !onWifi()) return setStatus("waiting", "Waiting for Wi-Fi")
        if (s.chargingOnly && !charging()) return setStatus("waiting", "Waiting for the charger")
        val items = newItems(s)
        if (items.isEmpty()) return setStatus("idle", null)
        val api = Api.connect(context) ?: return setStatus("waiting", "Waiting for the Varsto service")
        val state = JSONObject(api.get("/api/state"))
        if (!state.optBoolean("unlocked")) return setStatus("waiting", "Waiting for Varsto to be unlocked")
        val folders = JSONArray(api.get("/api/folders"))
        var encrypted = false
        var found = false
        for (i in 0 until folders.length()) {
            val f = folders.getJSONObject(i)
            if (f.optString("name") == s.folder && !f.isNull("path")) {
                found = true
                encrypted = !f.optBoolean("plain", true)
            }
        }
        if (!found) return setStatus("error", "Folder ${s.folder} is not on this phone")
        // Paths already in the folder, with their sizes: never overwrite a file.
        val existing = HashMap<String, Long>()
        val files = JSONArray(api.get("/api/files?folder=" + enc(s.folder)))
        for (i in 0 until files.length()) {
            val f = files.getJSONObject(i)
            existing[f.getString("path")] = f.optLong("size")
        }
        var uploaded = 0
        var skipped: String? = null
        for ((n, item) in items.withIndex()) {
            if (s.wifiOnly && !onWifi()) return setStatus("waiting", "Waiting for Wi-Fi")
            if (s.chargingOnly && !charging()) return setStatus("waiting", "Waiting for the charger")
            progress("Uploading ${n + 1} of ${items.size} to ${s.folder}")
            if (item.size > MAX_UPLOAD) {
                remember(item.key)
                skipped = "${item.name} is larger than 1 GiB and was skipped"
                continue
            }
            var path = item.dir + "/" + item.name
            if (existing[path] == item.size) {
                // Already there (uploaded before the list of done items was lost).
                remember(item.key)
                continue
            }
            var k = 2
            while (existing.containsKey(path)) {
                val dot = item.name.lastIndexOf('.')
                val base = if (dot > 0) item.name.substring(0, dot) else item.name
                val ext = if (dot > 0) item.name.substring(dot) else ""
                path = "${item.dir}/$base ($k)$ext"
                k++
            }
            val stream = context.contentResolver.openInputStream(item.uri) ?: continue
            stream.use { api.upload(s.folder, path, it, item.size) }
            existing[path] = item.size
            remember(item.key)
            uploaded++
            if (encrypted) {
                // Folders kept encrypted on the phone hold no plaintext they do not need;
                // the original is still in the gallery.
                try {
                    api.post("/api/free", JSONObject().put("folder", s.folder).put("path", path).toString())
                } catch (e: Exception) {}
            }
        }
        Settings.recordUploads(context, uploaded)
        if (skipped != null) setStatus("error", skipped) else setStatus("idle", null)
    }

    /** One photo or video waiting for upload. */
    private class Item(val key: String, val uri: Uri, val name: String, val size: Long, val dir: String)

    private fun collections(): List<Uri> = listOf(
        MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
        MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
    )

    @Suppress("DEPRECATION")
    private fun newItems(s: Settings): List<Item> {
        val seen = loadDone()
        val out = ArrayList<Item>()
        for ((kind, uri) in listOf("image" to collections()[0], "video" to collections()[1])) {
            val cols = mutableListOf(
                MediaStore.MediaColumns._ID,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.SIZE,
                MediaStore.MediaColumns.DATE_ADDED,
                MediaStore.Images.ImageColumns.DATE_TAKEN,
            )
            cols += if (Build.VERSION.SDK_INT >= 29) MediaStore.MediaColumns.RELATIVE_PATH else MediaStore.MediaColumns.DATA
            var where = "${MediaStore.MediaColumns.DATE_ADDED} >= ?"
            if (Build.VERSION.SDK_INT >= 29) where += " AND ${MediaStore.MediaColumns.IS_PENDING} = 0"
            context.contentResolver.query(uri, cols.toTypedArray(), where, arrayOf(s.since.toString()),
                "${MediaStore.MediaColumns.DATE_ADDED} ASC")?.use { c ->
                while (c.moveToNext()) {
                    val id = c.getLong(0)
                    val added = c.getLong(3)
                    val key = "$kind:$id:$added"
                    if (key in seen) continue
                    val where5 = c.getString(5) ?: ""
                    if (!wanted(where5, s)) continue
                    val name = (c.getString(1) ?: "$id").replace('/', '_')
                    val taken = c.getLong(4).takeIf { it > 0 } ?: (added * 1000)
                    val cal = Calendar.getInstance().apply { timeInMillis = taken }
                    val dir = "%04d/%02d".format(cal.get(Calendar.YEAR), cal.get(Calendar.MONTH) + 1)
                    out += Item(key, ContentUris.withAppendedId(uri, id), name, c.getLong(2), dir)
                }
            }
        }
        return out
    }

    /** Camera pictures (DCIM), and screenshots when asked for; other apps' images are left out. */
    private fun wanted(location: String, s: Settings): Boolean {
        val shot = location.contains("Screenshots", ignoreCase = true) || location.contains("Screen recordings", ignoreCase = true)
        if (shot) return s.screenshots
        return location.startsWith("DCIM/") || location.contains("/DCIM/")
    }

    private fun loadDone(): MutableSet<String> {
        done?.let { return it }
        val set = HashSet<String>()
        if (doneFile.exists()) doneFile.forEachLine { if (it.isNotBlank()) set += it.trim() }
        done = set
        return set
    }

    private fun remember(key: String) {
        loadDone() += key
        doneFile.appendText(key + "\n")
    }

    private fun setStatus(state: String, message: String?) = Settings.status(context, state, message)

    private fun onWifi(): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
    }

    private fun charging(): Boolean {
        val b = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) ?: return false
        return b.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) != 0
    }

    /** What the user chose in the interface, kept in the app's preferences. */
    data class Settings(
        val enabled: Boolean,
        val folder: String,
        val wifiOnly: Boolean,
        val chargingOnly: Boolean,
        val screenshots: Boolean,
        /** Items added before this moment (seconds) are not "new". */
        val since: Long,
    ) {
        companion object {
            private const val PREFS = "camera_upload"

            fun load(c: Context): Settings {
                val p = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                return Settings(
                    p.getBoolean("enabled", false), p.getString("folder", "") ?: "",
                    p.getBoolean("wifi_only", false), p.getBoolean("charging_only", false),
                    p.getBoolean("screenshots", false), p.getLong("since", 0),
                )
            }

            /** Store settings from the interface; switching on starts "new" from now. */
            fun save(c: Context, json: JSONObject) {
                val p = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                val enable = json.optBoolean("enabled")
                val e = p.edit()
                if (enable && !p.getBoolean("enabled", false)) e.putLong("since", System.currentTimeMillis() / 1000)
                e.putBoolean("enabled", enable)
                    .putString("folder", json.optString("folder").trim())
                    .putBoolean("wifi_only", json.optBoolean("wifi_only"))
                    .putBoolean("charging_only", json.optBoolean("charging_only"))
                    .putBoolean("screenshots", json.optBoolean("screenshots"))
                    .apply()
            }

            fun status(c: Context, state: String, message: String?) {
                c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                    .putString("state", state).putString("message", message ?: "")
                    .putLong("checked", System.currentTimeMillis() / 1000).apply()
            }

            fun recordUploads(c: Context, n: Int) {
                if (n == 0) return
                val p = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                p.edit().putLong("uploaded", p.getLong("uploaded", 0) + n)
                    .putLong("last_upload", System.currentTimeMillis() / 1000).apply()
            }

            /** Settings and status for the interface. */
            fun json(c: Context): String {
                val p = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                val s = load(c)
                return JSONObject()
                    .put("enabled", s.enabled).put("folder", s.folder)
                    .put("wifi_only", s.wifiOnly).put("charging_only", s.chargingOnly)
                    .put("screenshots", s.screenshots).put("since", s.since)
                    .put("permission", hasPermission(c))
                    .put("state", p.getString("state", "idle")).put("message", p.getString("message", ""))
                    .put("uploaded", p.getLong("uploaded", 0)).put("last_upload", p.getLong("last_upload", 0))
                    .toString()
            }
        }
    }

    /** Minimal client of the local service, with the token from its state file. */
    private class Api(private val base: String, private val token: String) {
        companion object {
            fun connect(c: Context): Api? {
                val url = VarstoService.serviceUrl(c.filesDir) ?: return null
                return Api(url.substringBefore("/?"), url.substringAfter("token="))
            }
        }

        private fun open(path: String, method: String): HttpURLConnection {
            val c = URL(base + path).openConnection() as HttpURLConnection
            c.requestMethod = method
            c.connectTimeout = 2000
            c.readTimeout = 10 * 60 * 1000
            c.setRequestProperty("X-Varsto-Token", token)
            return c
        }

        private fun finish(c: HttpURLConnection): String {
            try {
                val code = c.responseCode
                val stream = if (code in 200..299) c.inputStream else c.errorStream
                val body = stream?.bufferedReader()?.use { it.readText() } ?: ""
                if (code !in 200..299) {
                    val msg = try { JSONObject(body).optString("error", body) } catch (e: Exception) { body }
                    throw IllegalStateException(msg.ifEmpty { "HTTP $code" })
                }
                return body
            } finally {
                c.disconnect()
            }
        }

        fun get(path: String): String = finish(open(path, "GET"))

        fun post(path: String, json: String): String {
            val c = open(path, "POST")
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.outputStream.use { it.write(json.toByteArray()) }
            return finish(c)
        }

        fun upload(folder: String, path: String, input: java.io.InputStream, size: Long): String {
            val c = open("/api/upload?folder=" + enc(folder) + "&path=" + enc(path), "POST")
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/octet-stream")
            if (size > 0) c.setFixedLengthStreamingMode(size) else c.setChunkedStreamingMode(64 * 1024)
            c.outputStream.use { input.copyTo(it, 64 * 1024) }
            return finish(c)
        }
    }

    companion object {
        /** Same limit as the service's /api/upload. */
        const val MAX_UPLOAD = 1L shl 30

        private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8").replace("+", "%20")

        /** The runtime permissions camera upload asks for on this Android version. */
        fun permissions(): Array<String> =
            if (Build.VERSION.SDK_INT >= 33) arrayOf(Manifest.permission.READ_MEDIA_IMAGES, Manifest.permission.READ_MEDIA_VIDEO)
            else arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)

        fun hasPermission(c: Context): Boolean {
            if (Build.VERSION.SDK_INT >= 30 && Environment.isExternalStorageManager()) return true
            return permissions().all { ContextCompat.checkSelfPermission(c, it) == PackageManager.PERMISSION_GRANTED }
        }
    }
}
