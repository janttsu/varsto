// SPDX-License-Identifier: PolyForm-Shield-1.0.0
package `in`.soderlund.varsto

import android.content.Context
import android.system.Os
import java.io.File
import java.io.FileOutputStream
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * The app shell's own debug log, on by default: `files/vault/logs/varsto-app.log`
 * (next to the service's `varsto-service.log`), in the same line format as the
 * Rust core logger, rotated at 10 MiB with four old files kept.
 *
 * Never logged: the service URL (it carries the session token), the token,
 * passphrases, file contents. File names and paths are fine. As a last guard
 * any `token=...` that slips into a message is masked.
 */
object AppLog {
    const val ERROR = 1
    const val WARN = 2
    const val INFO = 3
    const val DEBUG = 4
    const val TRACE = 5

    /** Lines above this level are dropped. */
    @Volatile var maxLevel = DEBUG

    private const val MAX_SIZE = 10L * 1024 * 1024
    private const val KEEP = 4
    private val labels = arrayOf("ERROR", "WARN ", "INFO ", "DEBUG", "TRACE")
    private val stamp = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC)
    private val tokenRe = Regex("token=[^&\\s]*")
    private val pid = android.os.Process.myPid()
    private val lock = Any()
    private var dir: File? = null
    private var out: FileOutputStream? = null
    private var size = 0L
    private var lines = 0

    /** Open the log; called by the activity and the service (same process), harmless twice. */
    fun init(context: Context) {
        synchronized(lock) {
            if (dir != null) return
            val d = File(File(context.filesDir, "vault"), "logs")
            d.mkdirs()
            try { Os.chmod(d.path, "700".toInt(8)) } catch (e: Exception) { }
            dir = d
            open()
        }
    }

    fun e(module: String, msg: String, t: Throwable? = null) = log(ERROR, module, msg, t)
    fun w(module: String, msg: String, t: Throwable? = null) = log(WARN, module, msg, t)
    fun i(module: String, msg: String) = log(INFO, module, msg, null)
    fun d(module: String, msg: String, t: Throwable? = null) = log(DEBUG, module, msg, t)
    fun t(module: String, msg: String) = log(TRACE, module, msg, null)

    fun log(level: Int, module: String, msg: String, t: Throwable?) {
        if (level > maxLevel) return
        val full = if (t != null) "$msg: ${t.javaClass.simpleName}: ${t.message ?: ""}" else msg
        val text = full.replace('\n', ' ').replace('\r', ' ').replace(tokenRe, "token=<redacted>")
        val label = labels[level.coerceIn(1, 5) - 1]
        val line = "${stamp.format(Instant.now())} $label app[$pid/${Thread.currentThread().name}] $module: $text\n"
        val bytes = line.toByteArray(Charsets.UTF_8)
        synchronized(lock) {
            // A vault reset may remove the logs directory: look again now and then.
            if (++lines % 256 == 0 && dir?.let { File(it, name(0)).exists() } == false) {
                try { out?.close() } catch (e: Exception) { }
                dir?.mkdirs()
                open()
            }
            val o = out ?: return
            try {
                o.write(bytes)
                size += bytes.size
            } catch (e: Exception) {
                return
            }
            if (size > MAX_SIZE) rotate()
        }
    }

    private fun name(n: Int) = if (n == 0) "varsto-app.log" else "varsto-app.$n.log"

    private fun open() {
        val d = dir ?: return
        val f = File(d, name(0))
        out = try {
            if (!f.exists()) f.createNewFile()
            try { Os.chmod(f.path, "600".toInt(8)) } catch (e: Exception) { }
            size = f.length()
            FileOutputStream(f, true)
        } catch (e: Exception) {
            null
        }
    }

    private fun rotate() {
        try { out?.close() } catch (e: Exception) { }
        out = null
        val d = dir ?: return
        File(d, name(KEEP)).delete()
        for (n in KEEP - 1 downTo 0) {
            val f = File(d, name(n))
            if (f.exists()) f.renameTo(File(d, name(n + 1)))
        }
        open()
    }
}
