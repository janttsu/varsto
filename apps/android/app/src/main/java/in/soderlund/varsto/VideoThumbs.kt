// SPDX-License-Identifier: PolyForm-Shield-1.0.0
package `in`.soderlund.varsto

import android.content.Context
import android.graphics.Bitmap
import android.media.MediaMetadataRetriever
import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Video thumbnails on the phone: the service has no ffmpeg here, so it lists
 * the videos in plain folders that have none, and this makes a frame with
 * Android's own media framework and hands it back (the service checks,
 * encrypts and stores it like any other thumbnail).
 */
class VideoThumbs(private val context: Context) {
    @Volatile private var running = false

    fun start() {
        if (running) return
        running = true
        Thread {
            while (running) {
                try { round() } catch (e: Exception) { /* locked, starting, or offline: next round */ }
                Thread.sleep(60_000)
            }
        }.apply { isDaemon = true }.start()
    }

    fun stop() { running = false }

    private fun round() {
        val url = VarstoService.serviceUrl(context.filesDir) ?: return
        val base = url.substringBefore("/?")
        val token = url.substringAfter("token=")
        val list = JSONObject(call(base, token, "GET", "/api/thumbnails/wanted", null)).optJSONArray("videos") ?: return
        for (i in 0 until list.length()) {
            val v = list.getJSONObject(i)
            val jpeg = frame { it.setDataSource(v.getString("file")) } ?: continue
            val body = JSONObject()
                .put("folder", v.getString("folder"))
                .put("path", v.getString("path"))
                .put("jpeg", Base64.encodeToString(jpeg, Base64.NO_WRAP))
            try { call(base, token, "POST", "/api/thumbnail", body.toString()) } catch (e: Exception) { }
        }
    }

    companion object {
        /** A small JPEG of a gallery video, for a thumbnail sent with its upload. */
        fun frameOf(context: Context, uri: android.net.Uri): ByteArray? = frame { it.setDataSource(context, uri) }

        fun base64(jpeg: ByteArray): String = Base64.encodeToString(jpeg, Base64.NO_WRAP)

    private fun frame(open: (MediaMetadataRetriever) -> Unit): ByteArray? {
        val r = MediaMetadataRetriever()
        return try {
            open(r)
            val bmp = r.getFrameAtTime(1_000_000, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
                ?: r.getFrameAtTime(0) ?: return null
            val scale = 256.0 / maxOf(bmp.width, bmp.height)
            val small = if (scale < 1) Bitmap.createScaledBitmap(bmp, (bmp.width * scale).toInt().coerceAtLeast(1), (bmp.height * scale).toInt().coerceAtLeast(1), true) else bmp
            ByteArrayOutputStream().also { small.compress(Bitmap.CompressFormat.JPEG, 80, it) }.toByteArray()
        } catch (e: Exception) {
            null
        } finally {
            try { r.release() } catch (e: Exception) { }
        }
    }
    }

    private fun call(base: String, token: String, method: String, path: String, json: String?): String {
        val c = URL(base + path).openConnection() as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 2000
            c.readTimeout = 120_000
            c.setRequestProperty("X-Varsto-Token", token)
            if (json != null) {
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(json.toByteArray()) }
            }
            if (c.responseCode !in 200..299) throw IllegalStateException("HTTP ${c.responseCode}")
            return c.inputStream.bufferedReader().use { it.readText() }
        } finally {
            c.disconnect()
        }
    }
}
