package io.github.vvb2060.keyattestation.keystore

import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

object RkpRegistrationManager {
    private const val TAG = "RkpRegistration"
    private const val RKP_URL = "https://remoteprovisioning.googleapis.com/v1:signCertificates"

    enum class Action(val requestId: String) {
        REGISTER("keymint_register_for_new_root"),
        UNREGISTER("keymint_unregister")
    }

    sealed class Result {
        data class Success(val message: String) : Result()
        data class Error(val message: String) : Result()
    }

    suspend fun performAction(action: Action): Result = withContext(Dispatchers.IO) {
        if (!Shizuku.pingBinder()) {
            return@withContext Result.Error("Shizuku is not running or permission denied.")
        }

        try {
            // 1. Find the supported HAL
            val hal = getSupportedHal()
                ?: return@withContext Result.Error("No supported KeyMint HAL found.")

            // 2. Generate the CSR via Shizuku shell
            val csrBase64 = getCsr(hal)
            if (csrBase64.isNullOrBlank()) {
                return@withContext Result.Error("Failed to generate CSR from device.")
            }

            // 3. Decode base64 to raw bytes
            val csrBytes = Base64.decode(csrBase64, Base64.NO_WRAP)

            // 4. Send the POST request
            val result = sendRequest(csrBytes, action.requestId)

            // 5. Automatically clear the cache on success so the next test fetches fresh certs
            if (result is Result.Success) {
                clearRkpCache()
            }

            return@withContext result

        } catch (e: Exception) {
            Log.e(TAG, "RKP Action Failed", e)
            return@withContext Result.Error("Unexpected error: ${e.message}")
        }
    }

    // Shizuku recently made newProcess private to encourage using UserService, 
    // but we can cleanly bypass it with reflection for these simple shell commands.
    private fun runShizukuCommand(vararg command: String): String {
        val clazz = Class.forName("rikka.shizuku.Shizuku")
        val method = clazz.getDeclaredMethod(
            "newProcess",
            Array<String>::class.java,
            Array<String>::class.java,
            String::class.java
        )
        method.isAccessible = true // The magic line that bypasses the 'private' restriction
        
        val process = method.invoke(null, arrayOf(*command), null, null) as rikka.shizuku.ShizukuRemoteProcess
        val output = BufferedReader(InputStreamReader(process.inputStream)).use { it.readText() }
        process.waitFor()
        return output
    }

    private fun getSupportedHal(): String? {
        val output = runShizukuCommand("cmd", "remote_provisioning", "list")
        return when {
            output.contains("default") -> "default"
            output.contains("strongbox") -> "strongbox"
            else -> null
        }
    }

    private fun getCsr(hal: String): String? {
        val output = runShizukuCommand("cmd", "remote_provisioning", "csr", hal).trim()
        return output.ifEmpty { null }
    }

    private fun clearRkpCache() {
        try {
            // Try clearing both GMS and AOSP daemon packages. 
            // It will silently fail on the one that doesn't exist, which is perfectly fine.
            runShizukuCommand("pm", "clear", "com.google.android.rkpdapp")
            runShizukuCommand("pm", "clear", "com.android.rkpd")
            Log.i(TAG, "RKPD cache successfully cleared.")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to clear RKPD cache. A manual pm clear might be required.", e)
        }
    }

    private fun sendRequest(csrBytes: ByteArray, requestId: String): Result {
        var connection: HttpURLConnection? = null
        try {
            val url = URL("$RKP_URL?request_id=$requestId")
            connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.connectTimeout = 10000
            connection.readTimeout = 10000
            connection.setRequestProperty("Content-Type", "application/cbor")
            connection.doOutput = true

            connection.outputStream.use { it.write(csrBytes) }

            val responseCode = connection.responseCode
            return if (responseCode in 200..299) {
                Result.Success("Success: $requestId")
            } else if (responseCode == 400) {
                Result.Success("Device already in requested state (HTTP 400).")
            } else {
                Result.Error("Server rejected request: HTTP $responseCode")
            }
        } finally {
            connection?.disconnect()
        }
    }
}
