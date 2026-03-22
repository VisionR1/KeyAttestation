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
        // Defense in Depth: Layer 1
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

            // 5. Automatically clear the RKP keys on success so the next test fetches fresh certs
            if (result is Result.Success) {
                clearRkpKeys()
            }

            return@withContext result

        } catch (e: Exception) {
            Log.e(TAG, "RKP Action Failed", e)
            return@withContext Result.Error("Unexpected error: ${e.message}")
        }
    }

    // Shizuku recently made newProcess private to encourage using UserService, 
    // but we cleanly bypass it with reflection for these simple shell commands.
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
        val exitCode = process.waitFor()
        
        // Stop the logcat from lying to us on silent shell failures
        if (exitCode != 0) {
            val errorOutput = BufferedReader(InputStreamReader(process.errorStream)).use { it.readText() }
            Log.w(TAG, "Command '${command.joinToString(" ")}' failed with code $exitCode: $errorOutput")
        }
        
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
    
    private fun runCommandAndCaptureOutput(command: String): String {
        return try {
        // The Shizuku.newProcess API is hidden in recent versions, so we bypass it via reflection
            val clazz = Class.forName("rikka.shizuku.Shizuku")
            val method = clazz.getDeclaredMethod(
                "newProcess", 
                Array<String>::class.java, 
                Array<String>::class.java, 
                String::class.java
            )
            method.isAccessible = true
        
            // Execute the shell command and cast the result to a standard Java Process
            val process = method.invoke(null, arrayOf("sh", "-c", command), null, null) as java.lang.Process
        
            // Capture the standard output
            val reader = java.io.BufferedReader(java.io.InputStreamReader(process.inputStream))
            val output = reader.readText().trim()
            process.waitFor()
            output
        } catch (e: Exception) {
            "Error executing command: ${e.message}"
        }
    }


    suspend fun dumpCertChains(): Result {
        return kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            if (!Shizuku.pingBinder()) {
                return@withContext Result.Error("Shizuku is not running.")
            }

        val defaultOutput = runCommandAndCaptureOutput("cmd remote_provisioning certify default")
        val strongboxOutput = runCommandAndCaptureOutput("cmd remote_provisioning certify strongbox")

        val sb = java.lang.StringBuilder()
        
            sb.append("--- RKP DEFAULT HAL ---\n")
            sb.append(defaultOutput.ifEmpty { "No Default HAL output or unsupported." })
            sb.append("\n\n")
        
            sb.append("--- RKP STRONGBOX HAL ---\n")
            sb.append(strongboxOutput.ifEmpty { "No Strongbox HAL output or unsupported." })

        // Return the massive string payload in a Success wrapper
            Result.Success(sb.toString())
        }
    } 

    private fun getCsr(hal: String): String? {
        val output = runShizukuCommand("cmd", "remote_provisioning", "csr", hal).trim()
        return output.ifEmpty { null }
    }

    private fun clearRkpKeys() {
        try {
            Log.i(TAG, "Attempting to clear stored RKP keys...")
            // Try clearing both GMS and AOSP daemon packages. 
            // It will exit with code 1 on the one that doesn't exist, which runShizukuCommand will cleanly log.
            runShizukuCommand("pm", "clear", "com.google.android.rkpdapp")
            runShizukuCommand("pm", "clear", "com.android.rkpd")
            Log.i(TAG, "RKP key clearing commands executed.")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to execute pm clear commands for RKP keys.", e)
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
