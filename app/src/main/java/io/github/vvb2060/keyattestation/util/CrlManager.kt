package io.github.vvb2060.keyattestation.util

import android.app.Application
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import io.github.vvb2060.keyattestation.attestation.RevocationList

object CrlManager {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val _refreshTrigger = MutableLiveData<Unit>()
    val refreshTrigger: LiveData<Unit> = _refreshTrigger
    
    // Prevent redundant consecutive triggers causing a double load
    private var lastObservedSource: RevocationList.DataSource? = null

    fun install(application: Application) {
        val connectivityManager = application.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i("CrlManager", "Network ONLINE. Syncing...")
                sync()
            }

            override fun onLost(network: Network) {
                Log.i("CrlManager", "Network OFFLINE. Syncing...")
                sync()
            }
        }

        try {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            connectivityManager.registerNetworkCallback(request, networkCallback)
        } catch (e: Exception) {
            Log.w("CrlManager", "Failed to bind network status", e)
            sync()
        }
    }

    private fun sync() {
        // Leverages the internal background worker of RevocationList
        RevocationList.refreshAsync { source ->
            // If the incoming network source status matches what we already checked, skip it
            if (source == lastObservedSource) {
                Log.i("CrlManager", "Data state unchanged ($source). Skipping duplicate notification.")
                return@refreshAsync
            }

            lastObservedSource = source
            Log.i("CrlManager", "Sync complete ($source). Notifying UI...")
            mainHandler.post {
                _refreshTrigger.value = Unit
            }
        }
    }
}
