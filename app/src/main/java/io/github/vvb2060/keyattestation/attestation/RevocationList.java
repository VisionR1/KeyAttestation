package io.github.vvb2060.keyattestation.attestation;

import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public record RevocationList(String status, String reason, DataSource source) {
    public enum DataSource {
        NETWORK_INITIAL,
        NETWORK_UPDATE,
        NETWORK_UP_TO_DATE,
        CACHE,
        BUNDLED
    }
    
    private static final String TAG = "RevocationList";
    private static final String CACHE_FILE = "revocation_cache.json";
    private static final String PREFS_NAME = "revocation_prefs";
    private static final String KEY_PUBLISH_TIME = "last_publish_time";
    
    private static volatile JSONObject data = null;
    private static volatile Date publishTime = null;
    private static volatile DataSource currentSource = DataSource.BUNDLED;
    private static volatile Future<NetworkResult> pendingFetch;

    private static final ExecutorService asyncExecutor = Executors.newSingleThreadExecutor();
    private static final ExecutorService networkExecutor = Executors.newSingleThreadExecutor();
    private static final Handler mainHandler = new Handler(Looper.getMainLooper());

    public interface OnUpdateListener {
        void onUpdateSuccess(DataSource newSource);
    }

    private record StatusResult(JSONObject json, DataSource source) {}
    private record NetworkResult(JSONObject json, int responseCode) {}

    private static String toString(InputStream input) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } else {
            var output = new ByteArrayOutputStream(8192);
            var buffer = new byte[8192];
            for (int length; (length = input.read(buffer)) != -1; ) {
                output.write(buffer, 0, length);
            }
            return output.toString();
        }
    }

    private static JSONObject parseStatus(InputStream inputStream) throws IOException {
        try {
            return new JSONObject(toString(inputStream));
        } catch (JSONException e) {
            throw new IOException(e);
        }
    }

    private static void saveToCache(JSONObject fullJson) {
        try (var output = AppApplication.app.openFileOutput(CACHE_FILE, Context.MODE_PRIVATE)) {
            output.write(fullJson.toString().getBytes(StandardCharsets.UTF_8));
            if (publishTime != null) {
                var prefs = AppApplication.app.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                prefs.edit().putLong(KEY_PUBLISH_TIME, publishTime.getTime()).apply();
            }
            Log.i(TAG, "Local cache file written successfully.");
        } catch (IOException e) {
            Log.w(TAG, "Failed to cache revocation list", e);
        }
    }

    private static NetworkResult fetchFromNetwork(String statusUrl, long cachedTime) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(statusUrl);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(10_000);
            connection.setReadTimeout(20_000);
            connection.setRequestProperty("User-Agent", "KeyAttestation");
            
            double rand = Math.round(Math.random() * 1000.0) / 1000.0;
            connection.setRequestProperty("Cache-Control", "no-cache, no-store, no-transform, max-age=0");
            connection.setRequestProperty("Accept", "application/json, */*;q=" + rand);
            connection.setRequestProperty("Accept-Encoding", "identity, *;q=" + rand);
            connection.setRequestProperty("Accept-Ranges", "bytes");
            
            if (cachedTime != 0) {
                connection.setIfModifiedSince(cachedTime);
            }
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_NOT_MODIFIED) {
                return new NetworkResult(null, responseCode);
            }
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                long lastModified = connection.getLastModified();
                if (lastModified != 0) {
                    publishTime = new Date(lastModified);
                }
                try (var input = connection.getInputStream()) {
                    return new NetworkResult(parseStatus(input), responseCode);
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private static NetworkResult fetchNetworkWithTimeout(String url, long cachedTime) {
        var future = pendingFetch;
        if (future == null || future.isDone()) {
            future = networkExecutor.submit(() -> fetchFromNetwork(url, cachedTime));
            pendingFetch = future;
        } else {
            Log.i(TAG, "Network fetch already in progress; reusing it instead of queuing another.");
        }
        try {
            return future.get(3, TimeUnit.SECONDS);
        } catch (Exception e) {
            Log.w(TAG, "Network fetch dropped gracefully (Hard 3-second DNS/Connection Timeout)");
            return null;
        }
    }

    private static StatusResult loadLocalData() {
        var prefs = AppApplication.app.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        long cachedTime = prefs.getLong(KEY_PUBLISH_TIME, 0);
        
        try (var fis = AppApplication.app.openFileInput(CACHE_FILE)) {
            var cacheJson = parseStatus(fis);
            if (cachedTime != 0) publishTime = new Date(cachedTime);
            Log.i(TAG, "Successfully matched database schemas inside local CACHE storage.");
            return new StatusResult(cacheJson.getJSONObject("entries"), DataSource.CACHE);
        } catch (Exception e) {
            Log.i(TAG, "Local file cache missing, loading baseline fallback asset.");
        }

        var res = AppApplication.app.getResources();
        try (var input = res.openRawResource(R.raw.status)) {
            var bundledJson = parseStatus(input);
            publishTime = null; 
            return new StatusResult(bundledJson.getJSONObject("entries"), DataSource.BUNDLED);
        } catch (Exception e) {
            throw new RuntimeException("Critical: Baseline resource asset file missing from app payload", e);
        }
    }

    public static void refreshAsync(OnUpdateListener listener) {
        asyncExecutor.execute(() -> {
            var statusUrl = "https://android.googleapis.com/attestation/status";
            var res = AppApplication.app.getResources();
            var resName = "android:string/vendor_required_attestation_revocation_list_url";
            var id = res.getIdentifier(resName, null, null);
            if (id != 0) {
                var url = res.getString(id);
                if (!statusUrl.equals(url) && url.toLowerCase(Locale.ROOT).startsWith("https")) {
                    statusUrl = url;
                }
            }

            var prefs = AppApplication.app.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            long cachedTime = prefs.getLong(KEY_PUBLISH_TIME, 0);

            Log.i(TAG, "Starting background network sync operation...");
            NetworkResult networkResult = fetchNetworkWithTimeout(statusUrl, cachedTime);
            DataSource finalSource = null;
            JSONObject finalEntries = null;

            if (networkResult != null && networkResult.responseCode() == HttpURLConnection.HTTP_NOT_MODIFIED) {
                Log.i(TAG, "Network connection reporting 304 Not Modified. Local data streams up to date.");
                try (var fis = AppApplication.app.openFileInput(CACHE_FILE)) {
                    var cacheJson = parseStatus(fis);
                    publishTime = new Date(cachedTime);
                    finalEntries = cacheJson.getJSONObject("entries");
                    finalSource = DataSource.NETWORK_UP_TO_DATE;
                } catch (Exception e) {
                    Log.w(TAG, "Legacy cache format error. Resetting storage contexts.", e);
                    AppApplication.app.deleteFile(CACHE_FILE);
                    prefs.edit().remove(KEY_PUBLISH_TIME).apply();
                    
                    NetworkResult retryResult = fetchNetworkWithTimeout(statusUrl, 0);
                    if (retryResult != null && retryResult.json() != null) {
                        saveToCache(retryResult.json());
                        try {
                            finalEntries = retryResult.json().getJSONObject("entries");
                            finalSource = DataSource.NETWORK_UPDATE;
                        } catch (JSONException ignored) {}
                    }
                }
            } else if (networkResult != null && networkResult.json() != null) {
                Log.i(TAG, "Network fetch SUCCESS! Downloaded updated production data components.");
                saveToCache(networkResult.json());
                try {
                    finalEntries = networkResult.json().getJSONObject("entries");
                    finalSource = (cachedTime == 0) ? DataSource.NETWORK_INITIAL : DataSource.NETWORK_UPDATE;
                } catch (JSONException ignored) {}
            } else {
                // CHANGE THIS: Force parsing the local cache when connection errors drop out
                Log.i(TAG, "Sync complete. Network timed out or dropped; falling back to offline cache.");
                try {
                    StatusResult localResult = loadLocalData();
                    finalEntries = localResult.json();
                    finalSource = localResult.source(); // Becomes DataSource.CACHE
                } catch (Exception e) {
                    Log.w(TAG, "Failed to load local data fallback during offline transition", e);
                }
            }
			
            if (finalEntries != null && finalSource != null) {
                final DataSource sourceToApply = finalSource;
                final JSONObject entriesToApply = finalEntries;
                
                synchronized (RevocationList.class) {
                    data = entriesToApply;
                    currentSource = sourceToApply;
                }

                if (listener != null) {
                    mainHandler.post(() -> listener.onUpdateSuccess(sourceToApply));
                }
            } else {
                Log.i(TAG, "Sync complete. Network timed out or dropped; local data streams unchanged.");
            }
        });
    }

    public static void refresh() {
        refreshAsync(null);
    }

    public static Date getPublishTime() {
        return publishTime;
    }

    public static DataSource getCurrentSource() {
        return currentSource;
    }

    public static RevocationList get(BigInteger serialNumber) {
        if (data == null) {
            synchronized (RevocationList.class) {
                if (data == null) {
                    StatusResult result = loadLocalData();
                    data = result.json();
                    currentSource = result.source();
                }
            }
        }
        String serial = serialNumber.toString(16).toLowerCase();
        try {
            JSONObject entry = data.getJSONObject(serial);
            return new RevocationList(entry.getString("status"), entry.getString("reason"), currentSource);
        } catch (JSONException e) {
            return null;
        }
    }

    @Override
    public String toString() {
        return "status: " + status + ", source: " + source;
    }
}
