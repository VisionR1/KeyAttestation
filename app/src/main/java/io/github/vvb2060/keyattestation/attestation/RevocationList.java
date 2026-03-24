package io.github.vvb2060.keyattestation.attestation;

import android.content.Context;
import android.os.Build;
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

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public record RevocationList(String status, String reason, DataSource source) {
    public enum DataSource {
        NETWORK_UPDATE,
        NETWORK_UP_TO_DATE,
        CACHE,
        BUNDLED
    }

    private static final String TAG = "RevocationList";
    private static final String CACHE_FILE = "revocation_cache.json";
    private static final String PREFS_NAME = "revocation_prefs";
    private static final String KEY_PUBLISH_TIME = "last_publish_time";
    
    private static JSONObject data = null;
    private static Date publishTime = null;
    private static DataSource currentSource = DataSource.BUNDLED;

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
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setRequestProperty("User-Agent", "KeyAttestation");
            
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
            Log.w(TAG, "Network fetch failed", e);
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private static StatusResult getStatus() {
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
        
        // 1. Network Check
        NetworkResult networkResult = fetchFromNetwork(statusUrl, cachedTime);
        
        if (networkResult != null && networkResult.responseCode() == HttpURLConnection.HTTP_NOT_MODIFIED) {
            try (var fis = AppApplication.app.openFileInput(CACHE_FILE)) {
                var cacheJson = parseStatus(fis);
                publishTime = new Date(cachedTime);
                return new StatusResult(cacheJson.getJSONObject("entries"), DataSource.NETWORK_UP_TO_DATE);
            } catch (Exception e) {
                Log.w(TAG, "Legacy cache format detected. Clearing and forcing fresh fetch.", e);
                
                // 1. Wipe the old, incompatible cache file
                AppApplication.app.deleteFile(CACHE_FILE);
                
                // 2. Wipe the saved timestamp so we don't send If-Modified-Since again
                prefs.edit().remove(KEY_PUBLISH_TIME).apply();
                
                // 3. Immediately force a fresh 200 OK download
                NetworkResult retryResult = fetchFromNetwork(statusUrl, 0);
                
                if (retryResult != null && retryResult.json() != null) {
                    saveToCache(retryResult.json()); 
                    
                    try {
                        return new StatusResult(retryResult.json().getJSONObject("entries"), DataSource.NETWORK_UPDATE);
                    } catch (JSONException je) {
                        Log.e(TAG, "Failed to parse entries from fresh fallback fetch", je);
                    }
                }
            }
        } else if (networkResult != null && networkResult.json() != null) {
            saveToCache(networkResult.json());
            try {
                return new StatusResult(networkResult.json().getJSONObject("entries"), DataSource.NETWORK_UPDATE);
            } catch (JSONException ignored) {}
        }

        // 2. Cache
        try (var fis = AppApplication.app.openFileInput(CACHE_FILE)) {
            var cacheJson = parseStatus(fis);
            if (cachedTime != 0) publishTime = new Date(cachedTime);
            return new StatusResult(cacheJson.getJSONObject("entries"), DataSource.CACHE);
        } catch (Exception e) {
            Log.i(TAG, "Cache unavailable");
        }

        // 3. Bundled
        try (var input = res.openRawResource(R.raw.status)) {
            var bundledJson = parseStatus(input);
            publishTime = null; 
            return new StatusResult(bundledJson.getJSONObject("entries"), DataSource.BUNDLED);
        } catch (Exception e) {
            throw new RuntimeException("Critical: Failed to load revocation data", e);
        }
    }

    public static Date getPublishTime() {
        return publishTime;
    }

    public static DataSource getCurrentSource() {
        return currentSource;
    }

    public static void refresh() {
        synchronized (RevocationList.class) {
            StatusResult result = getStatus();
            data = result.json();
            
            // If we successfully fetched a brand new file this session, 
            // don't let a subsequent UI refresh overwrite our status with a 304!
            if (currentSource == DataSource.NETWORK_UPDATE && result.source() == DataSource.NETWORK_UP_TO_DATE) {
                Log.i(TAG, "Preserving NETWORK_UPDATE status across multiple refreshes");
            } else {
                currentSource = result.source();
            }
        }
    }

    public static RevocationList get(BigInteger serialNumber) {
        if (data == null) {
            synchronized (RevocationList.class) {
                if (data == null) {
                    StatusResult result = getStatus();
                    data = result.json();
                    
                    if (currentSource == DataSource.NETWORK_UPDATE && result.source() == DataSource.NETWORK_UP_TO_DATE) {
                        Log.i(TAG, "Preserving NETWORK_UPDATE status in get()");
                    } else {
                        currentSource = result.source();
                    }
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
