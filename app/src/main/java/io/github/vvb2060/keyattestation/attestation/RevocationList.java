package io.github.vvb2060.keyattestation.attestation;

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

public record RevocationList(String status, String reason) {
    private static final String TAG = "RevocationList";
    private static JSONObject data = null;
    private static Date publishTime = null;

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
            var statusListJson = new JSONObject(toString(inputStream));
            return statusListJson.getJSONObject("entries");
        } catch (JSONException e) {
            throw new IOException(e);
        }
    }

    private static JSONObject fetchFromNetwork(String statusUrl) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(statusUrl);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setRequestProperty("User-Agent", "KeyAttestation");
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Extract Last-Modified header for publish time
                long lastModified = connection.getLastModified();
                if (lastModified != 0) {
                    publishTime = new Date(lastModified);
                    Log.i(TAG, "Revocation list Last-Modified: " + publishTime);
                }
                
                try (var input = connection.getInputStream()) {
                    return parseStatus(input);
                }
            } else {
                Log.w(TAG, "Failed to fetch revocation list from network, HTTP " + responseCode);
                return null;
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to fetch revocation list from network", e);
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static JSONObject getStatus() {
        var statusUrl = "https://android.googleapis.com/attestation/status";
        var resName = "android:string/vendor_required_attestation_revocation_list_url";
        var res = AppApplication.app.getResources();
        // noinspection DiscouragedApi
        var id = res.getIdentifier(resName, null, null);
        if (id != 0) {
            var url = res.getString(id);
            if (!statusUrl.equals(url) && url.toLowerCase(Locale.ROOT).startsWith("https")) {
                statusUrl = url;
            }
        }
        
        // Try to fetch from network first
        JSONObject networkData = fetchFromNetwork(statusUrl);
        if (networkData != null) {
            Log.i(TAG, "Successfully fetched revocation list from network");
            return networkData;
        }
        
        // Fallback to local resource
        Log.i(TAG, "Using local revocation list");
        try (var input = res.openRawResource(R.raw.status)) {
            return parseStatus(input);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse certificate revocation status", e);
        }
    }

    public static Date getPublishTime() {
        return publishTime;
    }

    public static void refresh() {
        synchronized (RevocationList.class) {
            data = getStatus();
        }
    }

    public static RevocationList get(BigInteger serialNumber) {
        if (data == null) {
            synchronized (RevocationList.class) {
                if (data == null) {
                    data = getStatus();
                }
            }
        }
        String serialNumberString = serialNumber.toString(16).toLowerCase();
        JSONObject revocationStatus;
        try {
            revocationStatus = data.getJSONObject(serialNumberString);
        } catch (JSONException e) {
            return null;
        }
        try {
            var status = revocationStatus.getString("status");
            var reason = revocationStatus.getString("reason");
            return new RevocationList(status, reason);
        } catch (JSONException e) {
            return new RevocationList("", "");
        }
    }

    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }
}
