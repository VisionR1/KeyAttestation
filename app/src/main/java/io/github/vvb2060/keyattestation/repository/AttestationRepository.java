package io.github.vvb2060.keyattestation.repository;

import static android.security.KeyStoreException.ERROR_ATTESTATION_KEYS_UNAVAILABLE;
import static android.security.KeyStoreException.ERROR_ID_ATTESTATION_FAILURE;
import static android.security.KeyStoreException.ERROR_KEYMINT_FAILURE;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_ATTEST_EC_KEY_RSA_ONLY;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_ATTEST_RSA_KEY_EC_ONLY;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_CANT_PARSE_CERT;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_DEVICEIDS_UNAVAILABLE;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_INVALID_FILE;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_KEYS_NOT_PROVISIONED;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_OUT_OF_KEYS;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_OUT_OF_KEYS_TRANSIENT;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_RKP;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_STRONGBOX_UNAVAILABLE;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_UNAVAILABLE;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_UNAVAILABLE_TRANSIENT;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_UNKNOWN;

import android.annotation.SuppressLint;
import android.hardware.security.keymint.DeviceInfo;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.security.KeyStoreException;
import android.security.keystore.DeviceIdAttestationException;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.security.ProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.keystore.AndroidKeyStore;
import io.github.vvb2060.keyattestation.keystore.IAndroidKeyStore;
import io.github.vvb2060.keyattestation.keystore.KeyBoxXmlParser;
import io.github.vvb2060.keyattestation.keystore.KeyStoreManager;
import io.github.vvb2060.keyattestation.lang.AttestationException;
import io.github.vvb2060.keyattestation.util.Resource;

public class AttestationRepository {
    private final AndroidKeyStore localKeyStore;
    private final CertificateFactory factory;
    private final List<X509Certificate> currentCerts;
    private IAndroidKeyStore keyStore;

    public AttestationRepository() throws Exception {
        localKeyStore = new AndroidKeyStore();
        factory = CertificateFactory.getInstance("X.509");
        currentCerts = new ArrayList<>();
        keyStore = localKeyStore;
    }

    public void useRemoteKeyStore(boolean useRemote) {
        if (useRemote) {
            keyStore = KeyStoreManager.getRemoteKeyStore();
        } else {
            keyStore = localKeyStore;
        }
    }

    public boolean hasCertificates() {
        return !currentCerts.isEmpty();
    }

    @SuppressWarnings("unchecked")
    private void generateCertificates(InputStream in) throws CertificateException {
        var list = (List<X509Certificate>) factory.generateCertificates(in);
        if (list.isEmpty()) {
            throw new CertificateException("No certificate");
        }
        currentCerts.addAll(list);
    }

    @SuppressWarnings("unchecked")
    private void generateCertPath(InputStream in) throws CertificateException {
        var list = (List<X509Certificate>) factory.generateCertPath(in).getCertificates();
        if (list.isEmpty()) {
            throw new CertificateException("No certificate");
        }
        currentCerts.addAll(list);
    }

    private void generateKeyPair(String alias, String attestKeyAlias,
                                 boolean useStrongBox, boolean includeProps,
                                 boolean uniqueIdIncluded, int idFlags,
                                 byte keyStoreKeyType, boolean useSak) throws Exception {
        var data = keyStore.generateKeyPair(alias, attestKeyAlias, useStrongBox,
                includeProps, uniqueIdIncluded, idFlags, keyStoreKeyType, useSak);
        if (data != null) {
            try (var it = new ObjectInputStream((new ByteArrayInputStream(data)))) {
                throw (Exception) it.readObject();
            }
        }
    }

    private void attestDeviceIds(int idFlags) throws Exception {
        var data = keyStore.attestDeviceIds(idFlags);
        var in = new ByteArrayInputStream(data);
        if (in.read() == 1) {
            generateCertificates(in);
        } else {
            try (var it = new ObjectInputStream((in))) {
                var exception = (Exception) it.readObject();
                throw new ProviderException(exception);
            }
        }
    }

    @SuppressLint("SwitchIntDef")
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private static AttestationException toAttestationException(KeyStoreException exception,
                                                               Exception e) {
        int code = exception.getNumericErrorCode();
        if (code == ERROR_ID_ATTESTATION_FAILURE) {
            return new AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e);
        }
        if (code >= ERROR_ATTESTATION_KEYS_UNAVAILABLE) {
            if (exception.isTransientFailure()) {
                return new AttestationException(CODE_OUT_OF_KEYS_TRANSIENT, e);
            } else {
                return new AttestationException(CODE_OUT_OF_KEYS, e);
            }
        }
        if (code == ERROR_KEYMINT_FAILURE) {
            if (exception.toString().contains("ATTESTATION_KEYS_NOT_PROVISIONED")) {
                return new AttestationException(CODE_KEYS_NOT_PROVISIONED, e);
            }
        }
        if (exception.isTransientFailure()) {
            return new AttestationException(CODE_UNAVAILABLE_TRANSIENT, e);
        } else {
            return new AttestationException(CODE_UNAVAILABLE, e);
        }
    }

    private void getCertChain(String alias) throws RemoteException, CertificateException {
        var certChain = keyStore.getCertificateChain(alias);
        if (certChain == null) {
            throw new ProviderException("Unable to get certificate chain");
        }
        generateCertificates(new ByteArrayInputStream(certChain));
    }

    private void doAttestation(boolean useAttestKey, boolean useStrongBox,
                               boolean includeProps, boolean uniqueIdIncluded,
                               int idFlags, byte keyStoreKeyType, boolean useSak) throws AttestationException {
        var alias = useStrongBox ? AppApplication.TAG + "_strongbox" : AppApplication.TAG;
        var attestKeyAlias = useAttestKey ? alias + "_persistent" : null;
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S && idFlags != 0) {
                attestDeviceIds(idFlags);
                return;
            }

            if (useAttestKey && !keyStore.containsAlias(attestKeyAlias)) {
                generateKeyPair(attestKeyAlias, attestKeyAlias, useStrongBox,
                        includeProps, uniqueIdIncluded, idFlags, keyStoreKeyType, false);
            }
            generateKeyPair(alias, attestKeyAlias, useStrongBox,
                    includeProps, uniqueIdIncluded, idFlags, keyStoreKeyType, useSak);

            getCertChain(alias);
            if (useAttestKey) {
                getCertChain(attestKeyAlias);
            }
        } catch (ProviderException e) {
            var cause = e.getCause();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                    && e instanceof StrongBoxUnavailableException) {
                throw new AttestationException(CODE_STRONGBOX_UNAVAILABLE, e);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                    && cause instanceof KeyStoreException keyStoreException) {
                throw toAttestationException(keyStoreException, e);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    && cause instanceof DeviceIdAttestationException) {
                throw new AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e);
            } else if (cause != null && cause.toString().contains("device ids")) {
                throw new AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e);
            } else {
                throw new AttestationException(CODE_UNAVAILABLE, e);
            }
        } catch (Exception e) {
            throw new AttestationException(CODE_UNKNOWN, e);
        }
    }

    public Resource<AttestationData> attest(boolean reset, boolean useAttestKey,
                                            boolean useStrongBox, boolean includeProps,
                                            boolean uniqueIdIncluded, int idFlags,
                                            byte keyStoreKeyType, boolean useSak) {
        currentCerts.clear();
        try {
            if (reset) keyStore.deleteAllEntry();
            doAttestation(useAttestKey, useStrongBox, includeProps,
                    uniqueIdIncluded, idFlags, keyStoreKeyType, useSak);
            var data = AttestationData.parseCertificateChain(currentCerts);
            try {
                data.vbmetaDigest = keyStore.getVbmetaDigest();
            } catch (Exception e) {
                var cause = e instanceof AttestationException ? e.getCause() : e;
                Log.w(AppApplication.TAG, "Get vbmeta digest error.", cause);
            }
            return Resource.Companion.success(data);
        } catch (Exception e) {
            var cause = e instanceof AttestationException ? e.getCause() : e;
            Log.w(AppApplication.TAG, "Do attestation error.", cause);

            if (e instanceof AttestationException) {
                return Resource.Companion.error(e, null);
            } else {
                return Resource.Companion.error(new AttestationException(CODE_UNKNOWN, e), null);
            }
        }
    }

    /**
     * Load certificates from file, supporting multiple formats (binary, XML, PEM).
	 * Automatically filters to requested algorithm (RSA or EC).
     */
    public Resource<BaseData> loadCerts(ParcelFileDescriptor pfd, boolean preferRsa) {
        currentCerts.clear();
        try {
            // 1. Read raw bytes from file
            byte[] bytes;
            try (var in = new ParcelFileDescriptor.AutoCloseInputStream(pfd)) {
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    baos.write(buffer, 0, read);
                }
                bytes = baos.toByteArray();
            }

            // Strip a UTF-8 BOM if present -- it trips the plain-ASCII sanity check further down.
            if (bytes.length >= 3 && (bytes[0] & 0xFF) == 0xEF && (bytes[1] & 0xFF) == 0xBB && (bytes[2] & 0xFF) == 0xBF) {
                bytes = java.util.Arrays.copyOfRange(bytes, 3, bytes.length);
            }

            boolean parsedBinary = false;

            // 1a. Skip binary cert parsing for XML input to avoid chain corruption.
            int sniffLen = Math.min(bytes.length, 512);
            String sniff = new String(bytes, 0, sniffLen, java.nio.charset.StandardCharsets.UTF_8).trim();
            boolean looksLikeKeyboxXml = sniff.startsWith("<?xml") || sniff.contains("<AndroidAttestation");

            // 2. Parse binary format (PKCS7, PkiPath)
            if (!looksLikeKeyboxXml) {
                try (var bis = new java.io.ByteArrayInputStream(bytes)) {
                    java.security.cert.CertPath certPath = factory.generateCertPath(bis, "PkiPath");
                    for (java.security.cert.Certificate cert : certPath.getCertificates()) {
                        if (cert instanceof X509Certificate) {
                            currentCerts.add((X509Certificate) cert);
                        }
                    }
                    if (!currentCerts.isEmpty()) parsedBinary = true;
                } catch (Exception e) {
                    currentCerts.clear();
                    try (var bis = new java.io.ByteArrayInputStream(bytes)) {
                        java.util.Collection<? extends java.security.cert.Certificate> certsCollection = factory.generateCertificates(bis);
                        for (java.security.cert.Certificate cert : certsCollection) {
                            if (cert instanceof X509Certificate) {
                                currentCerts.add((X509Certificate) cert);
                            }
                        }
                        if (!currentCerts.isEmpty()) parsedBinary = true;
                    } catch (Exception ignored) {}
                }
            }

            // 2a. Filter to RSA certs only
            if (parsedBinary && preferRsa && !currentCerts.isEmpty()) {
                List<X509Certificate> rsaCerts = new ArrayList<>();
                for (X509Certificate cert : currentCerts) {
                    if (cert.getPublicKey().getAlgorithm().equalsIgnoreCase("RSA")) {
                        rsaCerts.add(cert);
                    }
                }
                if (!rsaCerts.isEmpty()) {
                    currentCerts.clear();
                    currentCerts.addAll(rsaCerts);
                }
            }

            // 3. Parse XML
            if (!parsedBinary) {
				String xmlContent = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                for (char c : xmlContent.toCharArray()) {
                    if (c > 127 && !Character.isWhitespace(c)) {  // Non-ASCII except whitespace
                        throw new AttestationException(CODE_INVALID_FILE, null);
                    }
                }
				
                boolean parsedViaXmlParser = false;
                try (var bis = new java.io.ByteArrayInputStream(bytes)) {
                    var xmlEntry = KeyBoxXmlParser.getInstance().parse(bis, preferRsa);
                    java.security.cert.Certificate[] chain = xmlEntry.getCertificateChain();
                    if (chain != null) {
                        for (java.security.cert.Certificate cert : chain) {
                            if (cert instanceof X509Certificate) {
                                currentCerts.add((X509Certificate) cert);
                            }
                        }                        
                        if (!currentCerts.isEmpty()) {
                            parsedViaXmlParser = true;
                        }
                    }
                } catch (Exception ignored) {}

                // 3a: Lenient regex parser for unstructured XML/PEM
                if (!parsedViaXmlParser) {
                    String content = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                    List<String> rawBlocks = new ArrayList<>();

                    java.util.regex.Pattern xmlPattern = java.util.regex.Pattern.compile(
                        "<certificate[^>]*>(.*?)</certificate>",
                        java.util.regex.Pattern.DOTALL | java.util.regex.Pattern.CASE_INSENSITIVE
                    );
                    java.util.regex.Matcher xmlMatcher = xmlPattern.matcher(content);
                    while (xmlMatcher.find()) {
                        String tagContent = xmlMatcher.group(1);
                        if (tagContent != null) rawBlocks.add(tagContent);
                    }

                    if (rawBlocks.isEmpty()) {
                        java.util.regex.Pattern pemPattern = java.util.regex.Pattern.compile(
                            "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                            java.util.regex.Pattern.DOTALL
                        );
                        java.util.regex.Matcher pemMatcher = pemPattern.matcher(content);
                        while (pemMatcher.find()) {
                            String pemContent = pemMatcher.group(1);
                            if (pemContent != null) rawBlocks.add(pemContent);
                        }
                    }

                    for (String block : rawBlocks) {
                        String cleanBlock = block.replaceAll("<!\\[CDATA\\[", "").replaceAll("\\]\\]>", "");
                        cleanBlock = cleanBlock.replaceAll("-----BEGIN CERTIFICATE-----", "")
                                               .replaceAll("-----END CERTIFICATE-----", "");
                        cleanBlock = cleanBlock.replaceAll("\\s+", "");

                        if (!cleanBlock.isEmpty()) {
                            try {
                                byte[] decoded = android.util.Base64.decode(cleanBlock, android.util.Base64.DEFAULT);
                                try (var bis = new java.io.ByteArrayInputStream(decoded)) {
                                    java.security.cert.Certificate cert = factory.generateCertificate(bis);
                                    if (cert instanceof X509Certificate) {
                                        currentCerts.add((X509Certificate) cert);
                                    }
                                }
                            } catch (Exception ignored) {}
                        }
                    }
                }
            }

            if (currentCerts.isEmpty()) {
                throw new AttestationException(CODE_INVALID_FILE, null);
            }

            // 4. Sort certs by attestation extension
            String attestationOid = "1.3.6.1.4.1.11129.2.1.17";
            X509Certificate leafCert = null;
            for (X509Certificate cert : currentCerts) {
                var criticalOids = cert.getCriticalExtensionOIDs();
                var nonCriticalOids = cert.getNonCriticalExtensionOIDs();
                if ((criticalOids != null && criticalOids.contains(attestationOid)) ||
                    (nonCriticalOids != null && nonCriticalOids.contains(attestationOid))) {
                    leafCert = cert;
                    break;
                }
            }
            if (leafCert != null) {
                currentCerts.remove(leafCert);
                currentCerts.add(0, leafCert);
            }

            // 5. Validate that requested key type matches the loaded leaf certificate
            if (!currentCerts.isEmpty()) {
                String firstCertAlgo = currentCerts.get(0).getPublicKey().getAlgorithm();
                
                if (preferRsa) {
                    // If user wants RSA, but leaf is not RSA
                    if (!firstCertAlgo.equalsIgnoreCase("RSA")) {
                        throw new AttestationException(CODE_ATTEST_RSA_KEY_EC_ONLY, null);
                    }
                } else {
                    // If user wants EC, but leaf is not EC/ECDSA
                    if (!firstCertAlgo.equalsIgnoreCase("EC") && !firstCertAlgo.equalsIgnoreCase("ECDSA")) {
                        throw new AttestationException(CODE_ATTEST_EC_KEY_RSA_ONLY, null);
                    }
                }
            }

            try {
                AttestationData data = AttestationData.parseCertificateChain(currentCerts);
                return Resource.Companion.success(data);
            } catch (Exception originalError) {
                return Resource.Companion.success(KeyboxData.fromCerts(currentCerts));
            }

        } catch (Exception e) {
            var cause = e instanceof AttestationException ? e.getCause() : e;
            Log.w(AppApplication.TAG, "Load attestation error.", cause);

            if (e instanceof AttestationException) {
                return Resource.Companion.error((AttestationException) e, null);
            } else if (e instanceof CertificateException) {
                return Resource.Companion.error(new AttestationException(CODE_CANT_PARSE_CERT, e), null);
            } else {
                return Resource.Companion.error(new AttestationException(CODE_UNKNOWN, e), null);
            }
        }
    }

    public void saveCerts(OutputStream out) throws Exception {
        var certPath = factory.generateCertPath(currentCerts);
        out.write(certPath.getEncoded("PKCS7"));
    }

    public void importKeyBox(boolean useStrongBox, ParcelFileDescriptor pfd) throws Exception {
        var base = useStrongBox ? AppApplication.TAG + "_strongbox" : AppApplication.TAG;
        var alias = base + "_persistent";
        keyStore.importKeyBox(alias, useStrongBox, pfd);
    }

    public boolean canRkp(boolean useStrongBox) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return false;
        }
        try {
            return keyStore.canRemoteProvisioning(useStrongBox);
        } catch (RemoteException e) {
            return false;
        }
    }

    public Resource<RemoteProvisioningData> checkRkp(boolean useStrongBox) {
        currentCerts.clear();
        try {
            var name = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
                    ? keyStore.getRkpHostname() : null;
            var deviceInfo = new DeviceInfo();
            var hw = keyStore.getHardwareInfo(useStrongBox, deviceInfo);
            var diceChain = keyStore.getDiceChain(useStrongBox);
            var info = new RemoteProvisioningData(name, hw, deviceInfo, diceChain);
            try {
                var data = keyStore.checkRemoteProvisioning(useStrongBox);
                info.setCerts(factory.generateCertificates(new ByteArrayInputStream(data)));
            } catch (IllegalStateException e) {
                info.setError(e);
            }
            return Resource.Companion.success(info);
        } catch (Exception e) {
            var cause = e instanceof AttestationException ? e.getCause() : e;
            Log.w(AppApplication.TAG, "Check RKP error.", cause);

            if (e instanceof IllegalStateException) {
                return Resource.Companion.error(new AttestationException(CODE_RKP, e), null);
            } else {
                return Resource.Companion.error(new AttestationException(CODE_UNKNOWN, e), null);
            }
        }
    }

    public void setHostname(String hostname) {
        if (hostname == null) return;
        try {
            keyStore.setRkpHostname(hostname);
        } catch (RemoteException e) {
            Log.w(AppApplication.TAG, "Set RKP hostname error.", e);
        }
    }
}
