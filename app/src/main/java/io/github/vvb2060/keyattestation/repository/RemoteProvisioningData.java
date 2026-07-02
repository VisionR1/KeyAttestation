package io.github.vvb2060.keyattestation.repository;

import android.hardware.security.keymint.DeviceInfo;
import android.hardware.security.keymint.RpcHardwareInfo;
import android.util.ArrayMap;
import android.util.Log;
import android.util.Pair;

import com.google.common.io.BaseEncoding;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.attestation.CertificateInfo;

public class RemoteProvisioningData extends BaseData {
    private static final int SUB = 2;
    private static final int CONFIG_DESCRIPTOR = -4670548;
    private static final int MODE = -4670551;
    private static final int COMPONENT_NAME = -70002;
    private static final int COMPONENT_VERSION = -70003;
    private static final int SECURITY_VERSION = -70005;

    private final String rkpHostname;
    private final RpcHardwareInfo hardwareInfo;
    private final java.util.Map<String, String> deviceInfo = new ArrayMap<>();
    private final List<Pair<String, String>> diceChain = new ArrayList<>();
    private Throwable error;

    public RemoteProvisioningData(String rkpHostname, RpcHardwareInfo hardwareInfo,
                                  DeviceInfo deviceInfoData, byte[] diceChainData) throws CborException {
        this.rkpHostname = rkpHostname;
        this.hardwareInfo = hardwareInfo;
        var deviceInfo = (Map) CborDecoder.decode(deviceInfoData.deviceInfo).get(0);
        for (var key : deviceInfo.getKeys()) {
            var value = deviceInfo.get(key);
            String valueString;
            if (value instanceof ByteString byteString) {
                valueString = BaseEncoding.base16().lowerCase().encode(byteString.getBytes());
            } else {
                valueString = value.toString();
            }
            this.deviceInfo.put(key.toString(), valueString);
        }
        if (diceChainData != null) {
            try {
                parseDiceChain(diceChainData);
            } catch (Exception e) {
                Log.w(AppApplication.TAG, "Parse dice chain error.", e);
                diceChain.clear();
            }
        }
    }

    private void parseDiceChain(byte[] data) throws CborException {
        var entries = ((Array) CborDecoder.decode(data).get(0)).getDataItems();
        for (var i = 1; i < entries.size(); i++) {
            var payloadData = (ByteString) ((Array) entries.get(i)).getDataItems().get(2);
            var payload = (Map) CborDecoder.decode(payloadData.getBytes()).get(0);
            String name = null;
            var details = "";
            var mode = payload.get(new NegativeInteger(MODE));
            if (mode instanceof ByteString bytes && bytes.getBytes().length == 1) {
                details = "mode: " + diceModeToString(bytes.getBytes()[0]);
            } else if (mode instanceof Number number) {
                details = "mode: " + diceModeToString(number.getValue().intValue());
            }
            if (payload.get(new NegativeInteger(CONFIG_DESCRIPTOR)) instanceof ByteString config) {
                var descriptor = (Map) CborDecoder.decode(config.getBytes()).get(0);
                if (descriptor.get(new NegativeInteger(COMPONENT_NAME)) instanceof UnicodeString s) {
                    name = s.getString();
                }
                details = appendItem(details, "securityVersion: ", descriptor.get(new NegativeInteger(SECURITY_VERSION)));
                details = appendItem(details, "componentVersion: ", descriptor.get(new NegativeInteger(COMPONENT_VERSION)));
            }
            if (name == null && payload.get(new UnsignedInteger(SUB)) instanceof UnicodeString s) {
                name = s.getString();
            }
            diceChain.add(new Pair<>(name != null ? name : "layer " + i, details));
        }
    }

    private static String appendItem(String details, String label, DataItem value) {
        if (value == null) return details;
        if (details.isEmpty()) return label + value;
        return details + '\n' + label + value;
    }

    private static String diceModeToString(int mode) {
        return switch (mode) {
            case 1 -> "normal";
            case 2 -> "debug";
            case 3 -> "recovery";
            default -> "not configured";
        };
    }

    @SuppressWarnings("unchecked")
    public void setCerts(Collection<? extends Certificate> data) {
        var infoList = new ArrayList<CertificateInfo>(data.size());
        CertificateInfo.parse((List<X509Certificate>) data, infoList);
        init(infoList);
    }

    public void setError(Throwable error) {
        this.error = error;
        init(List.of());
    }

    public String getRkpHostname() {
        return rkpHostname;
    }

    public RpcHardwareInfo getHardwareInfo() {
        return hardwareInfo;
    }

    public java.util.Map<String, String> getDeviceInfo() {
        return deviceInfo;
    }

    public List<Pair<String, String>> getDiceChain() {
        return diceChain;
    }

    public Throwable getError() {
        return error;
    }
}
