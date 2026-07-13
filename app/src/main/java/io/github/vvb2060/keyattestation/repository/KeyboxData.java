package io.github.vvb2060.keyattestation.repository;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import io.github.vvb2060.keyattestation.attestation.CertificateInfo;

public class KeyboxData extends BaseData {

    public static KeyboxData fromCerts(List<X509Certificate> certs) {
        var infoList = new ArrayList<CertificateInfo>(certs.size());
        CertificateInfo.parse(certs, infoList);
        var data = new KeyboxData();
        data.init(infoList);
        return data;
    }
}
