package org.example;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class TrustStoreHandler {
    private final String storePath;
    private final char[] storePassword;
    private final String storeInstance;


    public TrustStoreHandler(String storePath, char[] storePassword, String storeInstance) {
        this.storePath = storePath;
        this.storePassword = storePassword;
        this.storeInstance = storeInstance;
    }

    public void createStoreWith(String... certs) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(storeInstance);
        trustStore.load(null, null);

        for (String cert : certs) {
            try (FileInputStream fileInputStream = new FileInputStream(cert); BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream)) {
                while (bufferedInputStream.available() > 0) {
                    System.out.println("adding " + cert + " to " + storePath);
                    Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(bufferedInputStream);
                    trustStore.setCertificateEntry(cert, certificate);
                }
            }
        }

        try (FileOutputStream fileOutputStream = new FileOutputStream(storePath)) {
            trustStore.store(fileOutputStream, storePassword);
        }
    }
}
