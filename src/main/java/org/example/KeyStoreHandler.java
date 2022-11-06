package org.example;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class KeyStoreHandler {
    private final String storePath;
    private final char[] storePassword;
    private final String storeInstance;


    public KeyStoreHandler(String storePath, char[] storePassword, String storeInstance) {
        this.storePath = storePath;
        this.storePassword = storePassword;
        this.storeInstance = storeInstance;
    }

    public void addP12StoreToKeystore(String p12FilePath, char[] p12FilePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(storeInstance);
        keyStore.load(null, null);

        try (InputStream inputStream = new FileInputStream(p12FilePath)) {
            KeyStore p12Store = KeyStore.getInstance("PKCS12");
            p12Store.load(inputStream, p12FilePassword);

            for (String alias : Collections.list(p12Store.aliases())) {
                if (p12Store.isKeyEntry(alias)) {
                    Key key = p12Store.getKey(alias, p12FilePassword);
                    Certificate[] certificateChain = p12Store.getCertificateChain(alias);
                    keyStore.setKeyEntry(alias, key, storePassword, certificateChain);
                }
            }
        }

        try (FileOutputStream fileOutputStream = new FileOutputStream(storePath)) {
            keyStore.store(fileOutputStream, storePassword);
        }
    }

    public void addCertAndUnEncryptedDERKey(String certPath, String keyPath) throws Exception {
        try (FileInputStream fileInputStream = new FileInputStream(certPath); BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream)) {
            Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(bufferedInputStream);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(keyPath)));
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec);

            KeyStore keyStore = KeyStore.getInstance(storeInstance);
            keyStore.load(null, null);
            keyStore.setKeyEntry("cert", privateKey, storePassword, new Certificate[]{certificate});

            try (FileOutputStream fileOutputStream = new FileOutputStream(storePath)) {
                keyStore.store(fileOutputStream, storePassword);
            }
        }
    }

    public void addCertAndUnEncryptedPemKey(String certPath, String keyPath) throws Exception {
        try (FileInputStream fileInputStream = new FileInputStream(certPath); BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream)) {
            Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(bufferedInputStream);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(pemToDer(keyPath));
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec);

            KeyStore keyStore = KeyStore.getInstance(storeInstance);
            keyStore.load(null, null);
            keyStore.setKeyEntry("cert", privateKey, storePassword, new Certificate[]{certificate});

            try (FileOutputStream fileOutputStream = new FileOutputStream(storePath)) {
                keyStore.store(fileOutputStream, storePassword);
            }
        }
    }

    private byte[] pemToDer(String filePath) throws IOException {
        List<String> pemFileData = Files.readAllLines(Paths.get(filePath), StandardCharsets.UTF_8);
        pemFileData.remove(0);
        pemFileData.remove(pemFileData.size() - 1);

        return Base64.getDecoder().decode(String.join("", pemFileData));
    }

    public void addCertAnd3DESEncryptedPemKey(String certPath, String keyPath, char[] keyPassword) throws Exception {
        try (FileInputStream fileInputStream = new FileInputStream(certPath); BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream)) {
            Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(bufferedInputStream);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(keyPassword);
            EncryptedPrivateKeyInfo privateKeyInfo = new EncryptedPrivateKeyInfo(pemToDer(keyPath));

            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(privateKeyInfo.getAlgName());
            Key key = secretKeyFactory.generateSecret(pbeKeySpec);

            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeyInfo.getKeySpec(key));

            KeyStore keyStore = KeyStore.getInstance(storeInstance);
            keyStore.load(null, null);
            keyStore.setKeyEntry("cert", privateKey, storePassword, new Certificate[]{certificate});

            try (FileOutputStream fileOutputStream = new FileOutputStream(storePath)) {
                keyStore.store(fileOutputStream, storePassword);
            }
        }
    }

    public void addCertAndAESEncryptedPemKey(String certPath, String keyPath, char[] keyPassword) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        try (FileInputStream fileInputStream = new FileInputStream(certPath); BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream)) {
            Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(bufferedInputStream);

            PEMParser pemParser = new PEMParser(new FileReader(keyPath));

            PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();

            InputDecryptorProvider inputDecryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(keyPassword);

            PrivateKey privateKey = new JcaPEMKeyConverter().getPrivateKey(encryptedPrivateKeyInfo.decryptPrivateKeyInfo(inputDecryptorProvider));

            KeyStore keyStore = KeyStore.getInstance(storeInstance);
            keyStore.load(null, null);
            keyStore.setKeyEntry("cert", privateKey, storePassword, new Certificate[]{certificate});

            try (FileOutputStream fileOutputStream = new FileOutputStream(storePath)) {
                keyStore.store(fileOutputStream, storePassword);
            }
        }
    }

    public void addCertAndKeyFromPemFile(String pemFilePath, char[] keyPassword) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        PEMParser pemParser = new PEMParser(new FileReader(pemFilePath));

        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider());
        X509Certificate certificate = jcaX509CertificateConverter.getCertificate((X509CertificateHolder) pemParser.readObject());


        PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();
        InputDecryptorProvider inputDecryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(keyPassword);
        PrivateKey privateKey = new JcaPEMKeyConverter().getPrivateKey(encryptedPrivateKeyInfo.decryptPrivateKeyInfo(inputDecryptorProvider));


        KeyStore keyStore = KeyStore.getInstance(storeInstance);
        keyStore.load(null, null);
        keyStore.setKeyEntry("cert", privateKey, storePassword, new Certificate[]{certificate});

        try (FileOutputStream fileOutputStream = new FileOutputStream(storePath)) {
            keyStore.store(fileOutputStream, storePassword);
        }
    }
}
