package org.example;


import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.net.HttpURLConnection;

import static org.junit.Assert.assertEquals;

public class AppTest {
    public static final String STORE_TYPE = "PKCS12";
    private final String trustStorePath = System.getProperty("java.io.tmpdir") + "test.truststore";
    private final String keyStorePath = System.getProperty("java.io.tmpdir") + "test.keystore";
    private final char[] trustStorePassword = "abcd1234".toCharArray();
    private final char[] keyStorePassword = "qwerty1234".toCharArray();

    private void setStoreDetails(String STORE_TYPE) {
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", String.valueOf(trustStorePassword));
        System.setProperty("javax.net.ssl.trustStoreType", STORE_TYPE);
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", String.valueOf(keyStorePassword));
        System.setProperty("javax.net.ssl.keyStoreType", STORE_TYPE);
    }

    @After
    public void cleanUp() throws InterruptedException {
        new File(trustStorePath).delete();
        new File(keyStorePath).delete();
        /*
         * sometimes windows takes long to delete a file
         * so adding a delay before next test case begins,
         * else a better approach will be to append date-timestamp to file name
         * which will then create unique truststore and keystore files per test case
         * */
        Thread.sleep(2000);
    }

    @Test
    @Ignore
    public void should_connect_to_self_signed_cert_url_and_return_200() throws Exception {
        new TrustStoreHandler(trustStorePath, trustStorePassword, STORE_TYPE).createStoreWith("badssl/selfSigned.crt");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", String.valueOf(trustStorePassword));
        System.setProperty("javax.net.ssl.trustStoreType", STORE_TYPE);
        assertEquals(HttpURLConnection.HTTP_OK, new App().makeHttpCallTo("https://self-signed.badssl.com/"));
    }

    @Test
    @Ignore
    public void should_connect_to_ssl_client_cert_secured_url_usingP12_and_return_200() throws Exception {
        new TrustStoreHandler(trustStorePath, trustStorePassword, STORE_TYPE).createStoreWith("badssl/selfSigned.crt", "badssl/ISRGRootX1.crt", "badssl/R3.crt");
        new KeyStoreHandler(keyStorePath, keyStorePassword, STORE_TYPE).addP12StoreToKeystore("badssl/badssl.com-client.p12", "badssl.com".toCharArray());
        Thread.sleep(10000);
        setStoreDetails(STORE_TYPE);

        assertEquals(HttpURLConnection.HTTP_OK, new App().makeHttpCallTo("https://client.badssl.com/"));
    }

    @Test
    @Ignore
    public void should_connect_to_ssl_client_cert_secured_url_using_unencrypted_DER_Key_and_return_200() throws Exception {
        new TrustStoreHandler(trustStorePath, trustStorePassword, STORE_TYPE).createStoreWith("badssl/selfSigned.crt", "badssl/R3.crt", "badssl/ISRGRootX1.crt");
        new KeyStoreHandler(keyStorePath, keyStorePassword, STORE_TYPE).addCertAndUnEncryptedDERKey("badssl/cert.pem", "badssl/pkcs8_der.key");
        setStoreDetails(STORE_TYPE);

        assertEquals(HttpURLConnection.HTTP_OK, new App().makeHttpCallTo("https://client.badssl.com/"));
    }

    @Test
    @Ignore
    public void should_connect_to_ssl_client_cert_secured_url_using_unencrypted_PEM_Key_and_return_200() throws Exception {
        new TrustStoreHandler(trustStorePath, trustStorePassword, STORE_TYPE).createStoreWith("badssl/selfSigned.crt", "badssl/R3.crt", "badssl/ISRGRootX1.crt");
        new KeyStoreHandler(keyStorePath, keyStorePassword, STORE_TYPE).addCertAndUnEncryptedPemKey("badssl/cert.pem", "badssl/pkcs8_pem.key");
        setStoreDetails(STORE_TYPE);

        assertEquals(HttpURLConnection.HTTP_OK, new App().makeHttpCallTo("https://client.badssl.com/"));
    }

    @Test
    @Ignore
    public void should_connect_to_ssl_client_cert_secured_url_with_3DES_EncryptedKey_and_return_200() throws Exception {
        new TrustStoreHandler(trustStorePath, trustStorePassword, STORE_TYPE).createStoreWith("badssl/selfSigned.crt", "badssl/R3.crt", "badssl/ISRGRootX1.crt");
        new KeyStoreHandler(keyStorePath, keyStorePassword, STORE_TYPE).addCertAnd3DESEncryptedPemKey("badssl/cert.pem", "badssl/pkcs8_des.key", "badssl.com".toCharArray());
        setStoreDetails(STORE_TYPE);

        assertEquals(HttpURLConnection.HTTP_OK, new App().makeHttpCallTo("https://client.badssl.com/"));
    }

    @Test
    @Ignore
    public void should_connect_to_ssl_client_cert_secured_url_with_AES_EncryptedKey_and_return_200() throws Exception {
        new TrustStoreHandler(trustStorePath, trustStorePassword, STORE_TYPE).createStoreWith("badssl/selfSigned.crt", "badssl/R3.crt", "badssl/ISRGRootX1.crt");
        new KeyStoreHandler(keyStorePath, keyStorePassword, STORE_TYPE).addCertAndAESEncryptedPemKey("badssl/cert.pem", "badssl/pkcs8_aes.key", "badssl.com".toCharArray());
        setStoreDetails(STORE_TYPE);

        assertEquals(HttpURLConnection.HTTP_OK, new App().makeHttpCallTo("https://client.badssl.com/"));
    }

    @Test
    @Ignore
    public void should_connect_to_ssl_client_cert_secured_url_using_pemFile_and_return_200() throws Exception {
        new TrustStoreHandler(trustStorePath, trustStorePassword, STORE_TYPE).createStoreWith("badssl/selfSigned.crt", "badssl/R3.crt", "badssl/ISRGRootX1.crt");
        new KeyStoreHandler(keyStorePath, keyStorePassword, STORE_TYPE).addCertAndKeyFromPemFile("badssl/badssl.com-client.pem", "badssl.com".toCharArray());
        setStoreDetails(STORE_TYPE);

        assertEquals(HttpURLConnection.HTTP_OK, new App().makeHttpCallTo("https://client.badssl.com/"));
    }

}
