### Supporting code for YouTube video [Java programmatically create keystore + truststore and import certificates into it](https://youtu.be/hjchHVw-rn8)

### Download certificates from

* Base site [https://badssl.com/](https://badssl.com/)

* Download the self-signed certificate from [https://self-signed.badssl.com/](https://self-signed.badssl.com/)

* The client certificate secured url is [https://client.badssl.com/](https://client.badssl.com/)

* Download the client certificate .p12 and .pem files from [https://badssl.com/download/](https://badssl.com/download/)


### OpenSSL Commands

* GitBash in Windows requires winpty to capture user input

```
winpty openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt -in client.key -out pkcs8_der.key

winpty openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in client.key -out pkcs8_pem.key

winpty openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES -inform PEM -outform PEM -in client.key -out pkcs8_des.key

winpty openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA512 -inform PEM -outform PEM -in client.key -out pkcs8_aes.key
```

* Linux or WSL
```bash
openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt -in client.key -out pkcs8.key

openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in client.key -out pkcs8.key

openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES -inform PEM -outform PEM -in key.pem -out pkcs8_des.key

openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA512 -inform PEM -outform PEM -in key.pem -out pkcs8_aes.key
```
