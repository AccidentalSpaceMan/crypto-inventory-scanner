// Sample: symmetric ciphers in Java. Never compiled or run; the scanner only reads it.
package samples;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Ciphers {
    static final String TRANSFORMATION = "DESede/CBC/PKCS5Padding";

    Cipher defaultMode() throws Exception {
        return Cipher.getInstance("AES"); // expect: AES, ECB
    }

    Cipher ecb() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding"); // expect: AES, ECB
    }

    Cipher cbc() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS5Padding"); // expect: AES, CBC
    }

    Cipher gcm() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding"); // expect: AES_GCM
    }

    Cipher ctr() throws Exception {
        return Cipher.getInstance("AES_256/CTR/NoPadding"); // expect: AES, UNAUTH_MODE
    }

    Cipher des() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding"); // expect: DES, ECB
    }

    Cipher tripleDes() throws Exception {
        return Cipher.getInstance(TRANSFORMATION); // expect: TDES, CBC
    }

    Cipher rc4() throws Exception {
        return Cipher.getInstance("ARCFOUR"); // expect: RC4
    }

    Cipher chacha() throws Exception {
        return Cipher.getInstance("ChaCha20-Poly1305"); // expect: CHACHA20_POLY1305
    }

    Cipher rsaOaep() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // expect: RSA
    }

    Cipher passwordBased() throws Exception {
        return Cipher.getInstance("PBEWithMD5AndDES"); // expect: MD5, DES
    }

    byte[] aesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES"); // expect: AES
        kg.init(256);
        return kg.generateKey().getEncoded();
    }

    byte[] passwordKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // expect: PBKDF2
        return f.generateSecret(new PBEKeySpec(password, salt, 1000, 256)).getEncoded();
    }
}
