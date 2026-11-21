// Sample: hashes and MACs in Java. Never compiled or run; the scanner only reads it.
// An "expect" comment at the end of a line lists the algorithm ids that must be found there.
package samples;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;
import com.google.common.hash.Hashing;

public class Hashing {
    private static final String WEAK = "SHA-1";

    byte[] md5(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data); // expect: MD5
    }

    byte[] sha1ViaConstant(byte[] data) throws Exception {
        return MessageDigest.getInstance(WEAK).digest(data); // expect: SHA1
    }

    byte[] good(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data); // expect: SHA256
    }

    byte[] sha3(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA3-512").digest(data); // expect: SHA3
    }

    String commons(byte[] data) {
        return DigestUtils.md5Hex(data); // expect: MD5
    }

    String guava(byte[] data) {
        return Hashing.sha256().hashBytes(data).toString(); // expect: SHA256
    }

    byte[] macSha1(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1"); // expect: HMAC_SHA1
        mac.init(new SecretKeySpec(key, "HmacSHA1")); // expect: HMAC_SHA1
        return mac.doFinal(data);
    }

    byte[] macSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256"); // expect: HMAC
        mac.init(new SecretKeySpec(key, "HmacSHA256")); // expect: HMAC
        return mac.doFinal(data);
    }

    String notCode() {
        // MessageDigest.getInstance("MD5") in a comment is not a finding
        /* neither is Cipher.getInstance("DES") in a block comment */
        return "MessageDigest.getInstance(\"MD5\") inside a string is not one either";
    }
}
