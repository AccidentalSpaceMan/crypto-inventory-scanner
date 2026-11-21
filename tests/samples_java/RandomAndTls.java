// Sample: randomness and TLS settings in Java. Never compiled or run.
package samples;

import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class RandomAndTls {
    private final Random rng = new Random();
    private final SecureRandom secure = new SecureRandom(); // expect: CSPRNG

    int rollDice() {
        return rng.nextInt(6) + 1;
    }

    String generateToken() {
        return Long.toHexString(rng.nextLong()); // expect: INSECURE_RANDOM
    }

    int resetPin() {
        return ThreadLocalRandom.current().nextInt(10000); // expect: INSECURE_RANDOM
    }

    double jitter() {
        return Math.random();
    }

    byte[] sessionKey() {
        byte[] key = new byte[32];
        secure.nextBytes(key);
        return key;
    }

    SSLContext oldTls() throws Exception {
        return SSLContext.getInstance("TLSv1"); // expect: TLS_OLD
    }

    SSLContext modernTls() throws Exception {
        return SSLContext.getInstance("TLSv1.3"); // expect: TLS_MODERN
    }

    void protocols(SSLSocket socket) {
        socket.setEnabledProtocols(new String[] {"TLSv1.1", "TLSv1.2"}); // expect: TLS_OLD, TLS_MODERN
    }

    void trustEveryone() {
        HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true); // expect: TLS_NO_VERIFY
        new HttpsURLConnection(null).setHostnameVerifier((h, s) -> true); // expect: TLS_NO_VERIFY
    }

    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) { } // expect: TLS_NO_VERIFY
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
