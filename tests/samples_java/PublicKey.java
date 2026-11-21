// Sample: public-key crypto in Java, classical and post-quantum. Never compiled or run.
package samples;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.KEM;

public class PublicKey {
    static final int SMALL = 1024;

    KeyPair weakRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); // expect: RSA
        kpg.initialize(SMALL); // expect: RSA_WEAK
        return kpg.generateKeyPair();
    }

    KeyPair okRsa() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA"); // expect: RSA
        gen.initialize(3072); // expect: RSA
        return gen.generateKeyPair();
    }

    KeyPair rsaSpec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); // expect: RSA
        g.initialize(new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F4)); // expect: RSA_WEAK
        return g.generateKeyPair();
    }

    KeyPair weakDsa() throws Exception {
        KeyPairGenerator d = KeyPairGenerator.getInstance("DSA"); // expect: DSA
        d.initialize(1024); // expect: DSA_WEAK
        return d.generateKeyPair();
    }

    Signature sha1Rsa() throws Exception {
        return Signature.getInstance("SHA1withRSA"); // expect: SHA1, RSA
    }

    Signature ecdsa() throws Exception {
        return Signature.getInstance("SHA256withECDSA"); // expect: SHA256, ECC
    }

    Signature ed25519() throws Exception {
        return Signature.getInstance("Ed25519"); // expect: ED25519
    }

    KeyAgreement x25519() throws Exception {
        return KeyAgreement.getInstance("X25519"); // expect: X25519
    }

    KeyAgreement ecdh() throws Exception {
        return KeyAgreement.getInstance("ECDH"); // expect: ECDH
    }

    KeyPair mlKem() throws Exception {
        return KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair(); // expect: MLKEM
    }

    KEM kem() throws Exception {
        return KEM.getInstance("ML-KEM"); // expect: MLKEM
    }

    Signature mlDsa() throws Exception {
        return Signature.getInstance("ML-DSA-65"); // expect: MLDSA
    }
}
