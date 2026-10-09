package dev.mitryp.keyauth.crypto;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class Ed25519 {
    private static final String ALGORITHM = "Ed25519";
    private static final byte[] DOMAIN = "keyauth:v1:".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private Ed25519() {
    }

    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair decode(byte[] publicKey, byte[] privateKey) throws InvalidKeySpecException {
        try {
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            return new KeyPair(
                    factory.generatePublic(new X509EncodedKeySpec(publicKey)),
                    factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] signChallenge(PrivateKey key, byte[] nonce) {
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(key);
            signature.update(DOMAIN);
            signature.update(nonce);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static boolean verifyChallenge(byte[] publicKey, byte[] nonce, byte[] sig) {
        try {
            PublicKey key = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKey));
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initVerify(key);
            signature.update(DOMAIN);
            signature.update(nonce);
            return signature.verify(sig);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** Short SHA-256 fingerprint of an encoded public key, for display. */
    public static String fingerprint(byte[] publicKey) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02x", digest[i]));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
