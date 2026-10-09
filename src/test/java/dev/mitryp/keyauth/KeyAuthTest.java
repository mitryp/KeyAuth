package dev.mitryp.keyauth;

import dev.mitryp.keyauth.client.ClientIdentity;
import dev.mitryp.keyauth.crypto.Ed25519;
import dev.mitryp.keyauth.server.KeyStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class KeyAuthTest {
    @TempDir
    Path dir;

    private static byte[] nonce(int seed) {
        byte[] n = new byte[32];
        n[0] = (byte) seed;
        return n;
    }

    @Test
    void signatureVerifiesOnlyForSignedNonceAndKey() {
        KeyPair kp = Ed25519.generate();
        KeyPair other = Ed25519.generate();
        byte[] sig = Ed25519.signChallenge(kp.getPrivate(), nonce(1));
        byte[] pub = kp.getPublic().getEncoded();

        assertTrue(Ed25519.verifyChallenge(pub, nonce(1), sig));
        assertFalse(Ed25519.verifyChallenge(pub, nonce(2), sig));
        assertFalse(Ed25519.verifyChallenge(other.getPublic().getEncoded(), nonce(1), sig));
    }

    @Test
    void malformedInputIsRejectedNotThrown() {
        assertFalse(Ed25519.verifyChallenge(new byte[0], nonce(1), new byte[0]));
        assertFalse(Ed25519.verifyChallenge(new byte[]{1, 2, 3}, nonce(1), new byte[64]));
    }

    @Test
    void firstKeyIsBoundAndOthersMismatch() {
        KeyStore store = new KeyStore(dir.resolve("keys.json"));
        byte[] a = Ed25519.generate().getPublic().getEncoded();
        byte[] b = Ed25519.generate().getPublic().getEncoded();

        assertEquals(KeyStore.Outcome.REGISTERED, store.checkOrRegister("Steve", a));
        assertEquals(KeyStore.Outcome.VERIFIED, store.checkOrRegister("Steve", a));
        assertEquals(KeyStore.Outcome.MISMATCH, store.checkOrRegister("Steve", b));
        assertEquals(KeyStore.Outcome.MISMATCH, store.checkOrRegister("steve", b));
    }

    @Test
    void bindingsPersistAndResetWorks() {
        Path file = dir.resolve("keys.json");
        byte[] a = Ed25519.generate().getPublic().getEncoded();
        byte[] b = Ed25519.generate().getPublic().getEncoded();
        new KeyStore(file).checkOrRegister("Steve", a);

        KeyStore reloaded = new KeyStore(file);
        assertEquals(KeyStore.Outcome.MISMATCH, reloaded.checkOrRegister("Steve", b));
        assertTrue(reloaded.remove("STEVE"));
        assertEquals(KeyStore.Outcome.REGISTERED, reloaded.checkOrRegister("Steve", b));
        assertEquals(KeyStore.Outcome.VERIFIED, new KeyStore(file).checkOrRegister("Steve", b));
    }

    @Test
    void unreadableStoreFailsClosed() throws Exception {
        Path file = dir.resolve("keys.json");
        Files.createDirectory(file);
        assertThrows(UncheckedIOException.class, () -> new KeyStore(file));
    }

    @Test
    void identityIsGeneratedOnceAndReloaded() throws Exception {
        Path file = dir.resolve("keyauth/identity.json");
        KeyPair first = new ClientIdentity(file).get();
        KeyPair again = new ClientIdentity(file).get();

        assertArrayEquals(first.getPublic().getEncoded(), again.getPublic().getEncoded());
        byte[] sig = Ed25519.signChallenge(again.getPrivate(), nonce(7));
        assertTrue(Ed25519.verifyChallenge(first.getPublic().getEncoded(), nonce(7), sig));
    }
}
