package dev.mitryp.keyauth.server;

import com.mojang.logging.LogUtils;
import dev.mitryp.keyauth.crypto.Ed25519;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import net.minecraftforge.event.entity.player.PlayerNegotiationEvent;
import net.minecraftforge.server.ServerLifecycleHooks;
import org.slf4j.Logger;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds each login until the client proves it owns the key bound to its name.
 *
 * <p>The gate is a future enqueued on {@link PlayerNegotiationEvent}, not the login-packet ack: the
 * client picks the index it acks, so it could ack the challenge through another channel and skip it.
 * The future completes only on a valid signature; failures disconnect and leave it pending.
 */
public final class LoginGate {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final long NONCE_TTL_MS = 60_000;

    private record Pending(String name, CompletableFuture<Void> done) {
    }

    private final KeyStore keys;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Long> issuedNonces = new ConcurrentHashMap<>();
    private final Map<Connection, Pending> pending = Collections.synchronizedMap(new WeakHashMap<>());

    public LoginGate(KeyStore keys) {
        this.keys = keys;
    }

    public byte[] issueNonce() {
        long now = System.currentTimeMillis();
        issuedNonces.values().removeIf(issuedAt -> now - issuedAt > NONCE_TTL_MS);

        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        issuedNonces.put(Base64.getEncoder().encodeToString(nonce), now);
        return nonce;
    }

    public void onNegotiation(PlayerNegotiationEvent event) {
        if (event.getConnection().isMemoryConnection()) return;

        CompletableFuture<Void> done = new CompletableFuture<>();
        pending.put(event.getConnection(), new Pending(event.getProfile().getName(), done));
        event.enqueueWork(done);
    }

    public void onResponse(Connection connection, byte[] nonce, byte[] publicKey, byte[] signature) {
        Pending p = pending.remove(connection);
        if (p == null) {
            reject(connection, "?", "unexpected response");
            return;
        }

        Long issuedAt = issuedNonces.remove(Base64.getEncoder().encodeToString(nonce));
        if (issuedAt == null || System.currentTimeMillis() - issuedAt > NONCE_TTL_MS) {
            reject(connection, p.name(), "unknown or expired nonce");
            return;
        }
        if (!Ed25519.verifyChallenge(publicKey, nonce, signature)) {
            reject(connection, p.name(), "bad signature");
            return;
        }

        if (!keys.isRegistered(p.name()) && !mayRegister(p.name())) {
            reject(connection, p.name(), "not whitelisted, refusing to register a key", "You are not whitelisted on this server.");
            return;
        }

        KeyStore.Outcome outcome;
        try {
            outcome = keys.checkOrRegister(p.name(), publicKey);
        } catch (RuntimeException e) {
            LOGGER.error("[KeyAuth] Failed to store key for {}", p.name(), e);
            reject(connection, p.name(), "key store error");
            return;
        }

        switch (outcome) {
            case MISMATCH -> reject(connection, p.name(), "key mismatch",
                    "This name is registered to another device. Ask the server admin to reset your key.");
            case REGISTERED -> {
                LOGGER.info("[KeyAuth] Registered key {} for {}", Ed25519.fingerprint(publicKey), p.name());
                p.done().complete(null);
            }
            case VERIFIED -> p.done().complete(null);
        }
    }

    private static boolean mayRegister(String name) {
        MinecraftServer server = ServerLifecycleHooks.getCurrentServer();
        if (server == null) return false;
        var players = server.getPlayerList();
        if (!players.isUsingWhitelist()) return true;
        return Arrays.stream(players.getWhiteList().getUserList()).anyMatch(name::equalsIgnoreCase);
    }

    private static void reject(Connection connection, String name, String reason) {
        reject(connection, name, reason, "Authentication failed (" + reason + ").");
    }

    private static void reject(Connection connection, String name, String reason, String playerMessage) {
        LOGGER.warn("[KeyAuth] Rejected {} from {}: {}", name, connection.getRemoteAddress(), reason);
        Component message = Component.literal("KeyAuth: " + playerMessage);
        if (connection.getPacketListener() instanceof ServerLoginPacketListenerImpl login) {
            login.disconnect(message);
        } else {
            connection.disconnect(message);
        }
    }
}
