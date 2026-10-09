package dev.mitryp.keyauth.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import dev.mitryp.keyauth.crypto.Ed25519;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;

/** The player's key pair, generated on first use and kept in the game's config dir. */
public final class ClientIdentity {
    private static final Gson GSON = new Gson();

    private final Path file;
    private KeyPair keyPair;

    public ClientIdentity(Path file) {
        this.file = file;
    }

    public synchronized KeyPair get() throws IOException {
        if (keyPair == null) keyPair = Files.exists(file) ? load() : create();
        return keyPair;
    }

    private KeyPair load() throws IOException {
        JsonObject json = GSON.fromJson(Files.readString(file, StandardCharsets.UTF_8), JsonObject.class);
        try {
            return Ed25519.decode(
                    Base64.getDecoder().decode(json.get("public").getAsString()),
                    Base64.getDecoder().decode(json.get("private").getAsString()));
        } catch (Exception e) {
            throw new IOException("Corrupt identity file " + file, e);
        }
    }

    private KeyPair create() throws IOException {
        KeyPair kp = Ed25519.generate();
        JsonObject json = new JsonObject();
        json.addProperty("public", Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
        json.addProperty("private", Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));

        Files.createDirectories(file.getParent());
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.writeString(tmp, GSON.toJson(json), StandardCharsets.UTF_8);
        Files.move(tmp, file);
        return kp;
    }
}
