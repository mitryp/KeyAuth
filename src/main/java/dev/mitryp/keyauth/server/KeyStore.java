package dev.mitryp.keyauth.server;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.*;

/** Player name → registered public key, persisted as JSON. */
public final class KeyStore {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final Type MAP_TYPE = new TypeToken<Map<String, Entry>>() {
    }.getType();

    public record Entry(String name, String publicKey, String registeredAt) {
        public byte[] publicKeyBytes() {
            return Base64.getDecoder().decode(publicKey);
        }
    }

    public enum Outcome {VERIFIED, REGISTERED, MISMATCH}

    private final Path file;
    private final Map<String, Entry> entries = new TreeMap<>();

    /** Throws if the file exists but can't be read: starting empty would let anyone re-claim every name. */
    public KeyStore(Path file) {
        this.file = file;
        if (!Files.exists(file)) return;
        try {
            Map<String, Entry> loaded = GSON.fromJson(Files.readString(file, StandardCharsets.UTF_8), MAP_TYPE);
            if (loaded != null) entries.putAll(loaded);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + file, e);
        }
    }

    /** Binds the key on first sight of a name; otherwise compares it to the stored one. */
    public synchronized Outcome checkOrRegister(String name, byte[] publicKey) {
        Entry entry = entries.get(key(name));
        if (entry != null) {
            return Arrays.equals(entry.publicKeyBytes(), publicKey) ? Outcome.VERIFIED : Outcome.MISMATCH;
        }
        entries.put(key(name), new Entry(name, Base64.getEncoder().encodeToString(publicKey), Instant.now().toString()));
        try {
            save();
        } catch (UncheckedIOException e) {
            entries.remove(key(name));
            throw e;
        }
        return Outcome.REGISTERED;
    }

    public synchronized boolean isRegistered(String name) {
        return entries.containsKey(key(name));
    }

    public synchronized boolean remove(String name) {
        if (entries.remove(key(name)) == null) return false;
        save();
        return true;
    }

    public synchronized List<Entry> list() {
        return List.copyOf(entries.values());
    }

    private static String key(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    private void save() {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, GSON.toJson(entries, MAP_TYPE), StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write " + file, e);
        }
    }
}
