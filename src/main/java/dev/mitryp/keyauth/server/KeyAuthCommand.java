package dev.mitryp.keyauth.server;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import dev.mitryp.keyauth.crypto.Ed25519;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.commands.SharedSuggestionProvider;
import net.minecraft.network.chat.Component;

public final class KeyAuthCommand {
    private KeyAuthCommand() {
    }

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher, KeyStore keys) {
        dispatcher.register(Commands.literal("keyauth")
                .requires(src -> src.hasPermission(3))
                .then(Commands.literal("list").executes(ctx -> {
                    var entries = keys.list();
                    if (entries.isEmpty()) {
                        ctx.getSource().sendSuccess(() -> Component.literal("No keys registered."), false);
                    }
                    for (KeyStore.Entry e : entries) {
                        String line = e.name() + "  " + Ed25519.fingerprint(e.publicKeyBytes()) + "  " + e.registeredAt();
                        ctx.getSource().sendSuccess(() -> Component.literal(line), false);
                    }
                    return entries.size();
                }))
                .then(Commands.literal("reset")
                        .then(Commands.argument("player", StringArgumentType.word())
                                .suggests((ctx, builder) -> SharedSuggestionProvider.suggest(
                                        keys.list().stream().map(KeyStore.Entry::name), builder))
                                .executes(ctx -> {
                                    String name = StringArgumentType.getString(ctx, "player");
                                    if (!keys.remove(name)) {
                                        ctx.getSource().sendFailure(Component.literal(name + " has no registered key."));
                                        return 0;
                                    }
                                    ctx.getSource().sendSuccess(() -> Component.literal(
                                            "Reset key for " + name + ". Their next join registers a new one."), true);
                                    return 1;
                                }))));
    }
}
