package dev.mitryp.keyauth;

import com.mojang.logging.LogUtils;
import dev.mitryp.keyauth.client.ClientIdentity;
import dev.mitryp.keyauth.network.KeyAuthNetwork;
import dev.mitryp.keyauth.server.KeyAuthCommand;
import dev.mitryp.keyauth.server.KeyStore;
import dev.mitryp.keyauth.server.LoginGate;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.event.RegisterCommandsEvent;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.loading.FMLEnvironment;
import net.minecraftforge.fml.loading.FMLPaths;
import org.slf4j.Logger;

import java.nio.file.Path;

@Mod(KeyAuthMod.MODID)
public class KeyAuthMod {
    public static final String MODID = "keyauth";
    private static final Logger LOGGER = LogUtils.getLogger();

    public KeyAuthMod() {
        Path dir = FMLPaths.CONFIGDIR.get().resolve(MODID);
        ClientIdentity identity = new ClientIdentity(dir.resolve("identity.json"));

        // Only dedicated servers enforce; singleplayer and LAN worlds stay unaffected.
        if (!FMLEnvironment.dist.isDedicatedServer()) {
            KeyAuthNetwork.register(identity, null);
            return;
        }

        KeyStore keys = new KeyStore(dir.resolve("keys.json"));
        LoginGate gate = new LoginGate(keys);
        KeyAuthNetwork.register(identity, gate);

        MinecraftForge.EVENT_BUS.addListener(gate::onNegotiation);
        MinecraftForge.EVENT_BUS.addListener((RegisterCommandsEvent e) -> KeyAuthCommand.register(e.getDispatcher(), keys));
        LOGGER.info("[KeyAuth] Enforcing key authentication ({} keys registered)", keys.list().size());
    }
}
