package dev.mitryp.keyauth.network;

import com.mojang.logging.LogUtils;
import dev.mitryp.keyauth.KeyAuthMod;
import dev.mitryp.keyauth.client.ClientIdentity;
import dev.mitryp.keyauth.crypto.Ed25519;
import dev.mitryp.keyauth.server.LoginGate;
import net.minecraft.resources.ResourceLocation;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkRegistry;
import net.minecraftforge.network.simple.SimpleChannel;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;

import java.security.KeyPair;
import java.util.List;

public final class KeyAuthNetwork {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final String PROTOCOL = "1";

    // Exact version match on both sides: a client without the mod is rejected by Forge's channel check.
    private static final SimpleChannel CHANNEL = NetworkRegistry.newSimpleChannel(
            ResourceLocation.fromNamespaceAndPath(KeyAuthMod.MODID, "login"), () -> PROTOCOL, PROTOCOL::equals, PROTOCOL::equals);

    private KeyAuthNetwork() {
    }

    /** @param gate null where logins aren't enforced (clients, integrated servers) */
    public static void register(ClientIdentity identity, LoginGate gate) {
        CHANNEL.messageBuilder(ChallengeMessage.class, 0, NetworkDirection.LOGIN_TO_CLIENT)
                .loginIndex(ChallengeMessage::getAsInt, ChallengeMessage::setLoginIndex)
                .encoder(ChallengeMessage::encode)
                .decoder(ChallengeMessage::decode)
                .buildLoginPacketList(isLocal -> gate == null || isLocal
                        ? List.of()
                        : List.of(Pair.of("KeyAuth challenge", new ChallengeMessage(gate.issueNonce()))))
                .noResponse()
                .consumerNetworkThread((msg, ctx) -> {
                    ResponseMessage response = answer(identity, msg.nonce);
                    response.setLoginIndex(msg.getAsInt());
                    CHANNEL.reply(response, ctx.get());
                    ctx.get().setPacketHandled(true);
                })
                .add();

        CHANNEL.messageBuilder(ResponseMessage.class, 1, NetworkDirection.LOGIN_TO_SERVER)
                .loginIndex(ResponseMessage::getAsInt, ResponseMessage::setLoginIndex)
                .encoder(ResponseMessage::encode)
                .decoder(ResponseMessage::decode)
                .consumerNetworkThread((msg, ctx) -> {
                    if (gate != null) {
                        gate.onResponse(ctx.get().getNetworkManager(), msg.nonce, msg.publicKey, msg.signature);
                    }
                    ctx.get().setPacketHandled(true);
                })
                .add();
    }

    private static ResponseMessage answer(ClientIdentity identity, byte[] nonce) {
        try {
            KeyPair kp = identity.get();
            return new ResponseMessage(nonce, kp.getPublic().getEncoded(), Ed25519.signChallenge(kp.getPrivate(), nonce));
        } catch (Exception e) {
            // An empty answer makes the server disconnect with a reason instead of waiting for the login timeout.
            LOGGER.error("[KeyAuth] Cannot sign login challenge", e);
            return new ResponseMessage(nonce, new byte[0], new byte[0]);
        }
    }
}
