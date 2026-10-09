package dev.mitryp.keyauth.network;

import net.minecraft.network.FriendlyByteBuf;

import java.util.function.IntSupplier;

/** Server → client during login: a random nonce the client must sign. */
public final class ChallengeMessage implements IntSupplier {
    private int loginIndex;
    final byte[] nonce;

    public ChallengeMessage(byte[] nonce) {
        this.nonce = nonce;
    }

    static void encode(ChallengeMessage msg, FriendlyByteBuf buf) {
        buf.writeByteArray(msg.nonce);
    }

    static ChallengeMessage decode(FriendlyByteBuf buf) {
        return new ChallengeMessage(buf.readByteArray(64));
    }

    void setLoginIndex(int loginIndex) {
        this.loginIndex = loginIndex;
    }

    @Override
    public int getAsInt() {
        return loginIndex;
    }
}
