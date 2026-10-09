package dev.mitryp.keyauth.network;

import net.minecraft.network.FriendlyByteBuf;

import java.util.function.IntSupplier;

/** Client → server during login: the client's public key and its signature over the nonce. */
public final class ResponseMessage implements IntSupplier {
    private int loginIndex;
    final byte[] nonce;
    final byte[] publicKey;
    final byte[] signature;

    ResponseMessage(byte[] nonce, byte[] publicKey, byte[] signature) {
        this.nonce = nonce;
        this.publicKey = publicKey;
        this.signature = signature;
    }

    static void encode(ResponseMessage msg, FriendlyByteBuf buf) {
        buf.writeByteArray(msg.nonce);
        buf.writeByteArray(msg.publicKey);
        buf.writeByteArray(msg.signature);
    }

    static ResponseMessage decode(FriendlyByteBuf buf) {
        return new ResponseMessage(buf.readByteArray(64), buf.readByteArray(256), buf.readByteArray(256));
    }

    void setLoginIndex(int loginIndex) {
        this.loginIndex = loginIndex;
    }

    @Override
    public int getAsInt() {
        return loginIndex;
    }
}
