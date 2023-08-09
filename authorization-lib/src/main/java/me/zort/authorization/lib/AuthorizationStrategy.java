package me.zort.authorization.lib;

import com.google.gson.JsonObject;
import me.zort.authorization.lib.model.UserDetails;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public interface AuthorizationStrategy {

    @Nullable Token authorize(HttpProcessor processor, @Nullable JsonObject principal);
    @Nullable Token refresh(HttpProcessor processor, @NotNull String refreshToken);
    @Nullable UserDetails fetchUserDetails(HttpProcessor processor, Token token);
    boolean fetchNodeState(HttpProcessor processor, Token token, String node);
    boolean verifyToken(HttpProcessor processor, String token);

    record Token(String token, String refreshToken, long expiresAt) { }

}
