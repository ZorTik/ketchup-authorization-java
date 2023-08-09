package me.zort.authorization.lib;

import com.google.gson.JsonObject;
import me.zort.authorization.lib.model.UserDetails;
import org.jetbrains.annotations.Nullable;

public interface AuthorizationStrategy {

    @Nullable Token authorize(HttpProcessor processor, @Nullable JsonObject principal);
    @Nullable UserDetails fetchUserDetails(HttpProcessor processor, Token token);
    boolean fetchNodeState(HttpProcessor processor, Token token, String node);

    record Token(String token, long expiresAt) { }

}
