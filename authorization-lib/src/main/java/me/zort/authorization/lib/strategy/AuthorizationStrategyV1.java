package me.zort.authorization.lib.strategy;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import me.zort.authorization.lib.AuthorizationStrategy;
import me.zort.authorization.lib.HttpProcessor;
import me.zort.authorization.lib.model.UserDetails;
import org.jetbrains.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class AuthorizationStrategyV1 implements AuthorizationStrategy {

    @Override
    public @Nullable Token authorize(HttpProcessor processor, @Nullable JsonObject principal) {
        return makeCall(
                processor, null, "/v1/auth/authenticate", "POST", principal,
                response -> new Token(
                        response.get("token").getAsString(),
                        response.get("expiresAt").getAsLong()
                ),
                null
        );
    }

    @Override
    public @Nullable UserDetails fetchUserDetails(HttpProcessor processor, Token token) {
        return makeCall(
                processor, token, "/v1/user/details?includePermissions=true", "GET", null,
                response -> new UserDetails(
                        response.get("permissionsIncluded").getAsBoolean(),
                        response.get("permissions").getAsJsonArray().asList().stream()
                                .map(JsonElement::getAsString)
                                .toList(),
                        response.get("uuid").getAsString(),
                        response.get("primaryGroup").getAsString(),
                        response.get("username").getAsString()
                ),
                null
        );
    }

    @Override
    public boolean fetchNodeState(HttpProcessor processor, Token token, String node) {
        JsonObject body = new JsonObject();
        body.addProperty("node", node);
        return makeCall(
                processor, token, "/v1/user/checknode", "POST", body,
                response -> response.get("state").getAsBoolean(),
                false
        );
    }

    private static <T> T makeCall(
            HttpProcessor processor,
            Token token,
            String path,
            String method,
            JsonObject body,
            Function<JsonObject, T> mapper,
            T defaultValue
    ) {
        try {
            Map<String, String> headers = new HashMap<>();
            if (token != null) {
                headers.put("Authorization", "Bearer " + token.token());
            }
            JsonObject response = processor.perform(path, method, headers, body);
            return mapper.apply(response);
        } catch (HttpProcessor.BadStatusException e) {
            return defaultValue;
        }
    }
}
