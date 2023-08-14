package me.zort.authorization.lib.strategy;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import me.zort.authorization.lib.AuthorizationStrategy;
import me.zort.authorization.lib.HttpProcessor;
import me.zort.authorization.lib.model.UserDetails;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class AuthorizationStrategyV1 implements AuthorizationStrategy {

    @Override
    public @Nullable Token authorize(HttpProcessor processor, @Nullable JsonObject principal) {
        return makeCall(
                processor, null, "/v1/auth/authenticate", "POST", principal,
                tokenMapper(), null
        );
    }

    @Override
    public @Nullable Token refresh(HttpProcessor processor, @NotNull String refreshToken) {
        JsonObject body = new JsonObject();
        body.addProperty("refreshToken", refreshToken);
        return makeCall(
                processor, null, "/v1/auth/refresh", "POST", body,
                tokenMapper(), null
        );
    }

    @Override
    public @Nullable UserDetails fetchUserDetails(HttpProcessor processor, Token token) {
        return doFetchUserDetails(processor, token, true);
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

    @Override
    public boolean verifyToken(HttpProcessor processor, String token) {
        return doFetchUserDetails(processor,
                new Token(token, null, System.currentTimeMillis() + 60000), false
        ) != null;
    }

    private @NotNull Function<JsonObject, Token> tokenMapper() {
        return response -> new Token(
                response.get("token").getAsString(),
                response.get("refreshToken").getAsString(),
                response.get("expiresAt").getAsLong()
        );
    }

    private @Nullable UserDetails doFetchUserDetails(
            HttpProcessor processor, Token token, boolean includePermissions
    ) {
        String path = "/v1/user/details" + (includePermissions ? "?includePermissions=true" : "");
        return makeCall(
                processor, token, path, "GET", null,
                response -> new UserDetails(
                        response.get("permissionsIncluded").getAsBoolean(),
                        response.get("permissions").getAsJsonArray().asList().stream()
                                .map(JsonElement::getAsString)
                                .toList(),
                        parseNullableString(response.get("uuid")),
                        parseNullableString(response.get("primaryGroup")),
                        parseNullableString(response.get("username"))
                ),
                null
        );
    }

    private static String parseNullableString(JsonElement element) {
        return element.isJsonNull() ? null : element.getAsString();
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
