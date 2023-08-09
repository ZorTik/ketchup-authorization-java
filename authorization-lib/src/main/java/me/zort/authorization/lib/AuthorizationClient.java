package me.zort.authorization.lib;

import com.google.gson.JsonObject;
import lombok.Getter;
import lombok.Setter;
import me.zort.authorization.lib.model.UserDetails;
import me.zort.authorization.lib.okhttp.OkHttpProcessor;
import me.zort.authorization.lib.strategy.AuthorizationStrategyV1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;
import java.util.function.Supplier;

public final class AuthorizationClient {

    private final HttpProcessor processor;
    @Setter
    private AuthorizationStrategy strategy = new AuthorizationStrategyV1();

    public AuthorizationClient(
            @NotNull String baseUrl,
            @NotNull HttpProcessor httpProcessor
    ) {
        Objects.requireNonNull(baseUrl, "Base URL cannot be null");
        Objects.requireNonNull(httpProcessor, "HTTP processor cannot be null");

        this.processor = httpProcessor;
        httpProcessor.setBaseUrl(baseUrl);
    }

    public Result authorize() { // Administrator authorization
        return authorize((JsonObject) null);
    }

    public Result authorize(@NotNull String username, @NotNull String password) {
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(password, "Password cannot be null");

        JsonObject principal = new JsonObject();
        principal.addProperty("username", username);
        principal.addProperty("password", password);

        return authorize(principal);
    }

    public Result authorize(@Nullable JsonObject principal) {
        return new Result(strategy, principal, strategy.authorize(processor, principal));
    }

    public class Result {
        private final AuthorizationStrategy strategy;
        private final JsonObject principal;
        @Getter
        private AuthorizationStrategy.Token token;

        private Result(AuthorizationStrategy strategy,
                       @Nullable JsonObject principal,
                       @Nullable AuthorizationStrategy.Token token) {
            this.strategy = strategy;
            this.principal = principal;
            this.token = token;
        }

        public void refresh() {
            token = strategy.authorize(processor, principal);
        }

        public UserDetails fetchUserDetails() {
            return authorizedFetch(() -> strategy.fetchUserDetails(processor, token));
        }

        public boolean fetchNodeState(String node) {
            return Boolean.TRUE.equals(authorizedFetch(() -> strategy.fetchNodeState(processor, token, node)));
        }

        private <T> @Nullable T authorizedFetch(Supplier<@Nullable T> supplier) {
            if (!authorized()) {
                throw new IllegalStateException("Not authorized");
            }
            T tResult = supplier.get();
            if (tResult == null && System.currentTimeMillis() >= token.expiresAt()) {
                refresh();
                return authorizedFetch(supplier);
            } else if (tResult == null) {
                throw new IllegalStateException("Token should be valid, but response was not present");
            } else {
                return tResult;
            }
        }

        public boolean authorized() {
            return token != null;
        }
    }

    public static class Builder {
        private String baseUrl = null;
        private HttpProcessor processor = new OkHttpProcessor();

        public @NotNull Builder url(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public @NotNull Builder processor(HttpProcessor processor) {
            this.processor = processor;
            return this;
        }

        public @NotNull AuthorizationClient build() {
            Objects.requireNonNull(baseUrl, "Base URL cannot be null");
            Objects.requireNonNull(processor, "Processor cannot be null");
            return new AuthorizationClient(baseUrl, processor);
        }

    }

}
