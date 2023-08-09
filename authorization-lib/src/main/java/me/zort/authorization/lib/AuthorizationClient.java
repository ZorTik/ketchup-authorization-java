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

/**
 * Authorization client that can be used to authorize users and fetch their details
 * using the ketchup-authorization-server (JWT).
 *
 * <p>Initialization example:
 * <pre>
 *     AuthorizationClient client = new AuthorizationClient.Builder()
 *          .url("Authorization server url")
 *          .build();
 * </pre>
 *
 * @author ZorTik
 */
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

    public @NotNull Result authorize() { // Administrator authorization
        return authorize((JsonObject) null);
    }

    public @NotNull Result authorize(@NotNull String username, @NotNull String password) {
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(password, "Password cannot be null");

        JsonObject principal = new JsonObject();
        principal.addProperty("username", username);
        principal.addProperty("password", password);

        return authorize(principal);
    }

    public @NotNull Result authorize(@Nullable JsonObject principal) {
        return new Result(strategy, principal, strategy.authorize(processor, principal));
    }

    public @NotNull Result verify(@NotNull String token) {
        return verify(token, null);
    }

    public @NotNull Result verify(@NotNull String token, @Nullable String refreshToken) {
        Objects.requireNonNull(token, "Token cannot be null");

        // Token wrapper without expiration that can't be refreshed
        AuthorizationStrategy.Token tokenInstance = new AuthorizationStrategy.Token(token, refreshToken, -1);
        if (strategy.verifyToken(processor, token)) {
            return new Result(strategy, null, tokenInstance);
        } else {
            return new Result(strategy, null, null);
        }
    }

    public final class Result {
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

        /**
         * Tries to refresh current session.
         * Please note that you can use this method only if you provided either
         * principal or refresh token when initializing this session. Otherwise,
         * this method will throw an exception.
         */
        public void refresh() {
            boolean refreshed = false;
            if (token.refreshToken() != null) {
                token = strategy.refresh(processor, token.refreshToken());
                refreshed = true;
            }
            if (token != null && refreshed) {
                return;
            }
            if (principal == null) {
                // There is an option to not specify principal, in that case session was initialized
                // using token only.
                throw new RuntimeException("Cannot refresh, session was not initialized with principal or full token");
            }
            token = strategy.authorize(processor, principal);
        }

        public @NotNull UserDetails fetchUserDetails() throws UnauthorizedException {
            return authorizedFetch(() -> strategy.fetchUserDetails(processor, token));
        }

        public boolean fetchNodeState(String node) throws UnauthorizedException {
            return Boolean.TRUE.equals(authorizedFetch(() -> strategy.fetchNodeState(processor, token, node)));
        }

        // There is no nullable result since all unexpected states result in an exception.
        private <T> @NotNull T authorizedFetch(Supplier<@Nullable T> supplier) throws UnauthorizedException {
            if (!authorized()) {
                throw new UnauthorizedException("Not authorized");
            }
            T tResult = supplier.get();
            if (tResult == null && System.currentTimeMillis() >= token.expiresAt()) {
                if (principal == null && token.refreshToken() == null) {
                    // Principal is null in only case when this result was initialized
                    // with token only, so there is no way to refresh the session.
                    throw new UnauthorizedException("Session expired, please obtain another token");
                }
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

    public static class UnauthorizedException extends Exception {
        public UnauthorizedException(String message) {
            super(message);
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
