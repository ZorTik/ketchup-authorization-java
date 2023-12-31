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

    /**
     * Initializes a new authorization client with the specified base URL and HTTP processor.
     *
     * @param baseUrl Base URL of the authorization server
     * @param httpProcessor HTTP processor to use
     */
    public AuthorizationClient(
            @NotNull String baseUrl,
            @NotNull HttpProcessor httpProcessor
    ) {
        Objects.requireNonNull(baseUrl, "Base URL cannot be null");
        Objects.requireNonNull(httpProcessor, "HTTP processor cannot be null");

        this.processor = httpProcessor;
        httpProcessor.setBaseUrl(baseUrl);
    }

    /**
     * Initializes new authorization session using administrator principal.
     * To use this, current machine needs to be on the trusted IP addresses
     * list. By default, all permissions are granted to the administrator.
     *
     * @return New authorization session
     */
    public @NotNull AuthorizationClient.Session authorize() { // Administrator authorization
        return authorize((JsonObject) null).trusted();
    }

    /**
     * Initializes new authorization session using username-password credentials.
     *
     * @param username Username
     * @param password Password
     * @return New authorization session
     */
    public @NotNull AuthorizationClient.Session authorize(@NotNull String username, @NotNull String password) {
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(password, "Password cannot be null");

        JsonObject principal = new JsonObject();
        principal.addProperty("username", username);
        principal.addProperty("password", password);

        return authorize(principal);
    }

    /**
     * Initializes new authorization session using custom principal.
     *
     * @param principal Principal to use
     * @return New authorization session
     */
    public @NotNull AuthorizationClient.Session authorize(@Nullable JsonObject principal) {
        return new Session(strategy, principal, strategy.authorize(processor, principal));
    }

    /**
     * Verifies the specified token and returns a session wrapper.
     * If the token is not valid, session will be initialized without a token
     * instance, so {@link Session#authorized()} will return false.
     *
     * @param token Token to verify
     * @return New authorization session
     */
    public @NotNull AuthorizationClient.Session verify(@NotNull String token) {
        return verify(token, null);
    }

    /**
     * Verifies the specified token and returns a session wrapper.
     * If the token is not valid, session will be initialized without a token
     * instance, so {@link Session#authorized()} will return false.
     * <p>
     * Optionally, a refreshToken can be specified, which will allow the session
     * to be refreshed using {@link Session#refresh()}.
     *
     * @param token Token to verify
     * @param refreshToken Refresh token to use
     * @return New authorization session
     */
    public @NotNull AuthorizationClient.Session verify(@NotNull String token, @Nullable String refreshToken) {
        Objects.requireNonNull(token, "Token cannot be null");

        // Token wrapper without expiration that can't be refreshed
        AuthorizationStrategy.Token tokenInstance = new AuthorizationStrategy.Token(token, refreshToken, -1);
        if (strategy.verifyToken(processor, token)) {
            return new Session(strategy, null, tokenInstance);
        } else {
            return new Session(strategy, null, null);
        }
    }

    public @NotNull AuthorizationClient.Session refresh(@NotNull String refreshToken) {
        Objects.requireNonNull(refreshToken, "Refresh token cannot be null");

        Session session = new Session(strategy, null, new AuthorizationStrategy.Token(null, refreshToken, -1));
        session.refresh();
        return session;
    }

    /**
     * Authorization session wrapper, authorized or non-authorized.
     * Unauthorized session will return false in {@link Session#authorized()}.
     */
    public final class Session {
        private final AuthorizationStrategy strategy;
        private final JsonObject principal;
        @Getter
        private AuthorizationStrategy.Token token;
        private boolean trusted = false;

        private Session(AuthorizationStrategy strategy,
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
            if (token != null && token.refreshToken() != null) {
                token = strategy.refresh(processor, token.refreshToken());
                refreshed = true;
            }
            if (token != null && refreshed) {
                return;
            }
            if (principal == null && !trusted) {
                // There is an option to not specify principal, in that case session was initialized
                // using token only.
                throw new RuntimeException("Cannot refresh, session was not initialized with principal or full token");
            }
            token = strategy.authorize(processor, principal);
        }

        /**
         * Fetches the user details of the current session.
         *
         * @return User details
         * @throws UnauthorizedException When the session is not authorized
         */
        public @NotNull UserDetails fetchUserDetails() throws UnauthorizedException {
            return authorizedFetch(() -> strategy.fetchUserDetails(processor, token));
        }

        /**
         * Fetches the state of provided permission node.
         * In other words, this method will return true if the user has the permission
         * node, otherwise false.
         *
         * @param node Permission node to check
         * @return True if the user has the permission node, otherwise false
         * @throws UnauthorizedException When the session is not authorized
         */
        public boolean fetchNodeState(String node) throws UnauthorizedException {
            return Boolean.TRUE.equals(authorizedFetch(() -> strategy.fetchNodeState(processor, token, node)));
        }

        @NotNull Session trusted() {
            trusted = true;
            return this;
        }

        // There is no nullable result since all unexpected states result in an exception.
        private <T> @NotNull T authorizedFetch(Supplier<@Nullable T> supplier) throws UnauthorizedException {
            if (!authorized()) {
                throw new UnauthorizedException("Not authorized");
            }
            T tResult = supplier.get();
            if (tResult == null && System.currentTimeMillis() >= token.expiresAt()) {
                requireCanRefresh();
                refresh();
                return authorizedFetch(supplier);
            } else if (tResult == null) {
                throw new IllegalStateException("Token should be valid, but response was not present");
            } else {
                return tResult;
            }
        }

        public String getValidToken() throws UnauthorizedException {
            if (!authorized()) {
                throw new UnauthorizedException("Not authorized");
            }
            if (System.currentTimeMillis() >= token.expiresAt()) {
                requireCanRefresh();
                refresh();
                return getValidToken();
            } else {
                return token.token();
            }
        }

        private void requireCanRefresh() throws UnauthorizedException {
            if (principal == null && !trusted && token.refreshToken() == null) {
                // Principal is null in only case when this result was initialized
                // with token only, so there is no way to refresh the session.
                throw new UnauthorizedException("Session expired, please obtain another token");
            }
        }

        /**
         * Returns true if the session is authorized, otherwise false.
         *
         * @return Session authorization state
         */
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
