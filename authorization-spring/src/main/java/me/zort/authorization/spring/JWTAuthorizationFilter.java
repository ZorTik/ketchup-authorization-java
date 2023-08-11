package me.zort.authorization.spring;

import lombok.RequiredArgsConstructor;
import me.zort.authorization.lib.AuthorizationClient;
import me.zort.authorization.lib.model.UserDetails;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private final AuthorizationClient client;
    private final Map<AntPathRequestMatcher, String> permissionMapping = new ConcurrentHashMap<>();

    public JWTAuthorizationFilter(AuthorizationClient client) {
        this(client, null);
    }

    public JWTAuthorizationFilter(AuthorizationClient client, @Nullable PermissionMapping mapping) {
        this.client = client;
        if (mapping != null) {
            this.permissionMapping.putAll(mapping.getMapping());
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String jwtToken = authorizationHeader.substring(7);
            AuthorizationClient.Session session = client.verify(jwtToken);
            if (session.authorized()) {
                try {
                    UserDetails userDetails = session.fetchUserDetails();
                    if (permissionNodeCheck(request, session)) {
                        KetchupAuthenticationToken authenticationToken = new KetchupAuthenticationToken(session, userDetails);
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    }
                } catch (AuthorizationClient.UnauthorizedException ignored) {
                }
            }
        }

        // Combine with spring security's WebSecurityConfigurerAdapter to handle
        // requests where SecurityContextHolder.getContext().getAuthentication() is not present.
        filterChain.doFilter(request, response);
    }

    private boolean permissionNodeCheck(HttpServletRequest request, AuthorizationClient.Session session) {
        for (AntPathRequestMatcher matcher : permissionMapping.keySet()) {
            try {
                if (matcher.matches(request) && !session.fetchNodeState(permissionMapping.get(matcher))) {
                    return false;
                }
            } catch (AuthorizationClient.UnauthorizedException e) {
                e.printStackTrace();
                return false;
            }
        }
        return true;
    }

    public static class PermissionMapping {
        private final Map<AntPathRequestMatcher, String> mapping = new HashMap<>();

        public @NotNull PermissionMapping path(String ant, String node) {
            mapping.put(new AntPathRequestMatcher(ant), node);
            return this;
        }

        public @NotNull Map<AntPathRequestMatcher, String> getMapping() {
            return new HashMap<>(mapping);
        }
    }
}
