package me.zort.authorization.spring;

import lombok.RequiredArgsConstructor;
import me.zort.authorization.lib.AuthorizationClient;
import me.zort.authorization.lib.model.UserDetails;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private final AuthorizationClient client;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String jwtToken = authorizationHeader.substring(7);
            AuthorizationClient.Result result = client.verify(jwtToken);
            if (result.authorized()) {
                try {
                    UserDetails userDetails = result.fetchUserDetails();
                    KetchupAuthenticationToken authenticationToken = new KetchupAuthenticationToken(result, userDetails);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                } catch (AuthorizationClient.UnauthorizedException ignored) {
                }
            }
        }

        // Combine with spring security's WebSecurityConfigurerAdapter to handle
        // requests where SecurityContextHolder.getContext().getAuthentication() is not present.
        filterChain.doFilter(request, response);
    }
}
