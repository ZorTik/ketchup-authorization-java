package me.zort.authorization.spring;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class JWTDenyUnauthorizedFilter extends OncePerRequestFilter {
    private final List<AntPathRequestMatcher> ignoredPaths;

    public JWTDenyUnauthorizedFilter() {
        this(Collections.emptyList());
    }

    public JWTDenyUnauthorizedFilter(List<String> ignoredPaths) {
        this.ignoredPaths = ignoredPaths.stream().map(AntPathRequestMatcher::new).toList();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return ignoredPaths.stream().anyMatch(matcher -> matcher.matches(request));
    }
}
