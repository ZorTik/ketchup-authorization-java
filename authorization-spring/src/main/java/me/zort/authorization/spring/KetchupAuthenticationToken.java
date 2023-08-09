package me.zort.authorization.spring;

import me.zort.authorization.lib.AuthorizationClient;
import me.zort.authorization.lib.model.UserDetails;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.security.Principal;

public class KetchupAuthenticationToken extends AbstractAuthenticationToken {

    private final AuthorizationClient.Session session;
    private final UserDetailsPrincipal principal;

    public KetchupAuthenticationToken(AuthorizationClient.Session session, UserDetails details) {
        super(null);
        this.session = session;
        this.principal = new UserDetailsPrincipal(details);
    }

    @Override
    public Object getCredentials() {
        return session.getToken().token();
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public UserDetails getUserDetails() {
        return principal.details();
    }

    private record UserDetailsPrincipal(UserDetails details) implements Principal {
        @Override
        public String getName() {
            return details.username();
        }
    }
}
