package me.zort.authorization.spring;

import me.zort.authorization.lib.AuthorizationClient;
import me.zort.authorization.lib.model.UserDetails;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.security.Principal;

public class KetchupAuthenticationToken extends AbstractAuthenticationToken {

    private final AuthorizationClient.Result result;
    private final UserDetailsPrincipal principal;

    public KetchupAuthenticationToken(AuthorizationClient.Result result, UserDetails details) {
        super(null);
        this.result = result;
        this.principal = new UserDetailsPrincipal(details);
    }

    @Override
    public Object getCredentials() {
        return result.getToken().token();
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
