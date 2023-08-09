# ketchup-authorization-java
This repository contains common client libraries to interact with the ketchup-authorization-server.

## authorization-lib
This module contains plain authorization client to be used anywhere without specialization.

### Usage
```java
AuthorizationClient client = new AuthorizationClient.Builder()
   .url("http://authorizationserverurl:1234")
   .processor(new OkHttpProcessor());
AuthorizationClient.Result authorizationResult;

authorizationResult = client.authorize(); // Authorize as trusted client
authorizationResult = client.authorize("username", "password"); // Authorize with basic auth
authorizationResult = client.authorize(principal); // Authorize with custom principal

boolean success = authorizationResult.authorized(); // Check if authorization was successful
UserDetails details = authorizationResult.fetchUserDetails(); // Fetch user details
boolean nodeState = authorizationResult.fetchNodeState("any.permission.node"); // Fetch node (permission) state
```

## authorization-spring
This module contains utilities to simply implement authorization server client<br>
in spring boot.

### JWTAuthorizationFilter
Use this filter to handle incoming API requests authorization using remote<br>
ketchup-authorization-server.

To use this, you need to register it inside WebSecurityConfigurerAdapter<br>
like this:
```java
@Configuration
public class AuthorizationClientConfiguration {
    @Bean
    public AuthorizationClient authorizationClient(
            @Value("authorizationserver.url") String authorizationServerUrl
    ) {
        return new AuthorizationClient.Builder()
                .url(authorizationServerUrl)
                .build();
    }
}

@EnableWebSecurityWebSecurityConfigurerAdapter
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class ApiConfiguration extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private AuthorizationClient authorizationClient;
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JWTAuthorizationFilter authorizationFilter = new JWTAuthorizationFilter(authorizationClient);
        http.csrf().disable()
                // Set endpoints that don't require authorization
                .authorizeRequests().antMatchers("/permittedEndpoint").permitAll()
                // All other requests will require authorization using Bearer token
                // obtained using ketchup-authorization-server.
                .anyRequest().authenticated().and()
                // Setup other modules
                .exceptionHandling().authenticationEntryPoint(exceptionHandlerEntryPoint).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // Set the filter before authentication filter that rejects requests that
                // don't have SecurityContextHolder.getContext().getAuthentication() present.
                .addFilterBefore(authorizationFilter, CustomRejectUnauthorizedFilter.class);
    }
}
```