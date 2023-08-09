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