# OAuth2 Server Oak Local Storage example

This example was created to demonstrate how to use OAuth2 Server with the Oak
adapter and your own storage mechanism. This example uses localStorage as the
storage mechanism to keep it simple. It can be adapted to use any storage
mechanism by modifying the services.

The session service is not required by OAuth2 Server. I created it for this
example to demonstrate how the login and consent functions work for the
authorization code grant.

The login endpoint generates a CSRF token to help protect against CSRF
vulnerabilities. This is not required by OAuth2 Server but is recommended by the
Open Web Application Security Project. See
[Cross-Site request Forgery Prevention Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#login-csrf)
for more information.

This example does not include how to determine which scopes are allowed and
currently allows any valid scope value to be used. The token service's
acceptedScope function can be modified to limit which scopes can be requested
for a client user combination.

## Usage

To run this example, use the following command from this directory.

```
make load
make run
```

To have the oauth2 server reload and restart whenever a change is made, run the
following command from this directory.

```
make run-dev
```
