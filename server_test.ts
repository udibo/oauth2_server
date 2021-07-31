import {
  RefreshTokenGrant,
  RefreshTokenGrantInterface,
} from "./grants/refresh_token.ts";
import {
  AccessToken,
  RefreshToken,
  RefreshTokenService,
} from "./models/token.ts";
import { Client, ClientService } from "./models/client.ts";
import type { User } from "./models/user.ts";
import { Scope } from "./models/scope.ts";
import {
  assert,
  assertEquals,
  assertSpyCall,
  assertSpyCallAsync,
  assertSpyCalls,
  assertStrictEquals,
  assertThrows,
  assertThrowsAsync,
  delay,
  resolves,
  Spy,
  spy,
  SpyCall,
  Stub,
  stub,
  test,
  TestSuite,
} from "./test_deps.ts";
import {
  AccessDenied,
  InvalidClient,
  InvalidGrant,
  InvalidRequest,
  OAuth2Error,
  ServerError,
  UnauthorizedClient,
  UnsupportedGrantType,
} from "./errors.ts";
import {
  Authenticator,
  OAuth2Context,
  OAuth2Request,
  OAuth2Response,
  OAuth2State,
} from "./context.ts";
import { OAuth2Server, OAuth2ServerGrants } from "./server.ts";
import {
  fakeAuthorizeRequest,
  fakeResourceRequest,
  fakeResponse,
  fakeTokenRequest,
} from "./test_context.ts";
import { ExampleRefreshTokenService } from "./models/token_test.ts";
import { GrantServices } from "./grants/grant.ts";
import { ExampleClientService } from "./models/client_test.ts";
import { assertAuthorizationCode, assertToken } from "./asserts.ts";
import {
  AuthorizationCodeGrant,
  AuthorizationCodeGrantInterface,
} from "./grants/authorization_code.ts";
import {
  AuthorizationCode,
  AuthorizationCodeService,
} from "./models/authorization_code.ts";
import { ExampleAuthorizationCodeService } from "./models/authorization_code_test.ts";
import { challengeMethods, generateCodeVerifier } from "./pkce.ts";

const serverTests: TestSuite<void> = new TestSuite({
  name: "OAuth2Server",
});

const user: User = { username: "kyle" };
const client: Client = {
  id: "1",
  grants: ["refresh_token", "authorization_code"],
  redirectUris: [
    "https://client.example.com/cb",
    "https://client2.example.com/cb",
  ],
};
const clientService: ClientService = new ExampleClientService({ client });
const tokenService: RefreshTokenService = new ExampleRefreshTokenService({
  client,
});
const authorizationCodeService: AuthorizationCodeService =
  new ExampleAuthorizationCodeService({ client });
const services: GrantServices = { clientService, tokenService };

const refreshTokenGrant: RefreshTokenGrantInterface = new RefreshTokenGrant({
  services,
});
const authorizationCodeGrant: AuthorizationCodeGrantInterface =
  new AuthorizationCodeGrant({
    services: { ...services, authorizationCodeService },
  });
const grants: OAuth2ServerGrants = {
  "refresh_token": refreshTokenGrant,
  "authorization_code": authorizationCodeGrant,
};
const server: OAuth2Server = new OAuth2Server({
  grants,
  services: { tokenService },
});

const generateTokenTests: TestSuite<void> = new TestSuite({
  name: "generateToken",
  suite: serverTests,
});

test(generateTokenTests, "method must be post", async () => {
  const request: OAuth2Request = fakeTokenRequest();
  request.method = "GET";
  await assertThrowsAsync(
    () => server.generateToken(request),
    InvalidRequest,
    "method must be POST",
  );
});

test(
  generateTokenTests,
  "content-type header must be application/x-www-form-urlencoded",
  async () => {
    let request: OAuth2Request = fakeTokenRequest();
    request.headers.delete("Content-Type");
    await assertThrowsAsync(
      () => server.generateToken(request),
      InvalidRequest,
      "content-type header must be application/x-www-form-urlencoded",
    );

    request = fakeTokenRequest();
    request.headers.set("Content-Type", "application/json");
    await assertThrowsAsync(
      () => server.generateToken(request),
      InvalidRequest,
      "content-type header must be application/x-www-form-urlencoded",
    );
  },
);

test(generateTokenTests, "request body required", async () => {
  const request: OAuth2Request = fakeTokenRequest();
  await assertThrowsAsync(
    () => server.generateToken(request),
    InvalidRequest,
    "request body required",
  );
});

test(generateTokenTests, "grant_type parameter required", async () => {
  let request: OAuth2Request = fakeTokenRequest("");
  await assertThrowsAsync(
    () => server.generateToken(request),
    InvalidRequest,
    "grant_type parameter required",
  );

  request = fakeTokenRequest("grant_type=");
  await assertThrowsAsync(
    () => server.generateToken(request),
    InvalidRequest,
    "grant_type parameter required",
  );
});

test(generateTokenTests, "invalid grant_type", async () => {
  let request: OAuth2Request = fakeTokenRequest("grant_type=fake");
  await assertThrowsAsync(
    () => server.generateToken(request),
    UnsupportedGrantType,
    "invalid grant_type",
  );

  request = fakeTokenRequest("grant_type=refresh_token");
  try {
    delete server.grants["refresh_token"];
    await assertThrowsAsync(
      () => server.generateToken(request),
      UnsupportedGrantType,
      "invalid grant_type",
    );
  } finally {
    server.grants = { ...grants };
  }
});

test(generateTokenTests, "client authentication failed", async () => {
  const getAuthenticatedClientStub: Stub<RefreshTokenGrant> = stub(
    refreshTokenGrant,
    "getAuthenticatedClient",
    () => Promise.reject(new InvalidClient("client authentication failed")),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    await assertThrowsAsync(
      () => server.generateToken(request),
      InvalidClient,
      "client authentication failed",
    );
    assertEquals(getAuthenticatedClientStub.calls.length, 1);
    assertEquals(getAuthenticatedClientStub.calls[0].args.length, 1);
    assertStrictEquals(getAuthenticatedClientStub.calls[0].args[0], request);
    assertStrictEquals(
      getAuthenticatedClientStub.calls[0].self,
      refreshTokenGrant,
    );
  } finally {
    getAuthenticatedClientStub.restore();
  }
});

test(
  generateTokenTests,
  "client is not authorized to use this grant_type",
  async () => {
    const getAuthenticatedClientStub: Stub<RefreshTokenGrant> = stub(
      refreshTokenGrant,
      "getAuthenticatedClient",
      resolves({
        ...client,
        grants: ["fake"],
      }),
    );
    try {
      const request: OAuth2Request = fakeTokenRequest(
        "grant_type=refresh_token",
      );
      await assertThrowsAsync(
        () => server.generateToken(request),
        UnauthorizedClient,
        "client is not authorized to use this grant_type",
      );
      assertEquals(getAuthenticatedClientStub.calls.length, 1);
      assertEquals(getAuthenticatedClientStub.calls[0].args.length, 1);
      assertStrictEquals(getAuthenticatedClientStub.calls[0].args[0], request);
      assertStrictEquals(
        getAuthenticatedClientStub.calls[0].self,
        refreshTokenGrant,
      );
    } finally {
      getAuthenticatedClientStub.restore();
    }
  },
);

test(generateTokenTests, "grant token error", async () => {
  const refreshTokenGrantTokenStub: Stub<RefreshTokenGrant> = stub(
    refreshTokenGrant,
    "token",
    () => Promise.reject(new InvalidGrant("invalid refresh_token")),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    await assertThrowsAsync(
      () => server.generateToken(request),
      InvalidGrant,
      "invalid refresh_token",
    );
  } finally {
    refreshTokenGrantTokenStub.restore();
  }
});

const scope: Scope = new Scope("read write");

test(generateTokenTests, "returns refresh token", async () => {
  const token: RefreshToken = {
    accessToken: "foo",
    refreshToken: "bar",
    client,
    user,
    scope,
  };
  const refreshTokenGrantTokenStub: Stub<RefreshTokenGrant> = stub(
    refreshTokenGrant,
    "token",
    () => Promise.resolve(token),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    assertStrictEquals(await server.generateToken(request), token);
  } finally {
    refreshTokenGrantTokenStub.restore();
  }
});

const tokenTests: TestSuite<void> = new TestSuite({
  name: "token",
  suite: serverTests,
});

test(
  tokenTests,
  "handles generateToken error and awaits handleError response",
  async () => {
    const error: OAuth2Error = new InvalidGrant("invalid refresh_token");
    const generateToken: Stub<OAuth2Server> = stub(
      server,
      "generateToken",
      () => Promise.reject(error),
    );
    const afterErrorHandler: Spy<void> = spy();
    const errorHandler: Stub<OAuth2Server> = stub(
      server,
      "errorHandler",
      () => delay(0).then(afterErrorHandler),
    );
    const response: OAuth2Response = fakeResponse();
    const redirect: Spy<OAuth2Response> = spy(response, "redirect");
    try {
      const request: OAuth2Request = fakeTokenRequest(
        "grant_type=refresh_token",
      );
      const state: OAuth2State = {};
      await assertThrowsAsync(
        () => server.token({ request, response, state }),
        InvalidGrant,
        "invalid refresh_token",
      );
      assertSpyCall(errorHandler, 0, {
        args: [response, error, "Service"],
      });
      assertSpyCalls(afterErrorHandler, 1);

      assertEquals(response.status, undefined);
      assertEquals(response.body, undefined);
      assertSpyCalls(redirect, 0);

      assertEquals(state, {});
    } finally {
      generateToken.restore();
      errorHandler.restore();
    }
  },
);

test(tokenTests, "without optional token properties", async () => {
  const generateTokenStub: Stub<OAuth2Server> = stub(
    server,
    "generateToken",
    () =>
      Promise.resolve({
        accessToken: "foo",
        client,
        user,
      }),
  );
  const handleErrorSpy: Spy<OAuth2Server> = spy(server, "handleError");
  const response: OAuth2Response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    const state: OAuth2State = {};
    assertToken(
      await server.token({ request, response, state }),
      {
        accessToken: "foo",
        client,
        user,
      },
    );
    assertEquals(handleErrorSpy.calls.length, 0);
    assertEquals(response.status, 200);
    assertEquals(response.body, { access_token: "foo", token_type: "Bearer" });
    assertEquals(redirectSpy.calls.length, 0);

    assertEquals(state, {});
  } finally {
    generateTokenStub.restore();
  }
});

test(tokenTests, "with optional token properties", async () => {
  const now: Date = new Date("2021-05-15T13:09:05Z");
  const generateTokenStub: Stub<OAuth2Server> = stub(
    server,
    "generateToken",
    () =>
      Promise.resolve({
        accessToken: "foo",
        refreshToken: "bar",
        accessTokenExpiresAt: new Date(now.valueOf() + 120000),
        refreshTokenExpiresAt: new Date(now.valueOf() + 600000),
        client,
        user,
        scope,
        code: "xyz",
      }),
  );
  const handleErrorSpy: Spy<OAuth2Server> = spy(server, "handleError");
  const response: OAuth2Response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    const state: OAuth2State = {};
    assertToken(await server.token({ request, response, state }), {
      accessToken: "foo",
      refreshToken: "bar",
      accessTokenExpiresAt: new Date(now.valueOf() + 120000),
      refreshTokenExpiresAt: new Date(now.valueOf() + 600000),
      client,
      user,
      scope,
      code: "xyz",
    });
    assertEquals(handleErrorSpy.calls.length, 0);
    assertEquals(response.status, 200);
    assertEquals(response.body, {
      access_token: "foo",
      refresh_token: "bar",
      access_token_expires_at: "2021-05-15T13:11:05.000Z",
      refresh_token_expires_at: "2021-05-15T13:19:05.000Z",
      scope: "read write",
      token_type: "Bearer",
    });
    assertEquals(redirectSpy.calls.length, 0);

    assertEquals(state, {});
  } finally {
    generateTokenStub.restore();
  }
});

const authenticateTests: TestSuite<void> = new TestSuite({
  name: "authenticate",
  suite: serverTests,
});

test(authenticateTests, "token service required", async () => {
  const server: OAuth2Server = new OAuth2Server({ grants });
  const request = fakeResourceRequest("");
  const response = fakeResponse();
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  await assertThrowsAsync(
    () => server.authenticate(context),
    ServerError,
    "token service required",
  );

  assertEquals(response.status, undefined);
  assertEquals([...response.headers.entries()], []);
  assertEquals(response.body, undefined);

  assertEquals(state, {});
});

test(authenticateTests, "authentication required", async () => {
  const request = fakeResourceRequest("");
  const response = fakeResponse();
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  await assertThrowsAsync(
    () => server.authenticate(context),
    AccessDenied,
    "authentication required",
  );

  assertEquals(response.status, undefined);
  assertEquals([...response.headers.entries()], []);
  assertEquals(response.body, undefined);
});

test(authenticateTests, "invalid access_token", async () => {
  const getAccessToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "getAccessToken",
    resolves(undefined),
  );

  try {
    const request = fakeResourceRequest("123");
    const response = fakeResponse();
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    await assertThrowsAsync(
      () => server.authenticate(context),
      AccessDenied,
      "invalid access_token",
    );

    assertSpyCall(getAccessToken, 0, {
      self: tokenService,
      args: ["123"],
    });
    assertSpyCalls(getAccessToken, 1);

    assertEquals(response.status, undefined);
    assertEquals([...response.headers.entries()], []);
    assertEquals(response.body, undefined);

    assert("token" in state);
    assertToken(state.token, undefined);
  } finally {
    getAccessToken.restore();
  }
});

test(authenticateTests, "expired access_token", async () => {
  const getAccessToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "getAccessToken",
    () =>
      Promise.resolve({
        accessToken: "123",
        accessTokenExpiresAt: new Date(Date.now() - 60000),
        client,
        user,
        scope,
      }),
  );

  try {
    const request = fakeResourceRequest("123");
    const response = fakeResponse();
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    await assertThrowsAsync(
      () => server.authenticate(context),
      AccessDenied,
      "invalid access_token",
    );

    assertSpyCall(getAccessToken, 0, {
      self: tokenService,
      args: ["123"],
    });
    assertSpyCalls(getAccessToken, 1);

    assertEquals(response.status, undefined);
    assertEquals([...response.headers.entries()], []);
    assertEquals(response.body, undefined);

    assert("token" in state);
    assertToken(state.token, undefined);
  } finally {
    getAccessToken.restore();
  }
});

test(authenticateTests, "insufficient scope", async () => {
  const getAccessToken: Spy<RefreshTokenService> = spy(
    tokenService,
    "getAccessToken",
  );

  try {
    const request = fakeResourceRequest("123");
    const response = fakeResponse();
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    const acceptedScope: Scope = new Scope("read write delete");
    await assertThrowsAsync(
      () => server.authenticate(context, acceptedScope),
      AccessDenied,
      "insufficient scope",
    );

    assertSpyCall(getAccessToken, 0, {
      args: ["123"],
    });
    assertSpyCalls(getAccessToken, 1);

    assertEquals(response.status, undefined);
    assertEquals([...response.headers.entries()], [
      ["x-accepted-oauth-scopes", "read write delete"],
      ["x-oauth-scopes", "read write"],
    ]);
    assertEquals(response.body, undefined);

    assertToken(state.token, {
      accessToken: "123",
      client,
      user,
      scope,
    });
  } finally {
    getAccessToken.restore();
  }
});

test(authenticateTests, "without scope", async () => {
  const getAccessToken: Spy<RefreshTokenService> = spy(
    tokenService,
    "getAccessToken",
  );

  try {
    const request = fakeResourceRequest("123");
    const response = fakeResponse();
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    await server.authenticate(context);

    assertSpyCall(getAccessToken, 0, {
      args: ["123"],
    });
    assertSpyCalls(getAccessToken, 1);

    assertEquals(response.status, undefined);
    assertEquals([...response.headers.entries()], [
      ["x-accepted-oauth-scopes", ""],
      ["x-oauth-scopes", "read write"],
    ]);
    assertEquals(response.body, undefined);

    assertToken(state.token, {
      accessToken: "123",
      client,
      user,
      scope,
    });
  } finally {
    getAccessToken.restore();
  }
});

test(authenticateTests, "with scope", async () => {
  const getAccessToken: Spy<RefreshTokenService> = spy(
    tokenService,
    "getAccessToken",
  );

  try {
    const request = fakeResourceRequest("123");
    const response = fakeResponse();
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    await server.authenticate(context, scope);

    assertSpyCall(getAccessToken, 0, {
      args: ["123"],
    });
    assertSpyCalls(getAccessToken, 1);

    assertEquals(response.status, undefined);
    assertEquals([...response.headers.entries()], [
      ["x-accepted-oauth-scopes", "read write"],
      ["x-oauth-scopes", "read write"],
    ]);
    assertEquals(response.body, undefined);

    assertToken(state.token, {
      accessToken: "123",
      client,
      user,
      scope,
    });
  } finally {
    getAccessToken.restore();
  }
});

test(authenticateTests, "re-uses token stored in state", async () => {
  const getAccessToken: Spy<RefreshTokenService> = spy(
    tokenService,
    "getAccessToken",
  );

  try {
    const request = fakeResourceRequest("123");
    const response = fakeResponse();
    const token: AccessToken = {
      accessToken: "123",
      client,
      user,
      scope,
    };
    const state: OAuth2State = { token };
    const context: OAuth2Context = { request, response, state };
    await server.authenticate(context);

    assertSpyCalls(getAccessToken, 0);

    assertEquals(response.status, undefined);
    assertEquals([...response.headers.entries()], [
      ["x-accepted-oauth-scopes", ""],
      ["x-oauth-scopes", "read write"],
    ]);
    assertEquals(response.body, undefined);

    assertToken(state.token, token);
  } finally {
    getAccessToken.restore();
  }
});

const authenticatorFactoryTests: TestSuite<void> = new TestSuite({
  name: "authenticatorFactory",
  suite: serverTests,
});

test(authenticatorFactoryTests, "token service required", () => {
  const server: OAuth2Server = new OAuth2Server({ grants });
  assertThrows(
    () => server.authenticatorFactory(),
    ServerError,
    "token service required",
  );
});

test(authenticatorFactoryTests, "authenticator error", async () => {
  const authenticate: Spy<OAuth2Server> = spy(server, "authenticate");
  try {
    const authenticator: Authenticator = server.authenticatorFactory();
    const request = fakeResourceRequest("");
    const response = fakeResponse();
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    await assertThrowsAsync(
      () => authenticator(context),
      AccessDenied,
      "authentication required",
    );

    await assertSpyCallAsync(authenticate, 0, {
      self: server,
      args: [context],
      error: {
        Class: AccessDenied,
        msg: "authentication required",
      },
    });
    assertSpyCalls(authenticate, 1);

    assertEquals(response.status, 401);
    assertEquals([...response.headers.entries()], [
      ["www-authenticate", 'Basic realm="Service"'],
    ]);
    assertEquals(response.body, {
      error: "access_denied",
      error_description: "authentication required",
    });

    assert(!("token" in state));
  } finally {
    authenticate.restore();
  }
});

test(
  authenticatorFactoryTests,
  "authenticator success without scope",
  async () => {
    const authenticate: Spy<OAuth2Server> = spy(server, "authenticate");
    try {
      const authenticator = server.authenticatorFactory();
      const request = fakeResourceRequest("123");
      const response = fakeResponse();
      const state: OAuth2State = {};
      const context: OAuth2Context = { request, response, state };
      assertEquals(await authenticator(context), {
        accessToken: "123",
        client,
        user,
        scope,
      });

      await assertSpyCallAsync(authenticate, 0, {
        self: server,
        args: [context],
        returned: {
          accessToken: "123",
          client,
          user,
          scope,
        },
      });
      assertSpyCalls(authenticate, 1);

      assertEquals(response.status, undefined);
      assertEquals([...response.headers.entries()], [
        ["x-accepted-oauth-scopes", ""],
        ["x-oauth-scopes", "read write"],
      ]);
      assertEquals(response.body, undefined);

      assertToken(state.token, {
        accessToken: "123",
        client,
        user,
        scope,
      });
    } finally {
      authenticate.restore();
    }
  },
);

test(
  authenticatorFactoryTests,
  "authenticator success with scope",
  async () => {
    const authenticate: Spy<OAuth2Server> = spy(server, "authenticate");
    try {
      const authenticator = server.authenticatorFactory("read");
      const request = fakeResourceRequest("123");
      const response = fakeResponse();
      const state: OAuth2State = {};
      const context: OAuth2Context = { request, response, state };
      assertEquals(await authenticator(context), {
        accessToken: "123",
        client,
        user,
        scope,
      });

      const call: SpyCall = await assertSpyCallAsync(authenticate, 0, {
        self: server,
        returned: {
          accessToken: "123",
          client,
          user,
          scope,
        },
      });
      assertEquals(call.args.length, 2);
      assertEquals(call.args[0], context);
      assert((new Scope("read")).equals(call.args[1]));
      assertSpyCalls(authenticate, 1);

      assertEquals(response.status, undefined);
      assertEquals([...response.headers.entries()], [
        ["x-accepted-oauth-scopes", "read"],
        ["x-oauth-scopes", "read write"],
      ]);
      assertEquals(response.body, undefined);

      assertToken(state.token, {
        accessToken: "123",
        client,
        user,
        scope,
      });
    } finally {
      authenticate.restore();
    }
  },
);

const authorizeTests: TestSuite<void> = new TestSuite({
  name: "authorize",
  suite: serverTests,
});

test(
  authorizeTests,
  "missing authorization code grant",
  async () => {
    const server: OAuth2Server = new OAuth2Server({
      services,
      grants: {
        "refresh_token": refreshTokenGrant,
      },
    });
    const afterErrorHandler: Spy<void> = spy();
    const errorHandler: Stub<OAuth2Server> = stub(
      server,
      "errorHandler",
      () => delay(0).then(afterErrorHandler),
    );
    const request: OAuth2Request = fakeAuthorizeRequest();
    const response = fakeResponse();
    const redirect: Spy<OAuth2Response> = spy(response, "redirect");
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    try {
      let error: Error | null = null;
      await assertThrowsAsync(
        async () => {
          try {
            await server.authorize(context);
          } catch (e) {
            error = e;
            throw e;
          }
        },
        ServerError,
        "missing authorization code grant",
      );
      assertSpyCall(errorHandler, 0, {
        args: [response, error, "Service"],
      });
      assertSpyCalls(afterErrorHandler, 1);
      assertEquals(response.status, undefined);
      assertEquals(response.body, undefined);
      assertSpyCalls(redirect, 0);
    } finally {
      errorHandler.restore();
    }
  },
);

test(authorizeTests, "client_id parameter required", async () => {
  const afterErrorHandler: Spy<void> = spy();
  const errorHandler: Stub<OAuth2Server> = stub(
    server,
    "errorHandler",
    () => delay(0).then(afterErrorHandler),
  );
  const request: OAuth2Request = fakeAuthorizeRequest();
  request.url.searchParams.delete("client_id");
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    let error: Error | null = null;
    await assertThrowsAsync(
      async () => {
        try {
          await server.authorize(context, user);
        } catch (e) {
          error = e;
          throw e;
        }
      },
      InvalidRequest,
      "client_id parameter required",
    );
    assertSpyCall(errorHandler, 0, {
      args: [response, error, "Service"],
    });
    assertSpyCalls(afterErrorHandler, 1);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);
  } finally {
    errorHandler.restore();
  }
});

test(authorizeTests, "client not found", async () => {
  const clientServiceGet: Stub<ClientService> = stub(
    clientService,
    "get",
    resolves(undefined),
  );
  const afterErrorHandler: Spy<void> = spy();
  const errorHandler: Stub<OAuth2Server> = stub(
    server,
    "errorHandler",
    () => delay(0).then(afterErrorHandler),
  );
  const request: OAuth2Request = fakeAuthorizeRequest();
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    let error: Error | null = null;
    await assertThrowsAsync(
      async () => {
        try {
          await server.authorize(context, user);
        } catch (e) {
          error = e;
          throw e;
        }
      },
      InvalidClient,
      "client not found",
    );
    assertSpyCall(errorHandler, 0, {
      args: [response, error, "Service"],
    });
    assertSpyCalls(afterErrorHandler, 1);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);
  } finally {
    clientServiceGet.restore();
    errorHandler.restore();
  }
});

test(
  authorizeTests,
  "client is not authorized to use the authorization code grant type",
  async () => {
    const clientServiceGet: Stub<ClientService> = stub(
      clientService,
      "get",
      resolves({ ...client, grants: ["refresh_token"] }),
    );
    const afterErrorHandler: Spy<void> = spy();
    const errorHandler: Stub<OAuth2Server> = stub(
      server,
      "errorHandler",
      () => delay(0).then(afterErrorHandler),
    );
    const request: OAuth2Request = fakeAuthorizeRequest();
    const response = fakeResponse();
    const redirect: Spy<OAuth2Response> = spy(response, "redirect");
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    try {
      let error: Error | null = null;
      await assertThrowsAsync(
        async () => {
          try {
            await server.authorize(context, user);
          } catch (e) {
            error = e;
            throw e;
          }
        },
        UnauthorizedClient,
        "client is not authorized to use the authorization code grant type",
      );
      assertSpyCall(errorHandler, 0, {
        args: [response, error, "Service"],
      });
      assertSpyCalls(afterErrorHandler, 1);
      assertEquals(response.status, undefined);
      assertEquals(response.body, undefined);
      assertSpyCalls(redirect, 0);
    } finally {
      clientServiceGet.restore();
      errorHandler.restore();
    }
  },
);

test(authorizeTests, "no authorized redirect_uri", async () => {
  const clientServiceGet: Stub<ClientService> = stub(
    clientService,
    "get",
    resolves({ ...client, redirectUris: [] }),
  );
  const afterErrorHandler: Spy<void> = spy();
  const errorHandler: Stub<OAuth2Server> = stub(
    server,
    "errorHandler",
    () => delay(0).then(afterErrorHandler),
  );
  const request: OAuth2Request = fakeAuthorizeRequest();
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    let error: Error | null = null;
    await assertThrowsAsync(
      async () => {
        try {
          await server.authorize(context, user);
        } catch (e) {
          error = e;
          throw e;
        }
      },
      UnauthorizedClient,
      "no authorized redirect_uri",
    );
    assertSpyCall(errorHandler, 0, {
      args: [response, error, "Service"],
    });
    assertSpyCalls(afterErrorHandler, 1);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);
  } finally {
    clientServiceGet.restore();
    errorHandler.restore();
  }
});

test(authorizeTests, "redirect_uri not authorized", async () => {
  const afterErrorHandler: Spy<void> = spy();
  const errorHandler: Stub<OAuth2Server> = stub(
    server,
    "errorHandler",
    () => delay(0).then(afterErrorHandler),
  );
  const request: OAuth2Request = fakeAuthorizeRequest();
  request.url.searchParams.set("redirect_uri", "http://client.example.com/cb");
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    let error: Error | null = null;
    await assertThrowsAsync(
      async () => {
        try {
          await server.authorize(context, user);
        } catch (e) {
          error = e;
          throw e;
        }
      },
      UnauthorizedClient,
      "redirect_uri not authorized",
    );
    assertSpyCall(errorHandler, 0, {
      args: [response, error, "Service"],
    });
    assertSpyCalls(afterErrorHandler, 1);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);
  } finally {
    errorHandler.restore();
  }
});

test(authorizeTests, "state required", async () => {
  const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
  const request: OAuth2Request = fakeAuthorizeRequest();
  request.url.searchParams.delete("state");
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    await assertThrowsAsync(
      () => server.authorize(context, user),
      InvalidRequest,
      "state required",
    );
    assertSpyCalls(errorHandler, 0);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
    const { searchParams } = expectedRedirectUrl;
    searchParams.set("error", "invalid_request");
    searchParams.set("error_description", "state required");
    assertSpyCall(redirect, 0, {
      self: response,
      args: [expectedRedirectUrl],
    });
    assertSpyCalls(redirect, 1);
  } finally {
    errorHandler.restore();
  }
});

test(
  authorizeTests,
  "authentication required",
  async () => {
    const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
    const request: OAuth2Request = fakeAuthorizeRequest();
    const response = fakeResponse();
    const redirect: Spy<OAuth2Response> = spy(response, "redirect");
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    try {
      await assertThrowsAsync(
        () => server.authorize(context),
        AccessDenied,
        "authentication required",
      );
      assertSpyCalls(errorHandler, 0);
      assertEquals(response.status, undefined);
      assertEquals(response.body, undefined);
      const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
      const { searchParams } = expectedRedirectUrl;
      searchParams.set("state", "xyz");
      searchParams.set("error", "access_denied");
      searchParams.set("error_description", "authentication required");
      assertSpyCall(redirect, 0, {
        self: response,
        args: [expectedRedirectUrl],
      });
      assertSpyCalls(redirect, 1);

      await assertThrowsAsync(
        () => server.authorize(context, undefined),
        AccessDenied,
        "authentication required",
      );
      assertSpyCalls(errorHandler, 0);
      assertEquals(response.status, undefined);
      assertEquals(response.body, undefined);
      assertSpyCall(redirect, 1, {
        self: response,
        args: [expectedRedirectUrl],
      });
      assertSpyCalls(redirect, 2);

      await assertThrowsAsync(
        () => server.authorize(context, null),
        AccessDenied,
        "authentication required",
      );
      assertSpyCalls(errorHandler, 0);
      assertEquals(response.status, undefined);
      assertEquals(response.body, undefined);
      assertSpyCall(redirect, 2, {
        self: response,
        args: [expectedRedirectUrl],
      });
      assertSpyCalls(redirect, 3);
    } finally {
      errorHandler.restore();
    }
  },
);

test(authorizeTests, "response_type parameter required", async () => {
  const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
  const request: OAuth2Request = fakeAuthorizeRequest();
  request.url.searchParams.delete("response_type");
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    await assertThrowsAsync(
      () => server.authorize(context, user),
      InvalidRequest,
      "response_type parameter required",
    );
    assertSpyCalls(errorHandler, 0);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
    const { searchParams } = expectedRedirectUrl;
    searchParams.set("state", "xyz");
    searchParams.set("error", "invalid_request");
    searchParams.set("error_description", "response_type parameter required");
    assertSpyCall(redirect, 0, {
      self: response,
      args: [expectedRedirectUrl],
    });
    assertSpyCalls(redirect, 1);
  } finally {
    errorHandler.restore();
  }
});

test(authorizeTests, "response_type not supported", async () => {
  const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
  const request: OAuth2Request = fakeAuthorizeRequest();
  request.url.searchParams.set("response_type", "token");
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    await assertThrowsAsync(
      () => server.authorize(context, user),
      InvalidRequest,
      "response_type not supported",
    );
    assertSpyCalls(errorHandler, 0);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
    const { searchParams } = expectedRedirectUrl;
    searchParams.set("state", "xyz");
    searchParams.set("error", "invalid_request");
    searchParams.set("error_description", "response_type not supported");
    assertSpyCall(redirect, 0, {
      self: response,
      args: [expectedRedirectUrl],
    });
    assertSpyCalls(redirect, 1);
  } finally {
    errorHandler.restore();
  }
});

test(
  authorizeTests,
  "code_challenge required when code_challenge_method is set",
  async () => {
    const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
    const request: OAuth2Request = fakeAuthorizeRequest();
    request.url.searchParams.set("code_challenge_method", "S256");
    const response = fakeResponse();
    const redirect: Spy<OAuth2Response> = spy(response, "redirect");
    const state: OAuth2State = {};
    const context: OAuth2Context = { request, response, state };
    try {
      await assertThrowsAsync(
        () => server.authorize(context, user),
        InvalidRequest,
        "code_challenge required when code_challenge_method is set",
      );
      assertSpyCalls(errorHandler, 0);
      assertEquals(response.status, undefined);
      assertEquals(response.body, undefined);
      const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
      const { searchParams } = expectedRedirectUrl;
      searchParams.set("state", "xyz");
      searchParams.set("error", "invalid_request");
      searchParams.set(
        "error_description",
        "code_challenge required when code_challenge_method is set",
      );
      assertSpyCall(redirect, 0, {
        self: response,
        args: [expectedRedirectUrl],
      });
      assertSpyCalls(redirect, 1);
    } finally {
      errorHandler.restore();
    }
  },
);

test(authorizeTests, "code_challenge_method required", async () => {
  const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
  const request: OAuth2Request = fakeAuthorizeRequest();
  request.url.searchParams.set("code_challenge", "abc");
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    await assertThrowsAsync(
      () => server.authorize(context, user),
      InvalidRequest,
      "unsupported code_challenge_method",
    );
    assertSpyCalls(errorHandler, 0);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
    const { searchParams } = expectedRedirectUrl;
    searchParams.set("state", "xyz");
    searchParams.set("error", "invalid_request");
    searchParams.set("error_description", "unsupported code_challenge_method");
    assertSpyCall(redirect, 0, {
      self: response,
      args: [expectedRedirectUrl],
    });
    assertSpyCalls(redirect, 1);
  } finally {
    errorHandler.restore();
  }
});

test(authorizeTests, "unsupported code_challenge_method", async () => {
  const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
  const request: OAuth2Request = fakeAuthorizeRequest();
  request.url.searchParams.set("code_challenge", "abc");
  request.url.searchParams.set("code_challenge_method", "plain");
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    await assertThrowsAsync(
      () => server.authorize(context, user),
      InvalidRequest,
      "unsupported code_challenge_method",
    );
    assertSpyCalls(errorHandler, 0);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
    const { searchParams } = expectedRedirectUrl;
    searchParams.set("state", "xyz");
    searchParams.set("error", "invalid_request");
    searchParams.set("error_description", "unsupported code_challenge_method");
    assertSpyCall(redirect, 0, {
      self: response,
      args: [expectedRedirectUrl],
    });
    assertSpyCalls(redirect, 1);
  } finally {
    errorHandler.restore();
  }
});

test(authorizeTests, "generateAuthorizationCode error", async () => {
  const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
  const generateAuthorizationCode: Stub<AuthorizationCodeGrant> = stub(
    authorizationCodeGrant,
    "generateAuthorizationCode",
    () => Promise.reject(new ServerError("generateAuthorizationCode failed")),
  );
  const request: OAuth2Request = fakeAuthorizeRequest();
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    await assertThrowsAsync(
      () => server.authorize(context, user),
      ServerError,
      "generateAuthorizationCode failed",
    );
    const call: SpyCall = assertSpyCall(generateAuthorizationCode, 0, {
      self: authorizationCodeGrant,
    });
    assertEquals(call.args.length, 1);
    assertAuthorizationCode(call.args[0], {
      redirectUri: "https://client.example.com/cb",
      client,
      user,
      scope,
    });
    assertSpyCalls(generateAuthorizationCode, 1);
    assertSpyCalls(errorHandler, 0);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
    const { searchParams } = expectedRedirectUrl;
    searchParams.set("state", "xyz");
    searchParams.set("error", "server_error");
    searchParams.set("error_description", "generateAuthorizationCode failed");
    assertSpyCall(redirect, 0, {
      self: response,
      args: [expectedRedirectUrl],
    });
    assertSpyCalls(redirect, 1);
  } finally {
    generateAuthorizationCode.restore();
    errorHandler.restore();
  }
});

test(authorizeTests, "success without PKCE", async () => {
  const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
  const generateAuthorizationCode: Stub<AuthorizationCodeGrant> = stub(
    authorizationCodeGrant,
    "generateAuthorizationCode",
    (authorizationCode: Partial<AuthorizationCode>) =>
      Promise.resolve({
        ...authorizationCode,
        code: "1",
      }),
  );
  const request: OAuth2Request = fakeAuthorizeRequest();
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    const result: Promise<AuthorizationCode> = server.authorize(context, user);
    assertEquals(Promise.resolve(result), result);
    const authorizationCode: AuthorizationCode = await result;
    assertAuthorizationCode(authorizationCode, {
      code: "1",
      redirectUri: "https://client.example.com/cb",
      client,
      user,
      scope,
    });
    const call: SpyCall = assertSpyCall(generateAuthorizationCode, 0, {
      self: authorizationCodeGrant,
    });
    assertEquals(call.args.length, 1);
    assertAuthorizationCode(call.args[0], {
      redirectUri: "https://client.example.com/cb",
      client,
      user,
      scope,
    });
    assertSpyCalls(generateAuthorizationCode, 1);
    assertSpyCalls(errorHandler, 0);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
    const { searchParams } = expectedRedirectUrl;
    searchParams.set("state", "xyz");
    searchParams.set("code", "1");
    assertSpyCall(redirect, 0, {
      self: response,
      args: [expectedRedirectUrl],
    });
    assertSpyCalls(redirect, 1);
  } finally {
    generateAuthorizationCode.restore();
    errorHandler.restore();
  }
});

test(authorizeTests, "success with PKCE", async () => {
  const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
  const generateAuthorizationCode: Stub<AuthorizationCodeGrant> = stub(
    authorizationCodeGrant,
    "generateAuthorizationCode",
    (authorizationCode: Partial<AuthorizationCode>) =>
      Promise.resolve({
        ...authorizationCode,
        code: "1",
      }),
  );
  const request: OAuth2Request = fakeAuthorizeRequest();
  const verifier: string = generateCodeVerifier();
  const challenge: string = challengeMethods.S256(verifier);
  request.url.searchParams.set("code_challenge", challenge);
  request.url.searchParams.set("code_challenge_method", "S256");
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    const result: Promise<AuthorizationCode> = server.authorize(context, user);
    assertEquals(Promise.resolve(result), result);
    const authorizationCode: AuthorizationCode = await result;
    assertAuthorizationCode(authorizationCode, {
      code: "1",
      redirectUri: "https://client.example.com/cb",
      challengeMethod: "S256",
      challenge,
      client,
      user,
      scope,
    });
    const call: SpyCall = assertSpyCall(generateAuthorizationCode, 0, {
      self: authorizationCodeGrant,
    });
    assertEquals(call.args.length, 1);
    assertAuthorizationCode(call.args[0], {
      redirectUri: "https://client.example.com/cb",
      challengeMethod: "S256",
      challenge,
      client,
      user,
      scope,
    });
    assertSpyCalls(generateAuthorizationCode, 1);
    assertSpyCalls(errorHandler, 0);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
    const { searchParams } = expectedRedirectUrl;
    searchParams.set("state", "xyz");
    searchParams.set("code", "1");
    assertSpyCall(redirect, 0, {
      self: response,
      args: [expectedRedirectUrl],
    });
    assertSpyCalls(redirect, 1);
  } finally {
    generateAuthorizationCode.restore();
    errorHandler.restore();
  }
});

test(authorizeTests, "success with parameters from request body", async () => {
  const errorHandler: Stub<OAuth2Server> = stub(server, "errorHandler");
  const generateAuthorizationCode: Stub<AuthorizationCodeGrant> = stub(
    authorizationCodeGrant,
    "generateAuthorizationCode",
    (authorizationCode: Partial<AuthorizationCode>) =>
      Promise.resolve({
        ...authorizationCode,
        code: "1",
      }),
  );
  const verifier: string = generateCodeVerifier();
  const challenge: string = challengeMethods.S256(verifier);
  const request: OAuth2Request = fakeAuthorizeRequest({
    "response_type": "code",
    "client_id": "1",
    "redirect_uri": "https://client.example.com/cb",
    "scope": "read write",
    "state": "xyz",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
  });
  request.url.search = "";
  const response = fakeResponse();
  const redirect: Spy<OAuth2Response> = spy(response, "redirect");
  const state: OAuth2State = {};
  const context: OAuth2Context = { request, response, state };
  try {
    const result: Promise<AuthorizationCode> = server.authorize(context, user);
    assertEquals(Promise.resolve(result), result);
    const authorizationCode: AuthorizationCode = await result;
    assertAuthorizationCode(authorizationCode, {
      code: "1",
      redirectUri: "https://client.example.com/cb",
      challengeMethod: "S256",
      challenge,
      client,
      user,
      scope,
    });
    const call: SpyCall = assertSpyCall(generateAuthorizationCode, 0, {
      self: authorizationCodeGrant,
    });
    assertEquals(call.args.length, 1);
    assertAuthorizationCode(call.args[0], {
      redirectUri: "https://client.example.com/cb",
      challengeMethod: "S256",
      challenge,
      client,
      user,
      scope,
    });
    assertSpyCalls(generateAuthorizationCode, 1);
    assertSpyCalls(errorHandler, 0);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    const expectedRedirectUrl: URL = new URL("https://client.example.com/cb");
    const { searchParams } = expectedRedirectUrl;
    searchParams.set("state", "xyz");
    searchParams.set("code", "1");
    assertSpyCall(redirect, 0, {
      self: response,
      args: [expectedRedirectUrl],
    });
    assertSpyCalls(redirect, 1);
  } finally {
    generateAuthorizationCode.restore();
    errorHandler.restore();
  }
});
