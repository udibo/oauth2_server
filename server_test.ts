import { RefreshTokenGrant } from "./grants/refresh_token.ts";
import { AccessToken, RefreshToken, Token } from "./models/token.ts";
import type { User } from "./models/user.ts";
import { Scope } from "./models/scope.ts";
import {
  assertEquals,
  assertSpyCall,
  assertSpyCallAsync,
  assertSpyCalls,
  assertThrowsAsync,
  delay,
  resolves,
  Spy,
  spy,
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
  InvalidScope,
  ServerError,
  UnauthorizedClient,
  UnsupportedGrantType,
} from "./errors.ts";
import {
  authorizeParameters,
  OAuth2AuthenticatedRequest,
  OAuth2AuthorizedRequest,
  OAuth2Request,
  OAuth2Response,
} from "./context.ts";
import { OAuth2Server, OAuth2ServerGrants } from "./server.ts";
import {
  fakeAuthorizeRequest,
  fakeResourceRequest,
  fakeResponse,
  fakeTokenRequest,
} from "./test_context.ts";
import { GrantServices } from "./grants/grant.ts";
import {
  assertClientUserScopeCall,
  assertError,
  assertScope,
  assertToken,
  Constructor,
} from "./asserts.ts";
import { AuthorizationCodeGrant } from "./grants/authorization_code.ts";
import { AuthorizationCode } from "./models/authorization_code.ts";
import { challengeMethods, generateCodeVerifier } from "./pkce.ts";
import {
  AuthorizationCodeService,
  client,
  ClientService,
  RefreshTokenService,
  scope,
  user,
} from "./services/test_services.ts";

const clientService: ClientService = new ClientService();
const tokenService: RefreshTokenService = new RefreshTokenService();
const authorizationCodeService: AuthorizationCodeService =
  new AuthorizationCodeService();
const services: GrantServices<Scope> = { clientService, tokenService };

const refreshTokenGrant = new RefreshTokenGrant({ services });
const authorizationCodeGrant = new AuthorizationCodeGrant({
  services: { ...services, authorizationCodeService },
});
const grants: OAuth2ServerGrants<Scope> = {
  "refresh_token": refreshTokenGrant,
  "authorization_code": authorizationCodeGrant,
};
const server = new OAuth2Server({
  grants,
  services: { tokenService },
});

const serverTests: TestSuite<void> = new TestSuite({
  name: "OAuth2Server",
});

const errorHandlerTests: TestSuite<void> = new TestSuite({
  name: "errorHandler",
  suite: serverTests,
});

test(errorHandlerTests, "OAuth2Error without optional properties", async () => {
  const request = fakeTokenRequest();
  const response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await server.errorHandler(
      request,
      response,
      new InvalidGrant(),
    ),
    undefined,
  );
  assertEquals(response.status, 400);
  assertEquals([...response.headers.entries()], []);
  assertEquals(response.body, {
    error: "invalid_grant",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

test(errorHandlerTests, "OAuth2Error with optional properties", async () => {
  const request = fakeTokenRequest();
  const response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await server.errorHandler(
      request,
      response,
      new InvalidGrant({
        message: "invalid refresh_token",
        uri: "https://example.com/",
      }),
    ),
    undefined,
  );
  assertEquals(response.status, 400);
  assertEquals([...response.headers.entries()], []);
  assertEquals(response.body, {
    error: "invalid_grant",
    error_description: "invalid refresh_token",
    error_uri: "https://example.com/",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

test(errorHandlerTests, "OAuth2Error with 401 status", async () => {
  const request = fakeTokenRequest();
  const response: OAuth2Response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await server.errorHandler(
      request,
      response,
      new InvalidClient("client authentication failed"),
    ),
    undefined,
  );
  assertEquals(response.status, 401);
  assertEquals([...response.headers.entries()], [
    ["www-authenticate", 'Basic realm="Service"'],
  ]);
  assertEquals(response.body, {
    error: "invalid_client",
    error_description: "client authentication failed",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

test(errorHandlerTests, "Error", async () => {
  const request = fakeTokenRequest();
  const response: OAuth2Response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await server.errorHandler(
      request,
      response,
      new Error("unknown"),
    ),
    undefined,
  );
  assertEquals(response.status, 500);
  assertEquals([...response.headers.entries()], []);
  assertEquals(response.body, {
    error: "server_error",
    error_description: "unknown",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

interface TokenTestContext {
  success: Spy<void>;
  error: Spy<void>;
  tokenSuccess: Stub<OAuth2Server>;
  tokenError: Stub<OAuth2Server>;
}

const tokenTests = new TestSuite({
  name: "token",
  suite: serverTests,
  beforeEach(context: TokenTestContext) {
    context.success = spy();
    context.error = spy();
    context.tokenSuccess = stub(
      server,
      "tokenSuccess",
      () => delay(0).then(context.success),
    );
    context.tokenError = stub(
      server,
      "tokenError",
      () => delay(0).then(context.error),
    );
  },
  afterEach({ tokenSuccess, tokenError }) {
    tokenSuccess.restore();
    tokenError.restore();
  },
});

async function tokenTestError(
  { success, error, tokenSuccess, tokenError }: TokenTestContext,
  request: OAuth2Request<Scope>,
  response: OAuth2Response,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
) {
  const redirect = spy(response, "redirect");
  await server.token(request, response);

  assertSpyCalls(tokenSuccess, 0);
  assertSpyCalls(success, 0);

  const call = assertSpyCall(tokenError, 0, { self: server });
  assertEquals(call.args.length, 3);
  assertEquals(call.args.slice(0, 2), [request, response]);
  assertError(call.args[2], ErrorClass, msgIncludes, msg);
  assertSpyCalls(tokenError, 1);
  assertSpyCalls(error, 1);

  assertEquals([...response.headers.entries()], []);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCalls(redirect, 0);
}

test(
  tokenTests,
  "method must be post",
  async (context) => {
    const request = fakeTokenRequest();
    request.method = "GET";
    const response = fakeResponse();
    await tokenTestError(
      context,
      request,
      response,
      InvalidRequest,
      "method must be POST",
    );
  },
);

test(
  tokenTests,
  "content-type header required",
  async (context) => {
    const request = fakeTokenRequest();
    const response = fakeResponse();
    request.headers.delete("Content-Type");
    await tokenTestError(
      context,
      request,
      response,
      InvalidRequest,
      "content-type header must be application/x-www-form-urlencoded",
    );
  },
);

test(
  tokenTests,
  "content-type header must be application/x-www-form-urlencoded",
  async (context) => {
    const request = fakeTokenRequest();
    request.headers.set("Content-Type", "application/json");
    const response = fakeResponse();
    request.headers.delete("Content-Type");
    await tokenTestError(
      context,
      request,
      response,
      InvalidRequest,
      "content-type header must be application/x-www-form-urlencoded",
    );
  },
);

test(tokenTests, "request body required", async (context) => {
  const request = fakeTokenRequest();
  const response = fakeResponse();
  await tokenTestError(
    context,
    request,
    response,
    InvalidRequest,
    "request body required",
  );
});

test(tokenTests, "grant_type parameter required", async (context) => {
  const request = fakeTokenRequest("");
  const response = fakeResponse();
  await tokenTestError(
    context,
    request,
    response,
    InvalidRequest,
    "grant_type parameter required",
  );
});

test(tokenTests, "invalid grant_type", async (context) => {
  const request = fakeTokenRequest("grant_type=fake");
  const response = fakeResponse();
  await tokenTestError(
    context,
    request,
    response,
    UnsupportedGrantType,
    "invalid grant_type",
  );
});

test(tokenTests, "client authentication failed", async (context) => {
  const getAuthenticatedClient = stub(
    refreshTokenGrant,
    "getAuthenticatedClient",
    () => Promise.reject(new InvalidClient("client authentication failed")),
  );
  try {
    const request = fakeTokenRequest("grant_type=refresh_token");
    const response = fakeResponse();
    await tokenTestError(
      context,
      request,
      response,
      InvalidClient,
      "client authentication failed",
    );
    assertSpyCall(getAuthenticatedClient, 0, {
      self: refreshTokenGrant,
      args: [request],
    });
    assertSpyCalls(getAuthenticatedClient, 1);
  } finally {
    getAuthenticatedClient.restore();
  }
});

test(
  tokenTests,
  "client is not authorized to use this grant_type",
  async (context) => {
    const getAuthenticatedClient = stub(
      refreshTokenGrant,
      "getAuthenticatedClient",
      resolves({
        ...client,
        grants: ["fake"],
      }),
    );
    try {
      const request = fakeTokenRequest(
        "grant_type=refresh_token",
      );
      const response = fakeResponse();
      await tokenTestError(
        context,
        request,
        response,
        UnauthorizedClient,
        "client is not authorized to use this grant_type",
      );
      assertSpyCall(getAuthenticatedClient, 0, {
        self: refreshTokenGrant,
        args: [request],
      });
      assertSpyCalls(getAuthenticatedClient, 1);
    } finally {
      getAuthenticatedClient.restore();
    }
  },
);

test(tokenTests, "grant token error", async (context) => {
  const token = stub(
    refreshTokenGrant,
    "token",
    () => Promise.reject(new InvalidGrant("invalid refresh_token")),
  );
  try {
    const request = fakeTokenRequest("grant_type=refresh_token");
    const response = fakeResponse();
    await tokenTestError(
      context,
      request,
      response,
      InvalidGrant,
      "invalid refresh_token",
    );
    assertSpyCall(token, 0, {
      self: refreshTokenGrant,
      args: [request, client],
    });
    assertSpyCalls(token, 1);
  } finally {
    token.restore();
  }
});

test(
  tokenTests,
  "returns refresh token",
  async ({ success, error, tokenSuccess, tokenError }) => {
    const refreshToken: RefreshToken<Scope> = {
      accessToken: "foo",
      refreshToken: "bar",
      client,
      user,
      scope,
    };
    const token = stub(
      refreshTokenGrant,
      "token",
      () => Promise.resolve(refreshToken),
    );
    try {
      const request = fakeTokenRequest("grant_type=refresh_token");
      const response = fakeResponse();
      const redirect = spy(response, "redirect");
      await server.token(request, response);

      assertSpyCalls(tokenError, 0);
      assertSpyCalls(error, 0);

      assertSpyCall(tokenSuccess, 0, {
        self: server,
        args: [request, response],
      });
      assertSpyCalls(tokenSuccess, 1);
      assertSpyCalls(success, 1);
      assertToken(request.token, refreshToken);

      assertEquals(response.status, undefined);
      assertEquals(response.body, undefined);
      assertSpyCalls(redirect, 0);
    } finally {
      token.restore();
    }
  },
);

const bearerTokenTests = new TestSuite({
  name: "bearerToken",
  suite: serverTests,
});

test(bearerTokenTests, "without optional token properties", () => {
  const accessToken: AccessToken<Scope> = {
    accessToken: "foo",
    client,
    user,
  };
  assertEquals(server.bearerToken(accessToken), {
    "token_type": "Bearer",
    "access_token": "foo",
    "expires_in": tokenService.accessTokenLifetime,
  });
});

test(bearerTokenTests, "with optional token properties", () => {
  const refreshToken: RefreshToken<Scope> = {
    accessToken: "foo",
    refreshToken: "bar",
    client,
    user,
    scope,
  };
  assertEquals(server.bearerToken(refreshToken), {
    "token_type": "Bearer",
    "access_token": "foo",
    "expires_in": tokenService.accessTokenLifetime,
    "refresh_token": "bar",
    scope: scope.toJSON(),
  });
});

test(serverTests, "tokenResponse", async () => {
  const request = fakeTokenRequest();
  const response = fakeResponse();
  const redirect = spy(response, "redirect");
  await server.tokenResponse(request, response);
  assertEquals([...response.headers.entries()], [
    ["cache-control", "no-store"],
    ["content-type", "application/json;charset=UTF-8"],
    ["pragma", "no-cache"],
  ]);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCalls(redirect, 0);
});

test(serverTests, "tokenSuccess", async () => {
  const tokenResponseAwait = spy();
  const tokenResponse = stub(
    server,
    "tokenResponse",
    () => delay(0).then(tokenResponseAwait),
  );
  const bearerToken = spy(server, "bearerToken");
  try {
    const request = fakeTokenRequest(
      "grant_type=refresh_token",
    ) as OAuth2AuthenticatedRequest<Scope>;
    request.token = {
      accessToken: "foo",
      refreshToken: "bar",
      client,
      user,
      scope,
    };
    const response = fakeResponse();
    const redirect: Spy<OAuth2Response> = spy(response, "redirect");
    await server.tokenSuccess(request, response);

    assertSpyCall(tokenResponse, 0, {
      args: [request, response],
    });
    assertSpyCalls(tokenResponse, 1);
    assertSpyCalls(tokenResponseAwait, 1);

    const call = assertSpyCall(bearerToken, 0, {
      args: [request.token],
    });
    assertSpyCalls(bearerToken, 1);

    assertEquals(response.status, 200);
    assertEquals(response.body, call.returned);
    assertSpyCalls(redirect, 0);
  } finally {
    tokenResponse.restore();
  }
});

test(serverTests, "tokenError handles error", async () => {
  const tokenResponseAwait = spy();
  const tokenResponse = stub(
    server,
    "tokenResponse",
    () => delay(0).then(tokenResponseAwait),
  );
  const errorHandlerAwait = spy();
  const errorHandler = stub(
    server,
    "errorHandler",
    () => delay(0).then(errorHandlerAwait),
  );
  try {
    const request = fakeTokenRequest(
      "grant_type=refresh_token",
    );
    const response = fakeResponse();
    const redirect: Spy<OAuth2Response> = spy(response, "redirect");
    const error = new InvalidGrant("invalid refresh_token");
    await server.tokenError(request, response, error);

    assertSpyCall(tokenResponse, 0, {
      args: [request, response],
    });
    assertSpyCalls(tokenResponse, 1);
    assertSpyCalls(tokenResponseAwait, 1);

    assertSpyCall(errorHandler, 0, {
      args: [request, response, error],
    });
    assertSpyCalls(errorHandler, 1);
    assertSpyCalls(errorHandlerAwait, 1);

    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);
  } finally {
    tokenResponse.restore();
    errorHandler.restore();
  }
});

const getAccessTokenTests: TestSuite<void> = new TestSuite({
  name: "getAccessToken",
  suite: serverTests,
});

test(getAccessTokenTests, "GET request with no access token", async () => {
  const request = fakeResourceRequest("");
  const result = server.getAccessToken(request);
  assertEquals(Promise.resolve(result), result);
  assertEquals(await result, null);
});

test(
  getAccessTokenTests,
  "GET request with access token in authorization header",
  async () => {
    const request = fakeResourceRequest("abc");
    const result = server.getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);

test(getAccessTokenTests, "POST request with no access token", async () => {
  const request = fakeResourceRequest("");
  const result = server.getAccessToken(request);
  assertEquals(Promise.resolve(result), result);
  assertEquals(await result, null);
});

test(
  getAccessTokenTests,
  "POST request with access token in authorization header",
  async () => {
    const request = fakeResourceRequest("abc", {});
    const result = server.getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);

test(
  getAccessTokenTests,
  "POST request with access token in request body",
  async () => {
    const request = fakeResourceRequest("", {
      access_token: "abc",
    });
    const result = server.getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);

test(
  getAccessTokenTests,
  "POST request with access token in authorization header and body",
  async () => {
    const request = fakeResourceRequest("abc", {
      access_token: "def",
    });
    const result = server.getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);

const getTokenTests: TestSuite<void> = new TestSuite({
  name: "getToken",
  suite: serverTests,
});

test(getTokenTests, "token service required", async () => {
  const { services } = server;
  try {
    server.services = {};
    await assertThrowsAsync(
      () => server.getToken("123"),
      ServerError,
      "token service required",
    );
  } finally {
    server.services = services;
  }
});

test(getTokenTests, "invalid access_token", async () => {
  const getToken = stub(
    tokenService,
    "getToken",
    resolves(undefined),
  );

  try {
    await assertThrowsAsync(
      () => server.getToken("123"),
      AccessDenied,
      "invalid access_token",
    );

    assertSpyCall(getToken, 0, {
      self: tokenService,
      args: ["123"],
    });
    assertSpyCalls(getToken, 1);
  } finally {
    getToken.restore();
  }
});

test(getTokenTests, "expired access_token", async () => {
  const getToken = stub(
    tokenService,
    "getToken",
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
    await assertThrowsAsync(
      () => server.getToken("123"),
      AccessDenied,
      "invalid access_token",
    );

    assertSpyCall(getToken, 0, {
      self: tokenService,
      args: ["123"],
    });
    assertSpyCalls(getToken, 1);
  } finally {
    getToken.restore();
  }
});

interface AuthenticateTestContext {
  success: Spy<void>;
  error: Spy<void>;
  authenticateSuccess: Stub<OAuth2Server>;
  authenticateError: Stub<OAuth2Server>;
}

const authenticateTests = new TestSuite({
  name: "authenticate",
  suite: serverTests,
  beforeEach(context: AuthenticateTestContext) {
    context.success = spy();
    context.error = spy();
    context.authenticateSuccess = stub(
      server,
      "authenticateSuccess",
      () => delay(0).then(context.success),
    );
    context.authenticateError = stub(
      server,
      "authenticateError",
      () => delay(0).then(context.error),
    );
  },
  afterEach({ authenticateSuccess, authenticateError }) {
    authenticateSuccess.restore();
    authenticateError.restore();
  },
});

async function authenticateTestError(
  { success, error, authenticateSuccess, authenticateError }:
    AuthenticateTestContext,
  request: OAuth2Request<Scope>,
  response: OAuth2Response,
  customAccessToken: string | null,
  acceptedScope?: Scope,
  expectedToken?: Token<Scope>,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
) {
  const redirect = spy(response, "redirect");
  const next = spy();
  const getCustomAccessToken = spy(() => Promise.resolve(customAccessToken));
  const getAccessToken = spy(server, "getAccessToken");
  try {
    await server.authenticate(
      request,
      response,
      next,
      getCustomAccessToken,
      acceptedScope,
    );
  } finally {
    getAccessToken.restore();
  }

  await assertSpyCallAsync(getCustomAccessToken, 0, { args: [request] });
  assertSpyCalls(getCustomAccessToken, 1);

  if (customAccessToken) {
    assertSpyCalls(getAccessToken, 0);
  } else {
    assertSpyCall(getAccessToken, 0, { args: [request] });
    assertSpyCalls(getAccessToken, 1);
  }

  assertSpyCalls(authenticateSuccess, 0);
  assertSpyCalls(success, 0);

  const call = assertSpyCall(authenticateError, 0, { self: server });
  assertEquals(call.args.length, 3);
  assertEquals(call.args.slice(0, 2), [request, response]);
  assertError(call.args[2], ErrorClass, msgIncludes, msg);
  assertSpyCalls(authenticateError, 1);
  assertSpyCalls(error, 1);

  assertScope(request.acceptedScope, acceptedScope);
  assertToken(request.token, expectedToken);

  assertEquals([...response.headers.entries()], []);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCalls(redirect, 0);

  assertSpyCalls(next, 0);
}

test(authenticateTests, "authentication required", async (context) => {
  const request = fakeResourceRequest("");
  const response = fakeResponse();
  await authenticateTestError(
    context,
    request,
    response,
    null,
    scope,
    undefined,
    AccessDenied,
    "authentication required",
  );
});

test(
  authenticateTests,
  "invalid access_token from request",
  async (context) => {
    const getToken = stub(
      server,
      "getToken",
      () => Promise.reject(new AccessDenied("invalid access_token")),
    );

    try {
      const request = fakeResourceRequest("123");
      const response = fakeResponse();
      await authenticateTestError(
        context,
        request,
        response,
        null,
        scope,
        undefined,
        AccessDenied,
        "invalid access_token",
      );

      assertSpyCall(getToken, 0, {
        self: server,
        args: ["123"],
      });
      assertSpyCalls(getToken, 1);
    } finally {
      getToken.restore();
    }
  },
);

test(
  authenticateTests,
  "invalid access_token from custom getAccessToken",
  async (context) => {
    const getToken = stub(
      server,
      "getToken",
      () => Promise.reject(new AccessDenied("invalid access_token")),
    );

    try {
      const request = fakeResourceRequest("123");
      const response = fakeResponse();
      await authenticateTestError(
        context,
        request,
        response,
        "456",
        scope,
        undefined,
        AccessDenied,
        "invalid access_token",
      );

      assertSpyCall(getToken, 0, {
        self: server,
        args: ["456"],
      });
      assertSpyCalls(getToken, 1);
    } finally {
      getToken.restore();
    }
  },
);

test(authenticateTests, "insufficient scope", async (context) => {
  const getToken = spy(
    server,
    "getToken",
  );

  try {
    const request = fakeResourceRequest("123");
    const response = fakeResponse();
    const acceptedScope = new Scope("read write delete");
    const expectedToken = {
      accessToken: "123",
      client,
      user,
      scope,
    };
    await authenticateTestError(
      context,
      request,
      response,
      null,
      acceptedScope,
      expectedToken,
      AccessDenied,
      "insufficient scope",
    );
    assertSpyCall(getToken, 0, {
      self: server,
      args: ["123"],
    });
    assertSpyCalls(getToken, 1);
  } finally {
    getToken.restore();
  }
});

async function authenticateTest(
  { success, error, authenticateSuccess, authenticateError }:
    AuthenticateTestContext,
  request: OAuth2Request<Scope>,
  response: OAuth2Response,
  customAccessToken: string | null,
  acceptedScope?: Scope,
  expectedToken?: Token<Scope>,
  cached?: boolean,
) {
  const getToken = spy(server, "getToken");
  const getCustomAccessToken = spy(() => Promise.resolve(customAccessToken));
  const getAccessToken = spy(server, "getAccessToken");
  const redirect = spy(response, "redirect");
  const next = spy();

  try {
    await server.authenticate(
      request,
      response,
      next,
      getCustomAccessToken,
      acceptedScope,
    );
  } finally {
    getToken.restore();
    getAccessToken.restore();
  }

  if (cached) {
    assertSpyCalls(getAccessToken, 0);
    assertSpyCalls(getToken, 0);
  } else {
    await assertSpyCallAsync(getCustomAccessToken, 0, { args: [request] });
    assertSpyCalls(getCustomAccessToken, 1);

    if (customAccessToken) {
      assertSpyCalls(getAccessToken, 0);
    } else {
      assertSpyCall(getAccessToken, 0, { args: [request] });
      assertSpyCalls(getAccessToken, 1);
    }

    assertSpyCall(getToken, 0, {
      self: server,
      args: [customAccessToken || "123"],
    });
    assertSpyCalls(getToken, 1);
  }

  assertSpyCall(authenticateSuccess, 0, {
    self: server,
    args: [request, response, next],
  });
  assertSpyCalls(authenticateSuccess, 1);
  assertSpyCalls(success, 1);

  assertSpyCalls(authenticateError, 0);
  assertSpyCalls(error, 0);

  assertScope(request.acceptedScope, acceptedScope);
  assertToken(request.token, expectedToken);

  assertEquals([...response.headers.entries()], []);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCalls(redirect, 0);

  assertSpyCalls(next, 0);
}

test(authenticateTests, "without scope", async (context) => {
  const request = fakeResourceRequest("123");
  const response = fakeResponse();
  const expectedToken = {
    accessToken: "123",
    client,
    user,
    scope,
  };
  await authenticateTest(
    context,
    request,
    response,
    null,
    undefined,
    expectedToken,
  );
});

test(authenticateTests, "with scope", async (context) => {
  const request = fakeResourceRequest("123");
  const response = fakeResponse();
  const expectedToken = {
    accessToken: "123",
    client,
    user,
    scope,
  };
  await authenticateTest(
    context,
    request,
    response,
    null,
    scope,
    expectedToken,
  );
});

test(authenticateTests, "uses custom access token", async (context) => {
  const request = fakeResourceRequest("123");
  const response = fakeResponse();
  const expectedToken = {
    accessToken: "456",
    client,
    user,
    scope,
  };
  await authenticateTest(
    context,
    request,
    response,
    "456",
    scope,
    expectedToken,
  );
});

test(authenticateTests, "re-uses token stored in state", async (context) => {
  const request = fakeResourceRequest("123");
  const response = fakeResponse();
  const expectedToken = {
    accessToken: "123",
    client,
    user,
    scope,
  };
  request.token = expectedToken;
  await authenticateTest(
    context,
    request,
    response,
    null,
    scope,
    expectedToken,
    true,
  );
});

const authenticateResponseTests = new TestSuite({
  name: "authenticateResponse",
  suite: serverTests,
});

test(authenticateResponseTests, "without accepted scope", async () => {
  const request = fakeResourceRequest("123");
  request.token = {
    accessToken: "123",
    client,
    user,
    scope,
  };
  const response = fakeResponse();
  const redirect = spy(response, "redirect");
  await server.authenticateResponse(request, response);
  assertEquals([...response.headers.entries()], [
    ["x-accepted-oauth-scopes", ""],
    ["x-oauth-scopes", "read write"],
  ]);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCalls(redirect, 0);
});

test(authenticateResponseTests, "with accepted scope", async () => {
  const request = fakeResourceRequest("123");
  request.token = {
    accessToken: "123",
    client,
    user,
    scope,
  };
  request.acceptedScope = new Scope("read");
  const response = fakeResponse();
  const redirect = spy(response, "redirect");
  await server.authenticateResponse(request, response);
  assertEquals([...response.headers.entries()], [
    ["x-accepted-oauth-scopes", "read"],
    ["x-oauth-scopes", "read write"],
  ]);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCalls(redirect, 0);
});

test(authenticateResponseTests, "without scope", async () => {
  const request = fakeResourceRequest("123");
  request.token = {
    accessToken: "123",
    client,
    user,
  };
  request.acceptedScope = new Scope("read");
  const response = fakeResponse();
  const redirect = spy(response, "redirect");
  await server.authenticateResponse(request, response);
  assertEquals([...response.headers.entries()], [
    ["x-accepted-oauth-scopes", "read"],
    ["x-oauth-scopes", ""],
  ]);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCalls(redirect, 0);
});

test(serverTests, "authenticateSuccess", async () => {
  const authenticateResponseAwait = spy();
  const authenticateResponse = stub(
    server,
    "authenticateResponse",
    () => delay(0).then(authenticateResponseAwait),
  );
  try {
    const request = fakeResourceRequest("123") as OAuth2AuthenticatedRequest<
      Scope
    >;
    request.token = {
      accessToken: "123",
      client,
      user,
      scope,
    };
    const response = fakeResponse();
    const redirect = spy(response, "redirect");
    const nextAwait = spy();
    const next = spy(() => delay(0).then(nextAwait));
    await server.authenticateSuccess(request, response, next);

    assertSpyCall(authenticateResponse, 0, {
      args: [request, response],
    });
    assertSpyCalls(authenticateResponse, 1);
    assertSpyCalls(authenticateResponseAwait, 1);

    assertSpyCall(next, 0, { args: [] });
    assertSpyCalls(next, 1);
    assertSpyCalls(nextAwait, 1);

    assertEquals([...response.headers.entries()], []);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);
  } finally {
    authenticateResponse.restore();
  }
});

test(serverTests, "authenticateError", async () => {
  const authenticateResponseAwait = spy();
  const authenticateResponse = stub(
    server,
    "authenticateResponse",
    () => delay(0).then(authenticateResponseAwait),
  );
  const errorHandlerAwait = spy();
  const errorHandler = stub(
    server,
    "errorHandler",
    () => delay(0).then(errorHandlerAwait),
  );
  try {
    const request = fakeResourceRequest("123") as OAuth2AuthenticatedRequest<
      Scope
    >;
    request.token = {
      accessToken: "123",
      client,
      user,
      scope,
    };
    const response = fakeResponse();
    const redirect: Spy<OAuth2Response> = spy(response, "redirect");
    const error = new AccessDenied("insufficient scope");
    await server.authenticateError(request, response, error);

    assertSpyCall(authenticateResponse, 0, {
      args: [request, response],
    });
    assertSpyCalls(authenticateResponse, 1);
    assertSpyCalls(authenticateResponseAwait, 1);

    assertSpyCall(errorHandler, 0, {
      args: [request, response, error],
    });
    assertSpyCalls(errorHandler, 1);
    assertSpyCalls(errorHandlerAwait, 1);

    assertEquals([...response.headers.entries()], []);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);
  } finally {
    authenticateResponse.restore();
    errorHandler.restore();
  }
});

interface AuthorizeTestContext {
  success: Spy<void>;
  error: Spy<void>;
  authorizeSuccess: Stub<OAuth2Server>;
  authorizeError: Stub<OAuth2Server>;
  setAuthorizationAwait: Spy<void>;
  setAuthorization: Spy<void>;
  login: Spy<void>;
  consent: Spy<void>;
}

const authorizeTests = new TestSuite({
  name: "authorize",
  suite: serverTests,
  beforeEach(context: AuthorizeTestContext) {
    context.success = spy();
    context.error = spy();
    context.authorizeSuccess = stub(
      server,
      "authorizeSuccess",
      () => delay(0).then(context.success),
    );
    context.authorizeError = stub(
      server,
      "authorizeError",
      () => delay(0).then(context.error),
    );

    context.setAuthorizationAwait = spy();
    context.setAuthorization = spy(() =>
      delay(0).then(context.setAuthorizationAwait)
    );

    context.login = spy();
    context.consent = spy();
  },
  afterEach({ authorizeSuccess, authorizeError }) {
    authorizeSuccess.restore();
    authorizeError.restore();
  },
});

async function authorizeTestError(
  context: AuthorizeTestContext,
  request: OAuth2Request<Scope>,
  response: OAuth2Response,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
) {
  const {
    success,
    error,
    authorizeSuccess,
    authorizeError,
    setAuthorization,
    login,
    consent,
  } = context;
  const redirect = spy(response, "redirect");
  await server.authorize(request, response, setAuthorization, login, consent);

  assertSpyCalls(authorizeSuccess, 0);
  assertSpyCalls(success, 0);

  const call = assertSpyCall(authorizeError, 0, { self: server });
  assertEquals(call.args.length, 5);
  assertEquals(call.args.slice(0, 2), [request, response]);
  assertError(call.args[2], ErrorClass, msgIncludes, msg);
  assertEquals(call.args.slice(3), [login, consent]);
  assertSpyCalls(authorizeError, 1);
  assertSpyCalls(error, 1);

  assertEquals(request.authorizeParameters, await authorizeParameters(request));

  assertEquals([...response.headers.entries()], []);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCalls(redirect, 0);

  assertSpyCalls(login, 0);
  assertSpyCalls(consent, 0);
}

async function authorizeTestErrorNoRedirect(
  context: AuthorizeTestContext,
  request: OAuth2Request<Scope>,
  response: OAuth2Response,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
) {
  await authorizeTestError(
    context,
    request,
    response,
    ErrorClass,
    msgIncludes,
    msg,
  );

  assertEquals(request.redirectUrl, undefined);

  const { setAuthorization } = context;
  assertSpyCalls(setAuthorization, 0);
}

test(
  authorizeTests,
  "missing authorization code grant",
  async (context) => {
    const { grants } = server;
    try {
      server.grants = { "refresh_token": refreshTokenGrant };
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorNoRedirect(
        context,
        request,
        response,
        ServerError,
        "missing authorization code grant",
      );
    } finally {
      server.grants = grants;
    }
  },
);

test(
  authorizeTests,
  "client_id parameter required",
  async (context) => {
    const request = fakeAuthorizeRequest();
    request.url.searchParams.delete("client_id");
    const response = fakeResponse();
    await authorizeTestErrorNoRedirect(
      context,
      request,
      response,
      InvalidRequest,
      "client_id parameter required",
    );
  },
);

test(
  authorizeTests,
  "client not found",
  async (context) => {
    const clientServiceGet: Stub<ClientService> = stub(
      clientService,
      "get",
      resolves(undefined),
    );
    try {
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorNoRedirect(
        context,
        request,
        response,
        InvalidClient,
        "client not found",
      );
    } finally {
      clientServiceGet.restore();
    }
  },
);

test(
  authorizeTests,
  "client is not authorized to use the authorization code grant type",
  async (context) => {
    const clientServiceGet: Stub<ClientService> = stub(
      clientService,
      "get",
      resolves({ ...client, grants: ["refresh_token"] }),
    );
    try {
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorNoRedirect(
        context,
        request,
        response,
        UnauthorizedClient,
        "client is not authorized to use the authorization code grant type",
      );
    } finally {
      clientServiceGet.restore();
    }
  },
);

test(authorizeTests, "no authorized redirect_uri", async (context) => {
  const clientServiceGet: Stub<ClientService> = stub(
    clientService,
    "get",
    resolves({ ...client, redirectUris: [] }),
  );
  try {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorNoRedirect(
      context,
      request,
      response,
      UnauthorizedClient,
      "no authorized redirect_uri",
    );
  } finally {
    clientServiceGet.restore();
  }
});

test(authorizeTests, "redirect_uri not authorized", async (context) => {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("redirect_uri", "http://client.example.com/cb");
  const response = fakeResponse();
  await authorizeTestErrorNoRedirect(
    context,
    request,
    response,
    UnauthorizedClient,
    "redirect_uri not authorized",
  );
});

async function authorizeTestErrorRedirect(
  context: AuthorizeTestContext,
  request: OAuth2Request<Scope>,
  response: OAuth2Response,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
) {
  await authorizeTestError(
    context,
    request,
    response,
    ErrorClass,
    msgIncludes,
    msg,
  );

  const expectedRedirectUrl = new URL("https://client.example.com/cb");
  if (request.authorizeParameters?.state) {
    expectedRedirectUrl.searchParams.set(
      "state",
      request.authorizeParameters?.state,
    );
  }
  assertEquals(request.redirectUrl, expectedRedirectUrl);
}

async function authorizeTestErrorPreAuthorization(
  context: AuthorizeTestContext,
  request: OAuth2Request<Scope>,
  response: OAuth2Response,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
) {
  await authorizeTestErrorRedirect(
    context,
    request,
    response,
    ErrorClass,
    msgIncludes,
    msg,
  );

  const { setAuthorization } = context;
  assertSpyCalls(setAuthorization, 0);
}

test(authorizeTests, "state required", async (context) => {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.delete("state");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    context,
    request,
    response,
    InvalidRequest,
    "state required",
  );
});

test(authorizeTests, "response_type required", async (context) => {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.delete("response_type");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    context,
    request,
    response,
    InvalidRequest,
    "response_type required",
  );
});

test(authorizeTests, "response_type not supported", async (context) => {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("response_type", "token");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    context,
    request,
    response,
    InvalidRequest,
    "response_type not supported",
  );
});

test(
  authorizeTests,
  "code_challenge required when code_challenge_method is set",
  async (context) => {
    const request = fakeAuthorizeRequest();
    request.url.searchParams.set("code_challenge_method", "S256");
    const response = fakeResponse();
    await authorizeTestErrorPreAuthorization(
      context,
      request,
      response,
      InvalidRequest,
      "code_challenge required when code_challenge_method is set",
    );
  },
);

test(authorizeTests, "code_challenge_method required", async (context) => {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("code_challenge", "abc");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    context,
    request,
    response,
    InvalidRequest,
    "unsupported code_challenge_method",
  );
});

test(authorizeTests, "unsupported code_challenge_method", async (context) => {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("code_challenge", "abc");
  request.url.searchParams.set("code_challenge_method", "plain");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    context,
    request,
    response,
    InvalidRequest,
    "unsupported code_challenge_method",
  );
});

async function authorizeTestErrorAuthorized(
  context: AuthorizeTestContext,
  request: OAuth2Request<Scope>,
  response: OAuth2Response,
  user?: User,
  authorizedScope?: Scope,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
) {
  context.setAuthorization = spy((request: OAuth2Request<Scope>) => {
    request.user = user;
    request.authorizedScope = authorizedScope;
    return delay(0).then(context.setAuthorizationAwait);
  });
  await authorizeTestErrorRedirect(
    context,
    request,
    response,
    ErrorClass,
    msgIncludes,
    msg,
  );

  const {
    setAuthorization,
    setAuthorizationAwait,
  } = context;
  assertSpyCalls(setAuthorization, 1);
  assertSpyCalls(setAuthorizationAwait, 1);
}

test(authorizeTests, "authentication required with PKCE", async (context) => {
  const request = fakeAuthorizeRequest();
  const verifier: string = generateCodeVerifier();
  const challenge: string = challengeMethods.S256(verifier);
  request.url.searchParams.set("code_challenge", challenge);
  request.url.searchParams.set("code_challenge_method", "S256");
  const response = fakeResponse();
  await authorizeTestErrorAuthorized(
    context,
    request,
    response,
    undefined,
    undefined,
    AccessDenied,
    "authentication required",
  );
});

test(
  authorizeTests,
  "authentication required without PKCE",
  async (context) => {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorAuthorized(
      context,
      request,
      response,
      undefined,
      undefined,
      AccessDenied,
      "authentication required",
    );
  },
);

test(
  authorizeTests,
  "scope not accepted",
  async (context) => {
    const acceptedScope = stub(
      authorizationCodeGrant,
      "acceptedScope",
      () => Promise.reject(new InvalidScope("invalid scope")),
    );
    try {
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorAuthorized(
        context,
        request,
        response,
        user,
        undefined,
        InvalidScope,
        "invalid scope",
      );
    } finally {
      acceptedScope.restore();
    }
  },
);

test(
  authorizeTests,
  "not authorized",
  async (context) => {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorAuthorized(
      context,
      request,
      response,
      user,
      undefined,
      AccessDenied,
      "not authorized",
    );
  },
);

test(
  authorizeTests,
  "not fully authorized",
  async (context) => {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorAuthorized(
      context,
      request,
      response,
      user,
      new Scope("read"),
      AccessDenied,
      "not authorized",
    );
  },
);

test(authorizeTests, "generateAuthorizationCode error", async (context) => {
  const generateAuthorizationCode: Stub<AuthorizationCodeGrant> = stub(
    authorizationCodeGrant,
    "generateAuthorizationCode",
    () => Promise.reject(new ServerError("generateAuthorizationCode failed")),
  );
  try {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorAuthorized(
      context,
      request,
      response,
      user,
      scope,
      ServerError,
      "generateAuthorizationCode failed",
    );
  } finally {
    generateAuthorizationCode.restore();
  }
});

async function authorizeTest(
  context: AuthorizeTestContext,
  request: OAuth2Request<Scope>,
  response: OAuth2Response,
  code: string,
  user: User,
  authorizedScope?: Scope,
  challenge?: string,
  challengeMethod?: string,
) {
  context.setAuthorization = spy((request: OAuth2Request<Scope>) => {
    request.user = user;
    request.authorizedScope = authorizedScope;
    return delay(0).then(context.setAuthorizationAwait);
  });

  const {
    success,
    error,
    authorizeSuccess,
    authorizeError,
    setAuthorization,
    setAuthorizationAwait,
    login,
    consent,
  } = context;
  const redirect = spy(response, "redirect");

  const generateAuthorizationCode: Stub<AuthorizationCodeGrant> = stub(
    authorizationCodeGrant,
    "generateAuthorizationCode",
    (authorizationCode: Omit<AuthorizationCode<Scope>, "code" | "expiresAt">) =>
      Promise.resolve({
        ...authorizationCode,
        code,
      }),
  );
  const acceptedScope = stub(
    authorizationCodeGrant,
    "acceptedScope",
    () => Promise.resolve(authorizedScope),
  );
  try {
    await server.authorize(request, response, setAuthorization, login, consent);
  } finally {
    generateAuthorizationCode.restore();
    acceptedScope.restore();
  }

  assertSpyCalls(authorizeError, 0);
  assertSpyCalls(error, 0);

  assertSpyCall(authorizeSuccess, 0, {
    self: server,
    args: [request, response],
  });
  assertSpyCalls(authorizeSuccess, 1);
  assertSpyCalls(success, 1);

  assertEquals(request.authorizeParameters, await authorizeParameters(request));
  const expectedRedirectUrl = new URL("https://client.example.com/cb");
  if (request.authorizeParameters?.state) {
    expectedRedirectUrl.searchParams.set(
      "state",
      request.authorizeParameters?.state,
    );
  }
  expectedRedirectUrl.searchParams.set("code", code);
  assertEquals(request.redirectUrl, expectedRedirectUrl);

  assertClientUserScopeCall(
    acceptedScope,
    0,
    authorizationCodeGrant,
    client,
    user,
    scope,
  );
  assertSpyCalls(acceptedScope, 1);

  const expectedOptions: Omit<AuthorizationCode<Scope>, "code" | "expiresAt"> =
    {
      client,
      user,
      scope: authorizedScope,
      redirectUri: "https://client.example.com/cb",
    };
  if (challenge) expectedOptions.challenge = challenge;
  if (challengeMethod) expectedOptions.challengeMethod = challengeMethod;
  assertSpyCall(generateAuthorizationCode, 0, {
    self: authorizationCodeGrant,
    args: [expectedOptions],
  });
  assertSpyCalls(generateAuthorizationCode, 1);

  assertEquals([...response.headers.entries()], []);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCalls(redirect, 0);

  assertSpyCalls(login, 0);
  assertSpyCalls(consent, 0);

  assertSpyCalls(setAuthorization, 1);
  assertSpyCalls(setAuthorizationAwait, 1);
}

test(authorizeTests, "success without PKCE", async (context) => {
  const request = fakeAuthorizeRequest();
  const response = fakeResponse();
  await authorizeTest(
    context,
    request,
    response,
    "123",
    user,
    new Scope("read"),
  );
});

test(authorizeTests, "success with PKCE", async (context) => {
  const request = fakeAuthorizeRequest();
  const verifier: string = generateCodeVerifier();
  const challenge: string = challengeMethods.S256(verifier);
  request.url.searchParams.set("code_challenge", challenge);
  request.url.searchParams.set("code_challenge_method", "S256");
  const response = fakeResponse();
  await authorizeTest(
    context,
    request,
    response,
    "123",
    user,
    new Scope("read"),
    challenge,
    "S256",
  );
});

test(serverTests, "authorizeSuccess", async () => {
  const request = fakeAuthorizeRequest();
  const expectedRedirectUrl = new URL(
    "https://client.example.com/cb?state=xyz&code=123",
  );
  request.redirectUrl = new URL(expectedRedirectUrl.toString());
  const response = fakeResponse();
  const redirectAwait = spy();
  const redirect = stub(
    response,
    "redirect",
    () => delay(0).then(redirectAwait),
  );
  await server.authorizeSuccess(
    request as OAuth2AuthorizedRequest<Scope>,
    response,
  );

  assertEquals([...response.headers.entries()], []);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCall(redirect, 0, {
    self: response,
    args: [expectedRedirectUrl],
  });
  assertSpyCalls(redirect, 1);
});

interface AuthorizeTestContext {
  request: OAuth2Request<Scope>;
  response: OAuth2Response;
  redirect: Stub<OAuth2Response>;
  redirectAwait: Spy<void>;
  login: Spy<void>;
  loginAwait: Spy<void>;
  consent: Spy<void>;
  consentAwait: Spy<void>;
  errorHandler: Stub<OAuth2Server>;
  errorHandlerAwait: Spy<void>;
}

const authorizeErrorTests = new TestSuite({
  name: "authorizeError",
  suite: serverTests,
  async beforeEach(context: AuthorizeTestContext) {
    context.request = fakeAuthorizeRequest();
    context.request.authorizeParameters = await authorizeParameters(
      context.request,
    );
    context.request.redirectUrl = new URL(
      "https://client.example.com/cb?state=xyz",
    );
    context.response = fakeResponse();
    context.redirectAwait = spy();
    context.redirect = stub(
      context.response,
      "redirect",
      () => delay(0).then(context.redirectAwait),
    );
    context.loginAwait = spy();
    context.login = spy(() => delay(0).then(context.loginAwait));
    context.consentAwait = spy();
    context.consent = spy(() => delay(0).then(context.consentAwait));
    context.errorHandlerAwait = spy();
    context.errorHandler = stub(
      server,
      "errorHandler",
      () => delay(0).then(context.errorHandlerAwait),
    );
  },
  afterEach({ errorHandler }) {
    errorHandler.restore();
  },
});

test(authorizeErrorTests, "non access_denied error with redirectUrl", async ({
  request,
  response,
  redirect,
  redirectAwait,
  login,
  consent,
  errorHandler,
}) => {
  const expectedRedirectUrl = new URL(request.redirectUrl!.toString());
  expectedRedirectUrl.searchParams.set("error", "invalid_request");
  expectedRedirectUrl.searchParams.set("error_description", "not valid");

  const error = new InvalidRequest("not valid");
  await server.authorizeError(request, response, error, login, consent);

  assertEquals([...response.headers.entries()], []);
  assertEquals(response.status, undefined);
  assertEquals(response.body, undefined);
  assertSpyCall(redirect, 0, {
    self: response,
    args: [expectedRedirectUrl],
  });
  assertSpyCalls(redirect, 1);
  assertSpyCalls(redirectAwait, 1);

  assertSpyCalls(login, 0);
  assertSpyCalls(consent, 0);
  assertSpyCalls(errorHandler, 0);
});

test(
  authorizeErrorTests,
  "non access_denied error without redirectUrl",
  async ({
    request,
    response,
    redirect,
    login,
    consent,
    errorHandler,
    errorHandlerAwait,
  }) => {
    delete request.redirectUrl;
    const error = new InvalidRequest("not valid");
    await server.authorizeError(request, response, error, login, consent);

    assertEquals([...response.headers.entries()], []);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);

    assertSpyCalls(login, 0);
    assertSpyCalls(consent, 0);

    assertSpyCall(errorHandler, 0, {
      self: server,
      args: [request, response, error],
    });
    assertSpyCalls(errorHandler, 1);
    assertSpyCalls(errorHandlerAwait, 1);
  },
);

test(
  authorizeErrorTests,
  "calls login for access_denied error without user",
  async ({
    request,
    response,
    redirect,
    login,
    loginAwait,
    consent,
    errorHandler,
  }) => {
    const error = new AccessDenied("authentication required");
    await server.authorizeError(request, response, error, login, consent);

    assertEquals([...response.headers.entries()], []);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);

    assertSpyCall(login, 0, {
      self: undefined,
      args: [request, response],
    });
    assertSpyCalls(login, 1);
    assertSpyCalls(loginAwait, 1);

    assertSpyCalls(consent, 0);
    assertSpyCalls(errorHandler, 0);
  },
);

test(
  authorizeErrorTests,
  "calls consent for access_denied error without consent for requested scope",
  async ({
    request,
    response,
    redirect,
    login,
    consent,
    consentAwait,
    errorHandler,
  }) => {
    request.user = user;
    const error = new AccessDenied("not authorized");
    await server.authorizeError(request, response, error, login, consent);

    assertEquals([...response.headers.entries()], []);
    assertEquals(response.status, undefined);
    assertEquals(response.body, undefined);
    assertSpyCalls(redirect, 0);

    assertSpyCalls(login, 0);

    assertSpyCall(consent, 0, {
      self: undefined,
      args: [request, response],
    });
    assertSpyCalls(consent, 1);
    assertSpyCalls(consentAwait, 1);

    assertSpyCalls(errorHandler, 0);
  },
);
