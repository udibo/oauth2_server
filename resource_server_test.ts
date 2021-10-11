import {
  assertError,
  assertScope,
  assertToken,
  Constructor,
} from "./asserts.ts";
import {
  client,
  RefreshTokenService,
  scope,
  user,
} from "./services/test_services.ts";
import {
  fakeResourceRequest,
  fakeResponse,
  fakeTokenRequest,
} from "./test_context.ts";
import {
  assertEquals,
  assertRejects,
  assertSpyCall,
  assertSpyCalls,
  delay,
  resolves,
  Spy,
  spy,
  Stub,
  stub,
  test,
  TestSuite,
} from "./test_deps.ts";
import * as resourceServerModule from "./authorization_server.ts";
import {
  AccessDenied,
  Client,
  InvalidClient,
  InvalidGrant,
  OAuth2AuthenticatedRequest,
  OAuth2Request,
  OAuth2Response,
  ResourceServer,
  Scope,
  ServerError,
  Token,
  User,
} from "./authorization_server.ts";

test("verify exports", () => {
  const moduleKeys = Object.keys(resourceServerModule).sort();
  assertEquals(moduleKeys, [
    "AbstractAccessTokenService",
    "AbstractAuthorizationCodeService",
    "AbstractClientService",
    "AbstractGrant",
    "AbstractRefreshTokenService",
    "AbstractUserService",
    "AccessDenied",
    "AuthorizationCodeGrant",
    "AuthorizationServer",
    "BEARER_TOKEN",
    "ClientCredentialsGrant",
    "DefaultScope",
    "InvalidClient",
    "InvalidGrant",
    "InvalidRequest",
    "InvalidScope",
    "NQCHAR",
    "NQSCHAR",
    "OAuth2Error",
    "RefreshTokenGrant",
    "ResourceServer",
    "SCOPE",
    "SCOPE_TOKEN",
    "Scope",
    "ServerError",
    "TemporarilyUnavailable",
    "UNICODECHARNOCRLF",
    "UnauthorizedClient",
    "UnsupportedGrantType",
    "UnsupportedResponseType",
    "VSCHAR",
    "authorizeParameters",
    "authorizeUrl",
    "camelCase",
    "challengeMethods",
    "generateCodeVerifier",
    "getMessageOrOptions",
    "loginRedirectFactory",
    "parseBasicAuth",
    "snakeCase",
  ]);
});

const tokenService = new RefreshTokenService();

const server = new ResourceServer({
  services: { tokenService },
});

const serverTests = new TestSuite({
  name: "ResourceServer",
});

const errorHandlerTests = new TestSuite({
  name: "errorHandler",
  suite: serverTests,
});

test(errorHandlerTests, "OAuth2Error without optional properties", async () => {
  const request = fakeTokenRequest();
  const response = fakeResponse();
  const redirectSpy = spy(response, "redirect");
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
  const redirectSpy = spy(response, "redirect");
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
  const response = fakeResponse();
  const redirectSpy = spy(response, "redirect");
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
  const response = fakeResponse();
  const redirectSpy = spy(response, "redirect");
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

const getAccessTokenTests = new TestSuite({
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

const getTokenTests = new TestSuite({
  name: "getToken",
  suite: serverTests,
});

test(getTokenTests, "token service required", async () => {
  const { services } = server;
  try {
    server.services = {};
    await assertRejects(
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
    await assertRejects(
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
    await assertRejects(
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

const getTokenForRequestTests = new TestSuite({
  name: "getTokenForRequest",
  suite: serverTests,
});

test(
  getTokenForRequestTests,
  "authentication required from previous call",
  async () => {
    const getCustomAccessToken = spy();
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = spy(server, "getToken");
    try {
      const request = fakeResourceRequest("");
      request.token = null;
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDenied,
        "authentication required",
      );
      assertSpyCalls(getCustomAccessToken, 0);
      assertSpyCalls(getAccessToken, 0);
      assertSpyCalls(getToken, 0);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "invalid access_token from previous call",
  async () => {
    const getCustomAccessToken = spy();
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = spy(server, "getToken");
    try {
      const request = fakeResourceRequest("");
      request.token = null;
      request.accessToken = "123";
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDenied,
        "invalid access_token",
      );
      assertSpyCalls(getCustomAccessToken, 0);
      assertSpyCalls(getAccessToken, 0);
      assertSpyCalls(getToken, 0);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "returns cached token from previous call",
  async () => {
    const getCustomAccessToken = spy();
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = spy(server, "getToken");
    try {
      const expectedToken = {
        accessToken: "123",
        accessTokenExpiresAt: new Date(Date.now() - 60000),
        client,
        user,
        scope,
      };
      const request = fakeResourceRequest("");
      request.token = { ...expectedToken };
      assertToken(
        await server.getTokenForRequest(request, getCustomAccessToken),
        expectedToken,
      );
      assertSpyCalls(getCustomAccessToken, 0);
      assertSpyCalls(getAccessToken, 0);
      assertSpyCalls(getToken, 0);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "authentication required",
  async () => {
    const getCustomAccessToken = spy();
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = spy(server, "getToken");
    try {
      const request = fakeResourceRequest("");
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDenied,
        "authentication required",
      );
      assertSpyCall(getCustomAccessToken, 0, {
        self: undefined,
        args: [request],
      });
      assertSpyCalls(getCustomAccessToken, 1);
      assertSpyCall(getAccessToken, 0, {
        self: server,
        args: [request],
      });
      assertSpyCalls(getAccessToken, 1);
      assertSpyCalls(getToken, 0);

      assertEquals(request.accessToken, null);
      assertToken(request.token, null);
      assertEquals(request.token, null);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "invalid access token",
  async () => {
    const getCustomAccessToken = spy();
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = stub(
      server,
      "getToken",
      () => Promise.reject(new AccessDenied("invalid access_token")),
    );
    try {
      const request = fakeResourceRequest("123");
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDenied,
        "invalid access_token",
      );
      assertSpyCall(getCustomAccessToken, 0, {
        self: undefined,
        args: [request],
      });
      assertSpyCalls(getCustomAccessToken, 1);
      assertSpyCall(getAccessToken, 0, {
        self: server,
        args: [request],
      });
      assertSpyCalls(getAccessToken, 1);
      assertSpyCall(getToken, 0, {
        self: server,
        args: ["123"],
      });
      assertSpyCalls(getToken, 1);

      assertEquals(request.accessToken, "123");
      assertToken(request.token, null);
      assertEquals(request.token, null);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "returns token from authentication header",
  async () => {
    const getCustomAccessToken = spy();
    const getAccessToken = spy(server, "getAccessToken");
    const expectedToken = {
      accessToken: "123",
      accessTokenExpiresAt: new Date(Date.now() - 60000),
      client,
      user,
      scope,
    };
    const getToken = stub(
      server,
      "getToken",
      () => Promise.resolve(expectedToken),
    );
    try {
      const request = fakeResourceRequest("123");
      assertToken(
        await server.getTokenForRequest(request, getCustomAccessToken),
        expectedToken,
      );
      assertSpyCall(getCustomAccessToken, 0, {
        self: undefined,
        args: [request],
      });
      assertSpyCalls(getCustomAccessToken, 1);
      assertSpyCall(getAccessToken, 0, {
        self: server,
        args: [request],
      });
      assertSpyCalls(getAccessToken, 1);
      assertSpyCall(getToken, 0, {
        self: server,
        args: ["123"],
      });
      assertSpyCalls(getToken, 1);

      assertEquals(request.accessToken, "123");
      assertToken(request.token, expectedToken);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "error from custom getAccessToken",
  async () => {
    const getCustomAccessToken = spy(() =>
      Promise.reject(new ServerError("oops"))
    );
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = spy(server, "getToken");
    try {
      const request = fakeResourceRequest("");
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        ServerError,
        "oops",
      );
      assertSpyCall(getCustomAccessToken, 0, {
        self: undefined,
        args: [request],
      });
      assertSpyCalls(getCustomAccessToken, 1);
      assertSpyCalls(getAccessToken, 0);
      assertSpyCalls(getToken, 0);

      assertToken(request.token, null);
      assertEquals(request.token, null);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "non access denied error for token from custom getAccessToken",
  async () => {
    const getCustomAccessToken = spy(() => Promise.resolve("123"));
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = stub(
      server,
      "getToken",
      () => Promise.reject(new ServerError("oops")),
    );
    try {
      const request = fakeResourceRequest("");
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        ServerError,
        "oops",
      );
      assertSpyCall(getCustomAccessToken, 0, {
        self: undefined,
        args: [request],
      });
      assertSpyCalls(getCustomAccessToken, 1);
      assertSpyCalls(getAccessToken, 0);
      assertSpyCall(getToken, 0, {
        self: server,
        args: ["123"],
      });
      assertSpyCalls(getToken, 1);

      assertEquals(request.accessToken, "123");
      assertToken(request.token, null);
      assertEquals(request.token, null);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "returns token from custom getAccessToken",
  async () => {
    const getCustomAccessToken = spy(() => Promise.resolve("123"));
    const getAccessToken = spy(server, "getAccessToken");
    const expectedToken = {
      accessToken: "123",
      accessTokenExpiresAt: new Date(Date.now() - 60000),
      client,
      user,
      scope,
    };
    const getToken = stub(
      server,
      "getToken",
      () => Promise.resolve(expectedToken),
    );
    try {
      const request = fakeResourceRequest("");
      assertToken(
        await server.getTokenForRequest(request, getCustomAccessToken),
        expectedToken,
      );
      assertSpyCall(getCustomAccessToken, 0, {
        self: undefined,
        args: [request],
      });
      assertSpyCalls(getCustomAccessToken, 1);
      assertSpyCalls(getAccessToken, 0);
      assertSpyCall(getToken, 0, {
        self: server,
        args: ["123"],
      });
      assertSpyCalls(getToken, 1);

      assertEquals(request.accessToken, "123");
      assertToken(request.token, expectedToken);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "error for token from refreshed custom getAccessToken",
  async () => {
    const accessTokens = ["123", "456"];
    let accessTokenIndex = 0;
    const getCustomAccessToken = spy(() =>
      Promise.resolve(accessTokens[accessTokenIndex++])
    );
    const getAccessToken = spy(server, "getAccessToken");
    let tokenCalls = 0;
    const getToken = stub(
      server,
      "getToken",
      () => Promise.reject(new AccessDenied(`invalid session ${++tokenCalls}`)),
    );
    try {
      const request = fakeResourceRequest("");
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDenied,
        "invalid session 2",
      );
      assertSpyCall(getCustomAccessToken, 0, {
        self: undefined,
        args: [request],
      });
      assertSpyCall(getCustomAccessToken, 1, {
        self: undefined,
        args: [request, true],
      });
      assertSpyCalls(getCustomAccessToken, 2);
      assertSpyCalls(getAccessToken, 0);
      assertSpyCall(getToken, 0, {
        self: server,
        args: ["123"],
      });
      assertSpyCall(getToken, 1, {
        self: server,
        args: ["456"],
      });
      assertSpyCalls(getToken, 2);

      assertEquals(request.accessToken, "456");
      assertToken(request.token, null);
      assertEquals(request.token, null);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

test(
  getTokenForRequestTests,
  "returns token from refreshed custom getAccessToken",
  async () => {
    const accessTokens = ["123", "456"];
    let accessTokenIndex = 0;
    const getCustomAccessToken = spy(() =>
      Promise.resolve(accessTokens[accessTokenIndex++])
    );
    const getAccessToken = spy(server, "getAccessToken");
    const expectedToken = {
      accessToken: "456",
      accessTokenExpiresAt: new Date(Date.now() - 60000),
      client,
      user,
      scope,
    };
    let tokenCalls = 0;
    const getToken = stub(
      server,
      "getToken",
      () =>
        tokenCalls++ === 0
          ? Promise.reject(new AccessDenied("invalid session"))
          : Promise.resolve(expectedToken),
    );
    try {
      const request = fakeResourceRequest("");
      assertToken(
        await server.getTokenForRequest(request, getCustomAccessToken),
        expectedToken,
      );
      assertSpyCall(getCustomAccessToken, 0, {
        self: undefined,
        args: [request],
      });
      assertSpyCall(getCustomAccessToken, 1, {
        self: undefined,
        args: [request, true],
      });
      assertSpyCalls(getCustomAccessToken, 2);
      assertSpyCalls(getAccessToken, 0);
      assertSpyCall(getToken, 0, {
        self: server,
        args: ["123"],
      });
      assertSpyCall(getToken, 1, {
        self: server,
        args: ["456"],
      });
      assertSpyCalls(getToken, 2);

      assertEquals(request.accessToken, "456");
      assertToken(request.token, expectedToken);
    } finally {
      getAccessToken.restore();
      getToken.restore();
    }
  },
);

interface AuthenticateTestContext {
  success: Spy<void>;
  error: Spy<void>;
  authenticateSuccess: Stub<ResourceServer<Client, User, Scope>>;
  authenticateError: Stub<ResourceServer<Client, User, Scope>>;
}

const authenticateTests = new TestSuite<AuthenticateTestContext>({
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

async function authenticateTestError<
  Request extends OAuth2Request<Client, User, Scope>,
>(
  { success, error, authenticateSuccess, authenticateError }:
    AuthenticateTestContext,
  request: Request,
  response: OAuth2Response,
  getAccessToken: (
    request: Request,
    requireRefresh?: boolean,
  ) => Promise<string | null>,
  acceptedScope?: Scope,
  expectedToken?: Token<Client, User, Scope>,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
) {
  const redirect = spy(response, "redirect");
  const next = spy();
  await server.authenticate(
    request,
    response,
    next,
    getAccessToken,
    acceptedScope,
  );

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

test(
  authenticateTests,
  "error getting token for request",
  async (context) => {
    const getTokenForRequest = stub(
      server,
      "getTokenForRequest",
      () => Promise.reject(new AccessDenied("invalid access_token")),
    );

    try {
      const request = fakeResourceRequest("123");
      const response = fakeResponse();
      const getAccessToken = spy();
      await authenticateTestError(
        context,
        request,
        response,
        getAccessToken,
        scope,
        undefined,
        AccessDenied,
        "invalid access_token",
      );

      assertSpyCall(getTokenForRequest, 0, {
        self: server,
        args: [request, getAccessToken],
      });
      assertSpyCalls(getTokenForRequest, 1);
      assertSpyCalls(getAccessToken, 0);
    } finally {
      getTokenForRequest.restore();
    }
  },
);

test(authenticateTests, "insufficient scope", async (context) => {
  const expectedToken = {
    accessToken: "123",
    client,
    user,
    scope,
  };
  const getTokenForRequest = stub(
    server,
    "getTokenForRequest",
    () => Promise.resolve(expectedToken),
  );

  try {
    const request = fakeResourceRequest("123");
    const response = fakeResponse();
    const getAccessToken = spy();
    const acceptedScope = new Scope("read write delete");
    await authenticateTestError(
      context,
      request,
      response,
      getAccessToken,
      acceptedScope,
      expectedToken,
      AccessDenied,
      "insufficient scope",
    );

    assertSpyCall(getTokenForRequest, 0, {
      self: server,
      args: [request, getAccessToken],
    });
    assertSpyCalls(getTokenForRequest, 1);
    assertSpyCalls(getAccessToken, 0);
  } finally {
    getTokenForRequest.restore();
  }
});

async function authenticateTest<
  Request extends OAuth2Request<Client, User, Scope>,
>(
  { success, error, authenticateSuccess, authenticateError }:
    AuthenticateTestContext,
  request: Request,
  response: OAuth2Response,
  acceptedScope?: Scope,
  expectedToken?: Token<Client, User, Scope>,
) {
  const getTokenForRequest = stub(
    server,
    "getTokenForRequest",
    () => Promise.resolve(expectedToken),
  );
  const redirect = spy(response, "redirect");
  const next = spy();
  const getAccessToken = spy();

  try {
    await server.authenticate(
      request,
      response,
      next,
      getAccessToken,
      acceptedScope,
    );
  } finally {
    getTokenForRequest.restore();
  }

  assertSpyCalls(getAccessToken, 0);

  assertSpyCall(getTokenForRequest, 0, {
    self: server,
    args: [request, getAccessToken],
  });
  assertSpyCalls(getTokenForRequest, 1);

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
    scope,
    expectedToken,
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
      Client,
      User,
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
      Client,
      User,
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
