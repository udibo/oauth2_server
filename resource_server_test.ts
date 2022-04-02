import { assertScope, assertToken } from "./asserts.ts";
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
  assertIsError,
  assertRejects,
  assertSpyCall,
  assertSpyCalls,
  delay,
  describe,
  it,
  Spy,
  spy,
  Stub,
  stub,
} from "./test_deps.ts";
import * as resourceServerModule from "./authorization_server.ts";
import {
  AccessDeniedError,
  Client,
  InvalidClientError,
  InvalidGrantError,
  OAuth2AuthenticatedRequest,
  OAuth2Request,
  OAuth2Response,
  ResourceServer,
  Scope,
  ServerError,
  Token,
  User,
} from "./authorization_server.ts";

it("verify exports", () => {
  const moduleKeys = Object.keys(resourceServerModule).sort();
  assertEquals(moduleKeys, [
    "AbstractAccessTokenService",
    "AbstractAuthorizationCodeService",
    "AbstractClientService",
    "AbstractGrant",
    "AbstractRefreshTokenService",
    "AbstractUserService",
    "AccessDeniedError",
    "AuthorizationCodeGrant",
    "AuthorizationServer",
    "BEARER_TOKEN",
    "ClientCredentialsGrant",
    "DefaultScope",
    "InvalidClientError",
    "InvalidGrantError",
    "InvalidRequestError",
    "InvalidScopeError",
    "NQCHAR",
    "NQSCHAR",
    "OAuth2Error",
    "RefreshTokenGrant",
    "ResourceServer",
    "SCOPE",
    "SCOPE_TOKEN",
    "Scope",
    "ServerError",
    "TemporarilyUnavailableError",
    "UNICODECHARNOCRLF",
    "UnauthorizedClientError",
    "UnsupportedGrantTypeError",
    "UnsupportedResponseTypeError",
    "VSCHAR",
    "authorizeParameters",
    "authorizeUrl",
    "camelCase",
    "challengeMethods",
    "generateCodeVerifier",
    "generateSalt",
    "hashPassword",
    "loginRedirectFactory",
    "parseBasicAuth",
    "snakeCase",
  ]);
});

const tokenService = new RefreshTokenService();

const server = new ResourceServer({
  services: { tokenService },
});

const serverTests = describe("ResourceServer");

const errorHandlerTests = describe(serverTests, "errorHandler");

it(errorHandlerTests, "OAuth2Error without optional properties", async () => {
  const request = fakeTokenRequest();
  const response = fakeResponse();
  const redirectSpy = spy(response, "redirect");
  assertEquals(
    await server.errorHandler(
      request,
      response,
      new InvalidGrantError(),
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

it(errorHandlerTests, "OAuth2Error with optional properties", async () => {
  const request = fakeTokenRequest();
  const response = fakeResponse();
  const redirectSpy = spy(response, "redirect");
  assertEquals(
    await server.errorHandler(
      request,
      response,
      new resourceServerModule.OAuth2Error({
        status: 400,
        message: "invalid refresh_token",
        code: "invalid_token",
        uri: "https://example.com/",
      }),
    ),
    undefined,
  );
  assertEquals(response.status, 400);
  assertEquals([...response.headers.entries()], []);
  assertEquals(response.body, {
    error: "invalid_token",
    error_description: "invalid refresh_token",
    error_uri: "https://example.com/",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

it(errorHandlerTests, "OAuth2Error with 401 status", async () => {
  const request = fakeTokenRequest();
  const response = fakeResponse();
  const redirectSpy = spy(response, "redirect");
  assertEquals(
    await server.errorHandler(
      request,
      response,
      new InvalidClientError("client authentication failed"),
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

it(errorHandlerTests, "Error", async () => {
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
    error_description: "unexpected error",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

const getAccessTokenTests = describe(serverTests, "getAccessToken");

it(getAccessTokenTests, "GET request with no access token", async () => {
  const request = fakeResourceRequest("");
  const result = server.getAccessToken(request);
  assertEquals(Promise.resolve(result), result);
  assertEquals(await result, null);
});

it(
  getAccessTokenTests,
  "GET request with access token in authorization header",
  async () => {
    const request = fakeResourceRequest("abc");
    const result = server.getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);

it(getAccessTokenTests, "POST request with no access token", async () => {
  const request = fakeResourceRequest("");
  const result = server.getAccessToken(request);
  assertEquals(Promise.resolve(result), result);
  assertEquals(await result, null);
});

it(
  getAccessTokenTests,
  "POST request with access token in authorization header",
  async () => {
    const request = fakeResourceRequest("abc", {});
    const result = server.getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);

it(
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

it(
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

const getTokenTests = describe(serverTests, "getToken");

it(getTokenTests, "token service required", async () => {
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

it(getTokenTests, "invalid access_token", async () => {
  const getToken = stub(
    tokenService,
    "getToken",
    () => Promise.resolve(),
  );

  try {
    await assertRejects(
      () => server.getToken("123"),
      AccessDeniedError,
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

it(getTokenTests, "expired access_token", async () => {
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
      AccessDeniedError,
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

const getTokenForRequestTests = describe(serverTests, "getTokenForRequest");

it(
  getTokenForRequestTests,
  "authentication required from previous call",
  async () => {
    const getCustomAccessToken = spy(() => Promise.resolve(null));
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = spy(server, "getToken");
    try {
      const request = fakeResourceRequest("");
      request.token = null;
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDeniedError,
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

it(
  getTokenForRequestTests,
  "invalid access_token from previous call",
  async () => {
    const getCustomAccessToken = spy(() => Promise.resolve(null));
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = spy(server, "getToken");
    try {
      const request = fakeResourceRequest("");
      request.token = null;
      request.accessToken = "123";
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDeniedError,
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

it(
  getTokenForRequestTests,
  "returns cached token from previous call",
  async () => {
    const getCustomAccessToken = spy(() => Promise.resolve(null));
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

it(
  getTokenForRequestTests,
  "authentication required",
  async () => {
    const getCustomAccessToken = spy(() => Promise.resolve(null));
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = spy(server, "getToken");
    try {
      const request = fakeResourceRequest("");
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDeniedError,
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

it(
  getTokenForRequestTests,
  "invalid access token",
  async () => {
    const getCustomAccessToken = spy(() => Promise.resolve(null));
    const getAccessToken = spy(server, "getAccessToken");
    const getToken = stub(
      server,
      "getToken",
      () => Promise.reject(new AccessDeniedError("invalid access_token")),
    );
    try {
      const request = fakeResourceRequest("123");
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDeniedError,
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

it(
  getTokenForRequestTests,
  "returns token from authentication header",
  async () => {
    const getCustomAccessToken = spy(() => Promise.resolve(null));
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

it(
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

it(
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

it(
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

it(
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
      () =>
        Promise.reject(
          new AccessDeniedError(`invalid session ${++tokenCalls}`),
        ),
    );
    try {
      const request = fakeResourceRequest("");
      await assertRejects(
        () => server.getTokenForRequest(request, getCustomAccessToken),
        AccessDeniedError,
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

it(
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
          ? Promise.reject(new AccessDeniedError("invalid session"))
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

const authenticateTests = describe<AuthenticateTestContext>({
  name: "authenticate",
  suite: serverTests,
  beforeEach() {
    this.success = spy();
    this.error = spy();
    this.authenticateSuccess = stub(
      server,
      "authenticateSuccess",
      () => delay(0).then(this.success),
    );
    this.authenticateError = stub(
      server,
      "authenticateError",
      () => delay(0).then(this.error),
    );
  },
  afterEach() {
    this.authenticateSuccess.restore();
    this.authenticateError.restore();
  },
});

async function authenticateTestError<
  Request extends OAuth2Request<Client, User, Scope>,
  E extends Error = Error,
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
  // deno-lint-ignore no-explicit-any
  ErrorClass?: new (...args: any[]) => E,
  msgIncludes?: string,
  msg?: string,
) {
  const redirect = spy(response, "redirect");
  const next = spy(() => Promise.resolve());
  await server.authenticate(
    request,
    response,
    next,
    getAccessToken,
    acceptedScope,
  );

  assertSpyCalls(authenticateSuccess, 0);
  assertSpyCalls(success, 0);

  assertSpyCall(authenticateError, 0, { self: server });
  const call = authenticateError.calls[0];
  assertEquals(call.args.length, 3);
  assertEquals(call.args.slice(0, 2), [request, response]);
  assertIsError(call.args[2], ErrorClass, msgIncludes, msg);
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

it(
  authenticateTests,
  "error getting token for request",
  async function () {
    const getTokenForRequest = stub(
      server,
      "getTokenForRequest",
      () => Promise.reject(new AccessDeniedError("invalid access_token")),
    );

    try {
      const request = fakeResourceRequest("123");
      const response = fakeResponse();
      const getAccessToken = spy(() => Promise.resolve(null));
      await authenticateTestError(
        this,
        request,
        response,
        getAccessToken,
        scope,
        undefined,
        AccessDeniedError,
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

it(authenticateTests, "insufficient scope", async function () {
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
    const getAccessToken = spy(() => Promise.resolve(null));
    const acceptedScope = new Scope("read write delete");
    await authenticateTestError(
      this,
      request,
      response,
      getAccessToken,
      acceptedScope,
      expectedToken,
      AccessDeniedError,
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
  const next = spy(() => Promise.resolve());
  const getAccessToken = spy(() => Promise.resolve(null));

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

it(authenticateTests, "without scope", async function () {
  const request = fakeResourceRequest("123");
  const response = fakeResponse();
  const expectedToken = {
    accessToken: "123",
    client,
    user,
    scope,
  };
  await authenticateTest(
    this,
    request,
    response,
    undefined,
    expectedToken,
  );
});

it(authenticateTests, "with scope", async function () {
  const request = fakeResourceRequest("123");
  const response = fakeResponse();
  const expectedToken = {
    accessToken: "123",
    client,
    user,
    scope,
  };
  await authenticateTest(
    this,
    request,
    response,
    scope,
    expectedToken,
  );
});

const authenticateResponseTests = describe(serverTests, "authenticateResponse");

it(authenticateResponseTests, "without accepted scope", async () => {
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

it(authenticateResponseTests, "with accepted scope", async () => {
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

it(authenticateResponseTests, "without scope", async () => {
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

it(serverTests, "authenticateSuccess", async () => {
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

it(serverTests, "authenticateError", async () => {
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
    const error = new AccessDeniedError("insufficient scope");
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
