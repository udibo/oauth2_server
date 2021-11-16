import {
  assertEquals,
  assertIsError,
  assertSpyCall,
  assertSpyCalls,
  delay,
  Spy,
  spy,
  Stub,
  stub,
  test,
  TestSuite,
} from "./test_deps.ts";
import {
  fakeAuthorizeRequest,
  fakeResponse,
  fakeTokenRequest,
} from "./test_context.ts";
import { assertClientUserScopeCall, assertToken } from "./asserts.ts";
import {
  AuthorizationCodeService,
  client,
  ClientService,
  RefreshTokenService,
  scope,
  user,
} from "./services/test_services.ts";
import * as resourceServerModule from "./authorization_server.ts";
import * as authorizationServerModule from "./authorization_server.ts";
import {
  AccessDeniedError,
  AccessToken,
  AuthorizationCode,
  AuthorizationCodeGrant,
  AuthorizationServer,
  AuthorizationServerGrants,
  authorizeParameters,
  challengeMethods,
  Client,
  generateCodeVerifier,
  GrantServices,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  OAuth2AuthenticatedRequest,
  OAuth2AuthorizedRequest,
  OAuth2Request,
  OAuth2Response,
  RefreshToken,
  RefreshTokenGrant,
  Scope,
  ServerError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  User,
} from "./authorization_server.ts";

test("verify exports", () => {
  const moduleKeys = Object.keys(authorizationServerModule).sort();
  const moduleKeySet = new Set(moduleKeys);
  const missingKeys = [];
  for (const key of Object.keys(resourceServerModule)) {
    if (!moduleKeySet.has(key)) {
      missingKeys.push(key);
    }
  }
  assertEquals(missingKeys, []);
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

const clientService = new ClientService();
const tokenService = new RefreshTokenService();
const authorizationCodeService = new AuthorizationCodeService();
const services: GrantServices<Client, User, Scope> = {
  clientService,
  tokenService,
};

const refreshTokenGrant = new RefreshTokenGrant({ services });
const authorizationCodeGrant = new AuthorizationCodeGrant({
  services: { ...services, authorizationCodeService },
});
const grants: AuthorizationServerGrants<Client, User, Scope> = {
  "refresh_token": refreshTokenGrant,
  "authorization_code": authorizationCodeGrant,
};
const server = new AuthorizationServer({
  grants,
  services: { tokenService },
});

const serverTests = new TestSuite({
  name: "AuthorizationServer",
});

interface TokenTestContext {
  success: Spy<void>;
  error: Spy<void>;
  tokenSuccess: Stub<AuthorizationServer<Client, User, Scope>>;
  tokenError: Stub<AuthorizationServer<Client, User, Scope>>;
}

const tokenTests = new TestSuite<TokenTestContext>({
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

async function tokenTestError<E extends Error = Error>(
  { success, error, tokenSuccess, tokenError }: TokenTestContext,
  request: OAuth2Request<Client, User, Scope>,
  response: OAuth2Response,
  // deno-lint-ignore no-explicit-any
  ErrorClass?: new (...args: any[]) => E,
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
  assertIsError(call.args[2], ErrorClass, msgIncludes, msg);
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
      InvalidRequestError,
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
      InvalidRequestError,
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
      InvalidRequestError,
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
    InvalidRequestError,
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
    InvalidRequestError,
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
    UnsupportedGrantTypeError,
    "invalid grant_type",
  );
});

test(tokenTests, "client authentication failed", async (context) => {
  const getAuthenticatedClient = stub(
    refreshTokenGrant,
    "getAuthenticatedClient",
    () =>
      Promise.reject(new InvalidClientError("client authentication failed")),
  );
  try {
    const request = fakeTokenRequest("grant_type=refresh_token");
    const response = fakeResponse();
    await tokenTestError(
      context,
      request,
      response,
      InvalidClientError,
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
      () =>
        Promise.resolve({
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
        UnauthorizedClientError,
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
    () => Promise.reject(new InvalidGrantError("invalid refresh_token")),
  );
  try {
    const request = fakeTokenRequest("grant_type=refresh_token");
    const response = fakeResponse();
    await tokenTestError(
      context,
      request,
      response,
      InvalidGrantError,
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
    const refreshToken: RefreshToken<Client, User, Scope> = {
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
  const accessToken: AccessToken<Client, User, Scope> = {
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
  const refreshToken: RefreshToken<Client, User, Scope> = {
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
    ) as OAuth2AuthenticatedRequest<Client, User, Scope>;
    request.token = {
      accessToken: "foo",
      refreshToken: "bar",
      client,
      user,
      scope,
    };
    const response = fakeResponse();
    const redirect = spy(response, "redirect");
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
    const redirect = spy(response, "redirect");
    const error = new InvalidGrantError("invalid refresh_token");
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

interface AuthorizeTestContext {
  success: Spy<void>;
  error: Spy<void>;
  authorizeSuccess: Stub<AuthorizationServer<Client, User, Scope>>;
  authorizeError: Stub<AuthorizationServer<Client, User, Scope>>;
  setAuthorizationAwait: Spy<void>;
  setAuthorization: Spy<void>;
  login: Spy<void>;
  consent: Spy<void>;
}

const authorizeTests = new TestSuite<AuthorizeTestContext>({
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

async function authorizeTestError<E extends Error = Error>(
  context: AuthorizeTestContext,
  request: OAuth2Request<Client, User, Scope>,
  response: OAuth2Response,
  // deno-lint-ignore no-explicit-any
  ErrorClass?: new (...args: any[]) => E,
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
  assertIsError(call.args[2], ErrorClass, msgIncludes, msg);
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

async function authorizeTestErrorNoRedirect<E extends Error = Error>(
  context: AuthorizeTestContext,
  request: OAuth2Request<Client, User, Scope>,
  response: OAuth2Response,
  // deno-lint-ignore no-explicit-any
  ErrorClass?: new (...args: any[]) => E,
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
      InvalidRequestError,
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
      () => Promise.resolve(),
    );
    try {
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorNoRedirect(
        context,
        request,
        response,
        InvalidClientError,
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
      () => Promise.resolve({ ...client, grants: ["refresh_token"] }),
    );
    try {
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorNoRedirect(
        context,
        request,
        response,
        UnauthorizedClientError,
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
    () => Promise.resolve({ ...client, redirectUris: [] }),
  );
  try {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorNoRedirect(
      context,
      request,
      response,
      UnauthorizedClientError,
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
    UnauthorizedClientError,
    "redirect_uri not authorized",
  );
});

async function authorizeTestErrorRedirect<E extends Error = Error>(
  context: AuthorizeTestContext,
  request: OAuth2Request<Client, User, Scope>,
  response: OAuth2Response,
  // deno-lint-ignore no-explicit-any
  ErrorClass?: new (...args: any[]) => E,
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

async function authorizeTestErrorPreAuthorization<E extends Error = Error>(
  context: AuthorizeTestContext,
  request: OAuth2Request<Client, User, Scope>,
  response: OAuth2Response,
  // deno-lint-ignore no-explicit-any
  ErrorClass?: new (...args: any[]) => E,
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
    InvalidRequestError,
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
    InvalidRequestError,
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
    InvalidRequestError,
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
      InvalidRequestError,
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
    InvalidRequestError,
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
    InvalidRequestError,
    "unsupported code_challenge_method",
  );
});

async function authorizeTestErrorAuthorized<E extends Error = Error>(
  context: AuthorizeTestContext,
  request: OAuth2Request<Client, User, Scope>,
  response: OAuth2Response,
  user?: User,
  authorizedScope?: Scope,
  // deno-lint-ignore no-explicit-any
  ErrorClass?: new (...args: any[]) => E,
  msgIncludes?: string,
  msg?: string,
) {
  context.setAuthorization = spy(
    (request: OAuth2Request<Client, User, Scope>) => {
      request.user = user;
      request.authorizedScope = authorizedScope;
      return delay(0).then(context.setAuthorizationAwait);
    },
  );
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
  const challenge: string = await challengeMethods.S256(verifier);
  request.url.searchParams.set("code_challenge", challenge);
  request.url.searchParams.set("code_challenge_method", "S256");
  const response = fakeResponse();
  await authorizeTestErrorAuthorized(
    context,
    request,
    response,
    undefined,
    undefined,
    AccessDeniedError,
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
      AccessDeniedError,
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
      () => Promise.reject(new InvalidScopeError("invalid scope")),
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
        InvalidScopeError,
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
      AccessDeniedError,
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
      AccessDeniedError,
      "not authorized",
    );
  },
);

test(authorizeTests, "generateAuthorizationCode error", async (context) => {
  const generateAuthorizationCode = stub(
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
  request: OAuth2Request<Client, User, Scope>,
  response: OAuth2Response,
  code: string,
  user: User,
  authorizedScope?: Scope,
  challenge?: string,
  challengeMethod?: string,
) {
  context.setAuthorization = spy(
    (request: OAuth2Request<Client, User, Scope>) => {
      request.user = user;
      request.authorizedScope = authorizedScope;
      return delay(0).then(context.setAuthorizationAwait);
    },
  );

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

  const generateAuthorizationCode = stub(
    authorizationCodeGrant,
    "generateAuthorizationCode",
    (
      authorizationCode: Omit<
        AuthorizationCode<Client, User, Scope>,
        "code" | "expiresAt"
      >,
    ) =>
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

  const expectedOptions: Omit<
    AuthorizationCode<Client, User, Scope>,
    "code" | "expiresAt"
  > = {
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
  const challenge: string = await challengeMethods.S256(verifier);
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
    request as OAuth2AuthorizedRequest<Client, User, Scope>,
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
  request: OAuth2Request<Client, User, Scope>;
  response: OAuth2Response;
  redirect: Stub<OAuth2Response>;
  redirectAwait: Spy<void>;
  login: Spy<void>;
  loginAwait: Spy<void>;
  consent: Spy<void>;
  consentAwait: Spy<void>;
  errorHandler: Stub<AuthorizationServer<Client, User, Scope>>;
  errorHandlerAwait: Spy<void>;
}

const authorizeErrorTests = new TestSuite<AuthorizeTestContext>({
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

  const error = new InvalidRequestError("not valid");
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
    const error = new InvalidRequestError("not valid");
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
    const error = new AccessDeniedError("authentication required");
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
    const error = new AccessDeniedError("not authorized");
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
