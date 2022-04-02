import {
  assertEquals,
  assertIsError,
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

it("verify exports", () => {
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

const serverTests = describe("AuthorizationServer");

interface TokenTestContext {
  success: Spy;
  error: Spy;
  tokenSuccess: Stub;
  tokenError: Stub;
}

const tokenTests = describe<TokenTestContext>({
  name: "token",
  suite: serverTests,
  beforeEach() {
    this.success = spy();
    this.error = spy();
    this.tokenSuccess = stub(
      server,
      "tokenSuccess",
      () => delay(0).then(this.success),
    );
    this.tokenError = stub(
      server,
      "tokenError",
      () => delay(0).then(this.error),
    );
  },
  afterEach() {
    this.tokenSuccess.restore();
    this.tokenError.restore();
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

  assertSpyCall(tokenError, 0, { self: server });
  const call = tokenError.calls[0];
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

it(
  tokenTests,
  "method must be post",
  async function () {
    const request = fakeTokenRequest();
    request.method = "GET";
    const response = fakeResponse();
    await tokenTestError(
      this,
      request,
      response,
      InvalidRequestError,
      "method must be POST",
    );
  },
);

it(
  tokenTests,
  "content-type header required",
  async function () {
    const request = fakeTokenRequest();
    const response = fakeResponse();
    request.headers.delete("Content-Type");
    await tokenTestError(
      this,
      request,
      response,
      InvalidRequestError,
      "content-type header must be application/x-www-form-urlencoded",
    );
  },
);

it(
  tokenTests,
  "content-type header must be application/x-www-form-urlencoded",
  async function () {
    const request = fakeTokenRequest();
    request.headers.set("Content-Type", "application/json");
    const response = fakeResponse();
    request.headers.delete("Content-Type");
    await tokenTestError(
      this,
      request,
      response,
      InvalidRequestError,
      "content-type header must be application/x-www-form-urlencoded",
    );
  },
);

it(tokenTests, "grant_type parameter required", async function () {
  const request = fakeTokenRequest("");
  const response = fakeResponse();
  await tokenTestError(
    this,
    request,
    response,
    InvalidRequestError,
    "grant_type parameter required",
  );
});

it(tokenTests, "invalid grant_type", async function () {
  const request = fakeTokenRequest("grant_type=fake");
  const response = fakeResponse();
  await tokenTestError(
    this,
    request,
    response,
    UnsupportedGrantTypeError,
    "invalid grant_type",
  );
});

it(tokenTests, "client authentication failed", async function () {
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
      this,
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

it(
  tokenTests,
  "client is not authorized to use this grant_type",
  async function () {
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
        this,
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

it(tokenTests, "grant token error", async function () {
  const token = stub(
    refreshTokenGrant,
    "token",
    () => Promise.reject(new InvalidGrantError("invalid refresh_token")),
  );
  try {
    const request = fakeTokenRequest("grant_type=refresh_token");
    const response = fakeResponse();
    await tokenTestError(
      this,
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

it(
  tokenTests,
  "returns refresh token",
  async function () {
    const { success, error, tokenSuccess, tokenError } = this;
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

const bearerTokenTests = describe({
  name: "bearerToken",
  suite: serverTests,
});

it(bearerTokenTests, "without optional token properties", () => {
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

it(bearerTokenTests, "with optional token properties", () => {
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

it(serverTests, "tokenResponse", async () => {
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

it(serverTests, "tokenSuccess", async () => {
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

    assertSpyCall(bearerToken, 0, {
      args: [request.token],
    });
    const call = bearerToken.calls[0];
    assertSpyCalls(bearerToken, 1);

    assertEquals(response.status, 200);
    assertEquals(response.body, call.returned);
    assertSpyCalls(redirect, 0);
  } finally {
    tokenResponse.restore();
  }
});

it(serverTests, "tokenError handles error", async () => {
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

const authorizeTests = describe<AuthorizeTestContext>({
  name: "authorize",
  suite: serverTests,
  beforeEach() {
    this.success = spy();
    this.error = spy();
    this.authorizeSuccess = stub(
      server,
      "authorizeSuccess",
      () => delay(0).then(this.success),
    );
    this.authorizeError = stub(
      server,
      "authorizeError",
      () => delay(0).then(this.error),
    );

    this.setAuthorizationAwait = spy();
    this.setAuthorization = spy(() =>
      delay(0).then(this.setAuthorizationAwait)
    );

    this.login = spy();
    this.consent = spy();
  },
  afterEach() {
    this.authorizeSuccess.restore();
    this.authorizeError.restore();
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

  assertSpyCall(authorizeError, 0, { self: server });
  const call = authorizeError.calls[0];
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

it(
  authorizeTests,
  "missing authorization code grant",
  async function () {
    const { grants } = server;
    try {
      server.grants = { "refresh_token": refreshTokenGrant };
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorNoRedirect(
        this,
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

it(
  authorizeTests,
  "client_id parameter required",
  async function () {
    const request = fakeAuthorizeRequest();
    request.url.searchParams.delete("client_id");
    const response = fakeResponse();
    await authorizeTestErrorNoRedirect(
      this,
      request,
      response,
      InvalidRequestError,
      "client_id parameter required",
    );
  },
);

it(
  authorizeTests,
  "client not found",
  async function () {
    const clientServiceGet: Stub<ClientService> = stub(
      clientService,
      "get",
      () => Promise.resolve(),
    );
    try {
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorNoRedirect(
        this,
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

it(
  authorizeTests,
  "client is not authorized to use the authorization code grant type",
  async function () {
    const clientServiceGet: Stub<ClientService> = stub(
      clientService,
      "get",
      () => Promise.resolve({ ...client, grants: ["refresh_token"] }),
    );
    try {
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorNoRedirect(
        this,
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

it(authorizeTests, "no authorized redirect_uri", async function () {
  const clientServiceGet: Stub<ClientService> = stub(
    clientService,
    "get",
    () => Promise.resolve({ ...client, redirectUris: [] }),
  );
  try {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorNoRedirect(
      this,
      request,
      response,
      UnauthorizedClientError,
      "no authorized redirect_uri",
    );
  } finally {
    clientServiceGet.restore();
  }
});

it(authorizeTests, "redirect_uri not authorized", async function () {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("redirect_uri", "http://client.example.com/cb");
  const response = fakeResponse();
  await authorizeTestErrorNoRedirect(
    this,
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

it(authorizeTests, "state required", async function () {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.delete("state");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    this,
    request,
    response,
    InvalidRequestError,
    "state required",
  );
});

it(authorizeTests, "response_type required", async function () {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.delete("response_type");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    this,
    request,
    response,
    InvalidRequestError,
    "response_type required",
  );
});

it(authorizeTests, "response_type not supported", async function () {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("response_type", "token");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    this,
    request,
    response,
    InvalidRequestError,
    "response_type not supported",
  );
});

it(
  authorizeTests,
  "code_challenge required when code_challenge_method is set",
  async function () {
    const request = fakeAuthorizeRequest();
    request.url.searchParams.set("code_challenge_method", "S256");
    const response = fakeResponse();
    await authorizeTestErrorPreAuthorization(
      this,
      request,
      response,
      InvalidRequestError,
      "code_challenge required when code_challenge_method is set",
    );
  },
);

it(authorizeTests, "code_challenge_method required", async function () {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("code_challenge", "abc");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    this,
    request,
    response,
    InvalidRequestError,
    "unsupported code_challenge_method",
  );
});

it(authorizeTests, "unsupported code_challenge_method", async function () {
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("code_challenge", "abc");
  request.url.searchParams.set("code_challenge_method", "plain");
  const response = fakeResponse();
  await authorizeTestErrorPreAuthorization(
    this,
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

it(authorizeTests, "authentication required with PKCE", async function () {
  const request = fakeAuthorizeRequest();
  const verifier: string = generateCodeVerifier();
  const challenge: string = await challengeMethods.S256(verifier);
  request.url.searchParams.set("code_challenge", challenge);
  request.url.searchParams.set("code_challenge_method", "S256");
  const response = fakeResponse();
  await authorizeTestErrorAuthorized(
    this,
    request,
    response,
    undefined,
    undefined,
    AccessDeniedError,
    "authentication required",
  );
});

it(
  authorizeTests,
  "authentication required without PKCE",
  async function () {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorAuthorized(
      this,
      request,
      response,
      undefined,
      undefined,
      AccessDeniedError,
      "authentication required",
    );
  },
);

it(
  authorizeTests,
  "scope not accepted",
  async function () {
    const acceptedScope = stub(
      authorizationCodeGrant,
      "acceptedScope",
      () => Promise.reject(new InvalidScopeError("invalid scope")),
    );
    try {
      const request = fakeAuthorizeRequest();
      const response = fakeResponse();
      await authorizeTestErrorAuthorized(
        this,
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

it(
  authorizeTests,
  "not authorized",
  async function () {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorAuthorized(
      this,
      request,
      response,
      user,
      undefined,
      AccessDeniedError,
      "not authorized",
    );
  },
);

it(
  authorizeTests,
  "not fully authorized",
  async function () {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorAuthorized(
      this,
      request,
      response,
      user,
      new Scope("read"),
      AccessDeniedError,
      "not authorized",
    );
  },
);

it(authorizeTests, "generateAuthorizationCode error", async function () {
  const generateAuthorizationCode = stub(
    authorizationCodeGrant,
    "generateAuthorizationCode",
    () => Promise.reject(new ServerError("generateAuthorizationCode failed")),
  );
  try {
    const request = fakeAuthorizeRequest();
    const response = fakeResponse();
    await authorizeTestErrorAuthorized(
      this,
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

async function authorizeit(
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

it(authorizeTests, "success without PKCE", async function () {
  const request = fakeAuthorizeRequest();
  const response = fakeResponse();
  await authorizeit(
    this,
    request,
    response,
    "123",
    user,
    new Scope("read"),
  );
});

it(authorizeTests, "success with PKCE", async function () {
  const request = fakeAuthorizeRequest();
  const verifier: string = generateCodeVerifier();
  const challenge: string = await challengeMethods.S256(verifier);
  request.url.searchParams.set("code_challenge", challenge);
  request.url.searchParams.set("code_challenge_method", "S256");
  const response = fakeResponse();
  await authorizeit(
    this,
    request,
    response,
    "123",
    user,
    new Scope("read"),
    challenge,
    "S256",
  );
});

it(serverTests, "authorizeSuccess", async () => {
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

const authorizeErrorTests = describe<AuthorizeTestContext>({
  name: "authorizeError",
  suite: serverTests,
  async beforeEach() {
    this.request = fakeAuthorizeRequest();
    this.request.authorizeParameters = await authorizeParameters(
      this.request,
    );
    this.request.redirectUrl = new URL(
      "https://client.example.com/cb?state=xyz",
    );
    this.response = fakeResponse();
    this.redirectAwait = spy();
    this.redirect = stub(
      this.response,
      "redirect",
      () => delay(0).then(this.redirectAwait),
    );
    this.loginAwait = spy();
    this.login = spy(() => delay(0).then(this.loginAwait));
    this.consentAwait = spy();
    this.consent = spy(() => delay(0).then(this.consentAwait));
    this.errorHandlerAwait = spy();
    this.errorHandler = stub(
      server,
      "errorHandler",
      () => delay(0).then(this.errorHandlerAwait),
    );
  },
  afterEach() {
    this.errorHandler.restore();
  },
});

it(
  authorizeErrorTests,
  "non access_denied error with redirectUrl",
  async function () {
    const {
      request,
      response,
      redirect,
      redirectAwait,
      login,
      consent,
      errorHandler,
    } = this;
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
  },
);

it(
  authorizeErrorTests,
  "non access_denied error without redirectUrl",
  async function () {
    const {
      request,
      response,
      redirect,
      login,
      consent,
      errorHandler,
      errorHandlerAwait,
    } = this;
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

it(
  authorizeErrorTests,
  "calls login for access_denied error without user",
  async function () {
    const {
      request,
      response,
      redirect,
      login,
      loginAwait,
      consent,
      errorHandler,
    } = this;
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

it(
  authorizeErrorTests,
  "calls consent for access_denied error without consent for requested scope",
  async function () {
    const {
      request,
      response,
      redirect,
      login,
      consent,
      consentAwait,
      errorHandler,
    } = this;
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
