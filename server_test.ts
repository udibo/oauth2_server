import {
  RefreshTokenGrant,
  RefreshTokenGrantInterface,
} from "./grants/refresh_token.ts";
import {
  AccessToken,
  RefreshToken,
  RefreshTokenService,
  Token,
  TokenServiceInterface,
} from "./models/token.ts";
import { Client, ClientService } from "./models/client.ts";
import type { User } from "./models/user.ts";
import { Scope } from "./models/scope.ts";
import { test, TestSuite } from "./deps/udibo/test_suite/mod.ts";
import {
  assertEquals,
  assertStrictEquals,
  assertThrowsAsync,
} from "./deps/std/testing/asserts.ts";
import { resolves, Spy, spy, Stub, stub } from "./deps/udibo/mock/mod.ts";
import {
  InvalidClient,
  InvalidGrant,
  InvalidRequest,
  OAuth2Error,
  UnauthorizedClient,
  UnsupportedGrantType,
} from "./errors.ts";
import { OAuth2Request, OAuth2Response } from "./context.ts";
import {
  OAuth2Server,
  OAuth2ServerGrants,
  OAuth2ServerServices,
} from "./server.ts";
import { fakeTokenRequest, fakeTokenResponse } from "./test_context.ts";
import { delay } from "./deps/std/async/delay.ts";

const serverTests: TestSuite<void> = new TestSuite({
  name: "OAuth2Server",
});

const client: Client = {
  id: "1",
  grants: ["refresh_token"],
};
class FakeClientService extends ClientService {
  get(_clientId: string): Promise<Client | void> {
    return Promise.resolve({ ...client });
  }

  getAuthenticated(
    _clientId: string,
    _clientSecret?: string,
  ): Promise<Client | void> {
    return Promise.resolve({ ...client });
  }
}
const clientService: ClientService = new FakeClientService();

const user: User = {};
export class FakeRefreshTokenService extends RefreshTokenService {
  /** Retrieves an existing token. */
  getAccessToken(accessToken: string): Promise<AccessToken | void> {
    return Promise.resolve({
      accessToken,
      client,
      user,
    });
  }

  /** Retrieves an existing token. */
  getRefreshToken(refreshToken: string): Promise<RefreshToken | void> {
    return Promise.resolve({
      accessToken: "fake",
      refreshToken,
      client,
      user,
    });
  }

  /** Saves a token. */
  save<T extends Token>(token: T): Promise<T> {
    return Promise.resolve(token);
  }

  /** Revokes a token. */
  revoke(_token: Token): Promise<boolean> {
    return Promise.resolve(true);
  }

  /** Revokes all tokens generated from an authorization code. */
  revokeCode(_code: string): Promise<boolean> {
    return Promise.resolve(true);
  }
}
const refreshTokenService: TokenServiceInterface =
  new FakeRefreshTokenService();
const services: OAuth2ServerServices = {
  clientService,
  tokenService: refreshTokenService,
};
const refreshTokenGrant: RefreshTokenGrantInterface = new RefreshTokenGrant({
  services,
});
const grants: OAuth2ServerGrants = {
  "refresh_token": refreshTokenGrant,
};
const server: OAuth2Server = new OAuth2Server({ services, grants });

const getClientTests: TestSuite<void> = new TestSuite({
  name: "getClient",
  suite: serverTests,
});

test(getClientTests, "authorization header required", async () => {
  let request: OAuth2Request = fakeTokenRequest();
  request.headers.delete("authorization");
  await assertThrowsAsync(
    () => server.getAuthenticatedClient(request),
    InvalidClient,
    "authorization header required",
  );

  request = fakeTokenRequest();
  request.headers.set("authorization", "");
  await assertThrowsAsync(
    () => server.getAuthenticatedClient(request),
    InvalidClient,
    "authorization header required",
  );
});

test(getClientTests, "unsupported authorization header", async () => {
  let request: OAuth2Request = fakeTokenRequest();
  request.headers.set("authorization", "Bearer mF_9.B5f-4.1JqM");
  await assertThrowsAsync(
    () => server.getAuthenticatedClient(request),
    InvalidClient,
    "unsupported authorization header",
  );

  request = fakeTokenRequest();
  request.headers.set("authorization", "bearer mF_9.B5f-4.1JqM");
  await assertThrowsAsync(
    () => server.getAuthenticatedClient(request),
    InvalidClient,
    "unsupported authorization header",
  );
});

test(
  getClientTests,
  "authorization header is not correctly encoded",
  async () => {
    let request: OAuth2Request = fakeTokenRequest();
    request.headers.set("authorization", "basic x");
    await assertThrowsAsync(
      () => server.getAuthenticatedClient(request),
      InvalidClient,
      "authorization header is not correctly encoded",
    );

    request = fakeTokenRequest();
    request.headers.set("authorization", "BaSiC x");
    await assertThrowsAsync(
      () => server.getAuthenticatedClient(request),
      InvalidClient,
      "authorization header is not correctly encoded",
    );
  },
);

test(getClientTests, "authorization header is malformed", async () => {
  let request: OAuth2Request = fakeTokenRequest();
  request.headers.set("authorization", `basic ${btoa(":")}`);
  await assertThrowsAsync(
    () => server.getAuthenticatedClient(request),
    InvalidClient,
    "authorization header is malformed",
  );

  request = fakeTokenRequest();
  request.headers.set("authorization", `BaSiC ${btoa(":a")}`);
  await assertThrowsAsync(
    () => server.getAuthenticatedClient(request),
    InvalidClient,
    "authorization header is malformed",
  );
});

test(getClientTests, "client authentication failed", async () => {
  const clientServiceGetAuthenticatedStub: Stub<ClientService> = stub(
    clientService,
    "getAuthenticated",
    resolves(undefined),
  );
  try {
    let request: OAuth2Request = fakeTokenRequest();
    request.headers.set("authorization", `basic ${btoa("1")}`);
    await assertThrowsAsync(
      () => server.getAuthenticatedClient(request),
      InvalidClient,
      "client authentication failed",
    );
    assertEquals(clientServiceGetAuthenticatedStub.calls.length, 1);
    assertEquals(clientServiceGetAuthenticatedStub.calls[0].args, ["1"]);
    assertStrictEquals(
      clientServiceGetAuthenticatedStub.calls[0].self,
      clientService,
    );

    request = fakeTokenRequest("grant_type=refresh_token");
    request.headers.set("authorization", `BaSiC ${btoa("1:2")}`);
    await assertThrowsAsync(
      () => server.getAuthenticatedClient(request),
      InvalidClient,
      "client authentication failed",
    );
    assertEquals(clientServiceGetAuthenticatedStub.calls.length, 2);
    assertEquals(clientServiceGetAuthenticatedStub.calls[1].args, ["1", "2"]);
    assertStrictEquals(
      clientServiceGetAuthenticatedStub.calls[1].self,
      clientService,
    );
  } finally {
    clientServiceGetAuthenticatedStub.restore();
  }
});

const getTokenTests: TestSuite<void> = new TestSuite({
  name: "getToken",
  suite: serverTests,
});

test(getTokenTests, "method must be post", async () => {
  const request: OAuth2Request = fakeTokenRequest();
  request.method = "GET";
  await assertThrowsAsync(
    () => server.getToken(request),
    InvalidRequest,
    "method must be POST",
  );
});

test(
  getTokenTests,
  "content-type header must be application/x-www-form-urlencoded",
  async () => {
    let request: OAuth2Request = fakeTokenRequest();
    request.headers.delete("Content-Type");
    await assertThrowsAsync(
      () => server.getToken(request),
      InvalidRequest,
      "content-type header must be application/x-www-form-urlencoded",
    );

    request = fakeTokenRequest();
    request.headers.set("Content-Type", "application/json");
    await assertThrowsAsync(
      () => server.getToken(request),
      InvalidRequest,
      "content-type header must be application/x-www-form-urlencoded",
    );
  },
);

test(getTokenTests, "request body required", async () => {
  const request: OAuth2Request = fakeTokenRequest();
  await assertThrowsAsync(
    () => server.getToken(request),
    InvalidRequest,
    "request body required",
  );
});

test(getTokenTests, "grant_type parameter required", async () => {
  let request: OAuth2Request = fakeTokenRequest("");
  await assertThrowsAsync(
    () => server.getToken(request),
    InvalidRequest,
    "grant_type parameter required",
  );

  request = fakeTokenRequest("grant_type=");
  await assertThrowsAsync(
    () => server.getToken(request),
    InvalidRequest,
    "grant_type parameter required",
  );
});

test(getTokenTests, "invalid grant_type", async () => {
  let request: OAuth2Request = fakeTokenRequest("grant_type=fake");
  await assertThrowsAsync(
    () => server.getToken(request),
    UnsupportedGrantType,
    "invalid grant_type",
  );

  request = fakeTokenRequest("grant_type=refresh_token");
  try {
    delete server.grants["refresh_token"];
    await assertThrowsAsync(
      () => server.getToken(request),
      UnsupportedGrantType,
      "invalid grant_type",
    );
  } finally {
    server.grants = { ...grants };
  }
});

test(getTokenTests, "client authentication failed", async () => {
  const getAuthenticatedClientStub: Stub<OAuth2Server> = stub(
    server,
    "getAuthenticatedClient",
    () => Promise.reject(new InvalidClient("client authentication failed")),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    await assertThrowsAsync(
      () => server.getToken(request),
      InvalidClient,
      "client authentication failed",
    );
    assertEquals(getAuthenticatedClientStub.calls.length, 1);
    assertEquals(getAuthenticatedClientStub.calls[0].args.length, 1);
    assertStrictEquals(getAuthenticatedClientStub.calls[0].args[0], request);
    assertStrictEquals(
      getAuthenticatedClientStub.calls[0].self,
      server,
    );
  } finally {
    getAuthenticatedClientStub.restore();
  }
});

test(
  getTokenTests,
  "client is not authorized to use this grant_type",
  async () => {
    const getAuthenticatedClientStub: Stub<OAuth2Server> = stub(
      server,
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
        () => server.getToken(request),
        UnauthorizedClient,
        "client is not authorized to use this grant_type",
      );
      assertEquals(getAuthenticatedClientStub.calls.length, 1);
      assertEquals(getAuthenticatedClientStub.calls[0].args.length, 1);
      assertStrictEquals(getAuthenticatedClientStub.calls[0].args[0], request);
      assertStrictEquals(
        getAuthenticatedClientStub.calls[0].self,
        server,
      );
    } finally {
      getAuthenticatedClientStub.restore();
    }
  },
);

test(getTokenTests, "grant handle error", async () => {
  const refreshTokenGrantHandleStub: Stub<RefreshTokenGrant> = stub(
    refreshTokenGrant,
    "handle",
    () => Promise.reject(new InvalidGrant("invalid refresh_token")),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    await assertThrowsAsync(
      () => server.getToken(request),
      InvalidGrant,
      "invalid refresh_token",
    );
  } finally {
    refreshTokenGrantHandleStub.restore();
  }
});

const scope: Scope = new Scope("read");

test(getTokenTests, "returns refresh token", async () => {
  const token: RefreshToken = {
    accessToken: "foo",
    refreshToken: "bar",
    client: { ...client },
    user: { ...user },
    scope,
  };
  const refreshTokenGrantHandleStub: Stub<RefreshTokenGrant> = stub(
    refreshTokenGrant,
    "handle",
    () => Promise.resolve(token),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    assertStrictEquals(await server.getToken(request), token);
  } finally {
    refreshTokenGrantHandleStub.restore();
  }
});

const handleErrorTests: TestSuite<void> = new TestSuite({
  name: "handleError",
  suite: serverTests,
});

test(handleErrorTests, "OAuth2Error without optional properties", async () => {
  const response: OAuth2Response = fakeTokenResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await server.handleError(
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

test(handleErrorTests, "OAuth2Error with optional properties", async () => {
  const response: OAuth2Response = fakeTokenResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await server.handleError(
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

test(handleErrorTests, "OAuth2Error with 401 status", async () => {
  const response: OAuth2Response = fakeTokenResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await server.handleError(
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

test(handleErrorTests, "Error", async () => {
  const response: OAuth2Response = fakeTokenResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await server.handleError(
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

const tokenTests: TestSuite<void> = new TestSuite({
  name: "token",
  suite: serverTests,
});

test(
  tokenTests,
  "handles getToken error and awaits handleError response",
  async () => {
    const error: OAuth2Error = new InvalidGrant("invalid refresh_token");
    const getTokenStub: Stub<OAuth2Server> = stub(
      server,
      "getToken",
      () => Promise.reject(error),
    );
    const afterHandleErrorSpy: Spy<void> = spy();
    const handleErrorStub: Stub<OAuth2Server> = stub(
      server,
      "handleError",
      () => delay(0).then(afterHandleErrorSpy),
    );
    const response: OAuth2Response = fakeTokenResponse();
    const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
    try {
      const request: OAuth2Request = fakeTokenRequest(
        "grant_type=refresh_token",
      );
      assertEquals(await server.token({ request, response }), undefined);
      assertEquals(handleErrorStub.calls.length, 1);
      assertStrictEquals(handleErrorStub.calls[0].args[0], response);
      assertStrictEquals(handleErrorStub.calls[0].args[1], error);
      assertEquals(afterHandleErrorSpy.calls.length, 1);
      assertEquals(response.status, undefined);
      assertEquals(response.body, undefined);
      assertEquals(redirectSpy.calls.length, 0);
    } finally {
      getTokenStub.restore();
      handleErrorStub.restore();
    }
  },
);

test(tokenTests, "without optional token properties", async () => {
  const getTokenStub: Stub<OAuth2Server> = stub(
    server,
    "getToken",
    () => Promise.resolve({ accessToken: "foo" }),
  );
  const handleErrorSpy: Spy<OAuth2Server> = spy(server, "handleError");
  const response: OAuth2Response = fakeTokenResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    assertEquals(await server.token({ request, response }), undefined);
    assertEquals(handleErrorSpy.calls.length, 0);
    assertEquals(response.status, 200);
    assertEquals(response.body, { access_token: "foo", token_type: "Bearer" });
    assertEquals(redirectSpy.calls.length, 0);
  } finally {
    getTokenStub.restore();
  }
});

test(tokenTests, "with optional token properties", async () => {
  const now: Date = new Date("2021-05-15T13:09:05Z");
  const getTokenStub: Stub<OAuth2Server> = stub(
    server,
    "getToken",
    () =>
      Promise.resolve({
        accessToken: "foo",
        refreshToken: "bar",
        accessTokenExpiresAt: new Date(now.valueOf() + 120000),
        refreshTokenExpiresAt: new Date(now.valueOf() + 600000),
      }),
  );
  const handleErrorSpy: Spy<OAuth2Server> = spy(server, "handleError");
  const response: OAuth2Response = fakeTokenResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  try {
    const request: OAuth2Request = fakeTokenRequest("grant_type=refresh_token");
    assertEquals(await server.token({ request, response }), undefined);
    assertEquals(handleErrorSpy.calls.length, 0);
    assertEquals(response.status, 200);
    assertEquals(response.body, {
      access_token: "foo",
      refresh_token: "bar",
      access_token_expires_at: "2021-05-15T13:11:05.000Z",
      refresh_token_expires_at: "2021-05-15T13:19:05.000Z",
      token_type: "Bearer",
    });
    assertEquals(redirectSpy.calls.length, 0);
  } finally {
    getTokenStub.restore();
  }
});
