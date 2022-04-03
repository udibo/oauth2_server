import { AbstractGrant } from "./grant.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";
import { Token } from "../models/token.ts";
import {
  assertClientUserScopeCall,
  assertScope,
  assertToken,
} from "../asserts.ts";
import { Scope } from "../models/scope.ts";
import {
  assertEquals,
  assertRejects,
  assertSpyCalls,
  assertStrictEquals,
  describe,
  it,
  Spy,
  spy,
  Stub,
  stub,
} from "../test_deps.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { InvalidClientError, InvalidScopeError } from "../errors.ts";
import {
  ClientService,
  RefreshTokenService,
  scope,
} from "../services/test_services.ts";
import { User } from "../models/user.ts";

const grantTests = describe("Grant");

const clientService = new ClientService();
const client: Client = (clientService as ClientService).client;
const tokenService = new RefreshTokenService();

class ExampleGrant extends AbstractGrant<Client, User, Scope> {
  async token(
    _request: OAuth2Request<Client, User, Scope>,
    _client: Client,
  ): Promise<Token<Client, User, Scope>> {
    return await Promise.reject(new Error("not implemented"));
  }
}
const grant: ExampleGrant = new ExampleGrant({
  services: { clientService, tokenService },
});

const refreshTokenGrant: ExampleGrant = new ExampleGrant({
  services: { clientService, tokenService },
  allowRefreshToken: true,
});

it(grantTests, "parseScope", () => {
  assertScope(grant.parseScope(undefined), undefined);
  assertScope(grant.parseScope(null), undefined);
  assertScope(grant.parseScope(""), undefined);
  assertScope(grant.parseScope("read"), new Scope("read"));
  assertScope(grant.parseScope("read write"), new Scope("read write"));
});

const acceptedScopeTests = describe({
  name: "acceptedScope",
  suite: grantTests,
});

it(
  acceptedScopeTests,
  "returns undefined if token service accepts no scope",
  async () => {
    const acceptedScope = stub(
      tokenService,
      "acceptedScope",
      () => Promise.resolve(undefined),
    );
    try {
      assertScope(await grant.acceptedScope(client, user, scope), undefined);

      assertClientUserScopeCall(
        acceptedScope,
        0,
        tokenService,
        client,
        user,
        scope,
      );
      assertSpyCalls(acceptedScope, 1);
    } finally {
      acceptedScope.restore();
    }
  },
);

it(
  acceptedScopeTests,
  "returns scope accepted by token service without requesting scope",
  async () => {
    const expectedScope = new Scope("other");
    const acceptedScope = stub(
      tokenService,
      "acceptedScope",
      () => Promise.resolve(expectedScope),
    );
    try {
      assertScope(await grant.acceptedScope(client, user), expectedScope);

      assertClientUserScopeCall(acceptedScope, 0, tokenService, client, user);
      assertSpyCalls(acceptedScope, 1);
    } finally {
      acceptedScope.restore();
    }
  },
);

it(
  acceptedScopeTests,
  "returns scope accepted by token service instead of requested scope",
  async () => {
    const expectedScope = new Scope("other");
    const acceptedScope = stub(
      tokenService,
      "acceptedScope",
      () => Promise.resolve(expectedScope),
    );
    try {
      assertScope(
        await grant.acceptedScope(client, user, scope),
        expectedScope,
      );

      assertClientUserScopeCall(
        acceptedScope,
        0,
        tokenService,
        client,
        user,
        scope,
      );
      assertSpyCalls(acceptedScope, 1);
    } finally {
      acceptedScope.restore();
    }
  },
);

it(acceptedScopeTests, "invalid scope", async () => {
  const acceptedScope = stub(
    tokenService,
    "acceptedScope",
    () => Promise.resolve(false),
  );
  try {
    await assertRejects(
      () => grant.acceptedScope(client, user, scope),
      InvalidScopeError,
      "invalid scope",
    );

    assertClientUserScopeCall(
      acceptedScope,
      0,
      tokenService,
      client,
      user,
      scope,
    );
    assertSpyCalls(acceptedScope, 1);
  } finally {
    acceptedScope.restore();
  }
});

it(acceptedScopeTests, "scope required", async () => {
  const acceptedScope = stub(
    tokenService,
    "acceptedScope",
    () => Promise.resolve(false),
  );
  try {
    await assertRejects(
      () => grant.acceptedScope(client, user),
      InvalidScopeError,
      "scope required",
    );

    assertClientUserScopeCall(acceptedScope, 0, tokenService, client, user);
    assertSpyCalls(acceptedScope, 1);
  } finally {
    acceptedScope.restore();
  }
});

const getClientCredentialsTests = describe({
  name: "getClientCredentials",
  suite: grantTests,
});

it(
  getClientCredentialsTests,
  "authorization header required if credentials not in body",
  async () => {
    const request = fakeTokenRequest();
    request.headers.delete("authorization");
    await assertRejects(
      () => grant.getClientCredentials(request),
      InvalidClientError,
      "authorization header required",
    );
  },
);

it(
  getClientCredentialsTests,
  "from request body without secret",
  async () => {
    const request = fakeTokenRequest("client_id=1");
    request.headers.delete("authorization");
    const result = grant.getClientCredentials(request);
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1" });
  },
);

it(getClientCredentialsTests, "from request body with secret", async () => {
  const request = fakeTokenRequest(
    "client_id=1&client_secret=2",
  );
  request.headers.delete("authorization");
  const result = grant.getClientCredentials(request);
  assertEquals(result, Promise.resolve(result));
  assertEquals(await result, { clientId: "1", clientSecret: "2" });
});

it(
  getClientCredentialsTests,
  "from authorization header without secret",
  async () => {
    const request = fakeTokenRequest();
    request.headers.set("authorization", `basic ${btoa("1:")}`);
    const result = grant.getClientCredentials(request);
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1" });
  },
);

it(
  getClientCredentialsTests,
  "from authorization header with secret",
  async () => {
    const request = fakeTokenRequest();
    request.headers.set("authorization", `basic ${btoa("1:2")}`);
    const result = grant.getClientCredentials(request);
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1", clientSecret: "2" });
  },
);

it(
  getClientCredentialsTests,
  "ignores request body when authorization header is present",
  async () => {
    const request = fakeTokenRequest(
      "client_id=1&client_secret=2",
    );
    request.headers.set("authorization", `basic ${btoa("3:")}`);
    const result = grant.getClientCredentials(request);
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "3" });
  },
);

const getAuthenticatedClientTests = describe({
  name: "getAuthenticatedClient",
  suite: grantTests,
});

it(getAuthenticatedClientTests, "getClientCredentials failed", async () => {
  const getClientCredentials: Spy<ExampleGrant> = spy(
    grant,
    "getClientCredentials",
  );
  const clientServiceGetAuthenticated: Stub<ClientService> = stub(
    clientService,
    "getAuthenticated",
    () => Promise.resolve(),
  );
  try {
    const request = fakeTokenRequest();
    request.headers.delete("authorization");
    await assertRejects(
      () => grant.getAuthenticatedClient(request),
      InvalidClientError,
      "authorization header required",
    );

    assertEquals(getClientCredentials.calls.length, 1);
    const call = getClientCredentials.calls[0];
    assertEquals(call.args.length, 1);
    assertStrictEquals(call.args[0], request);
    assertStrictEquals(call.self, grant);

    assertEquals(clientServiceGetAuthenticated.calls.length, 0);
  } finally {
    getClientCredentials.restore();
    clientServiceGetAuthenticated.restore();
  }
});

it(
  getAuthenticatedClientTests,
  "client authentication failed without secret",
  async () => {
    const getClientCredentials: Spy<ExampleGrant> = spy(
      grant,
      "getClientCredentials",
    );
    const clientServiceGetAuthenticated: Stub<ClientService> = stub(
      clientService,
      "getAuthenticated",
      () => Promise.resolve(),
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:")}`);
      await assertRejects(
        () => grant.getAuthenticatedClient(request),
        InvalidClientError,
        "client authentication failed",
      );

      assertEquals(getClientCredentials.calls.length, 1);
      const getClientCredentialsCall = getClientCredentials.calls[0];
      assertEquals(getClientCredentialsCall.args.length, 1);
      assertStrictEquals(getClientCredentialsCall.args[0], request);
      assertStrictEquals(getClientCredentialsCall.self, grant);

      assertEquals(clientServiceGetAuthenticated.calls.length, 1);
      const getAuthenticatedCall = clientServiceGetAuthenticated.calls[0];
      assertEquals(getAuthenticatedCall.args, ["1"]);
      assertStrictEquals(getAuthenticatedCall.self, clientService);
    } finally {
      getClientCredentials.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

it(
  getAuthenticatedClientTests,
  "client authentication failed with secret",
  async () => {
    const getClientCredentials: Spy<ExampleGrant> = spy(
      grant,
      "getClientCredentials",
    );
    const clientServiceGetAuthenticated: Stub<ClientService> = stub(
      clientService,
      "getAuthenticated",
      () => Promise.resolve(),
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:2")}`);
      await assertRejects(
        () => grant.getAuthenticatedClient(request),
        InvalidClientError,
        "client authentication failed",
      );

      assertEquals(getClientCredentials.calls.length, 1);
      const getClientCredentialsCall = getClientCredentials.calls[0];
      assertEquals(getClientCredentialsCall.args.length, 1);
      assertStrictEquals(getClientCredentialsCall.args[0], request);
      assertStrictEquals(getClientCredentialsCall.self, grant);

      assertEquals(clientServiceGetAuthenticated.calls.length, 1);
      const getAuthenticatedCall = clientServiceGetAuthenticated.calls[0];
      assertEquals(getAuthenticatedCall.args, ["1", "2"]);
      assertStrictEquals(getAuthenticatedCall.self, clientService);
    } finally {
      getClientCredentials.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

it(
  getAuthenticatedClientTests,
  "returns client authenticated without secret",
  async () => {
    const getClientCredentials: Spy<ExampleGrant> = spy(
      grant,
      "getClientCredentials",
    );
    const clientServiceGetAuthenticated: Spy<ClientService> = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:")}`);
      const result = grant.getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client = await result;

      assertEquals(getClientCredentials.calls.length, 1);
      const getClientCredentialsCall = getClientCredentials.calls[0];
      assertEquals(getClientCredentialsCall.args.length, 1);
      assertStrictEquals(getClientCredentialsCall.args[0], request);
      assertStrictEquals(getClientCredentialsCall.self, grant);

      assertEquals(clientServiceGetAuthenticated.calls.length, 1);
      const getAuthenticatedCall = clientServiceGetAuthenticated.calls[0];
      assertEquals(getAuthenticatedCall.args, ["1"]);
      assertStrictEquals(getAuthenticatedCall.self, clientService);

      assertEquals(client, await getAuthenticatedCall.returned);
    } finally {
      getClientCredentials.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

it(
  getAuthenticatedClientTests,
  "returns client authenticated with secret",
  async () => {
    const getClientCredentials: Spy<ExampleGrant> = spy(
      grant,
      "getClientCredentials",
    );
    const clientServiceGetAuthenticated: Spy<ClientService> = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:2")}`);
      const result = grant.getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client = await result;

      assertEquals(getClientCredentials.calls.length, 1);
      const getClientCredentialsCall = getClientCredentials.calls[0];
      assertEquals(getClientCredentialsCall.args.length, 1);
      assertStrictEquals(getClientCredentialsCall.args[0], request);
      assertStrictEquals(getClientCredentialsCall.self, grant);

      assertEquals(clientServiceGetAuthenticated.calls.length, 1);
      const getAuthenticatedCall = clientServiceGetAuthenticated.calls[0];
      assertEquals(getAuthenticatedCall.args, ["1", "2"]);
      assertStrictEquals(getAuthenticatedCall.self, clientService);

      assertEquals(client, await getAuthenticatedCall.returned);
    } finally {
      getClientCredentials.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

const generateTokenTests = describe({
  name: "generateToken",
  suite: grantTests,
});

const user: User = { username: "kyle" };

it(
  generateTokenTests,
  "access token without optional properties",
  async () => {
    const generateAccessToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateAccessToken",
      () => Promise.resolve("x"),
    );
    const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "accessTokenExpiresAt",
      () => Promise.resolve(undefined),
    );
    try {
      const result = grant.generateToken(client, user);
      assertStrictEquals(Promise.resolve(result), result);
      const token = await result;

      assertClientUserScopeCall(
        accessTokenExpiresAt,
        0,
        tokenService,
        client,
        user,
      );
      assertSpyCalls(accessTokenExpiresAt, 1);

      assertToken(token, {
        accessToken: "x",
        client,
        user,
      });
    } finally {
      generateAccessToken.restore();
      accessTokenExpiresAt.restore();
    }
  },
);

it(generateTokenTests, "access token with optional properties", async () => {
  const generateAccessToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "generateAccessToken",
    () => Promise.resolve("x"),
  );
  const expectedAccessTokenExpiresAt: Date = new Date();
  const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
    tokenService,
    "accessTokenExpiresAt",
    () => Promise.resolve(new Date(expectedAccessTokenExpiresAt)),
  );
  try {
    const result = grant.generateToken(client, user, new Scope("read"));
    assertStrictEquals(Promise.resolve(result), result);
    const token = await result;

    assertClientUserScopeCall(
      accessTokenExpiresAt,
      0,
      tokenService,
      client,
      user,
      new Scope("read"),
    );
    assertSpyCalls(accessTokenExpiresAt, 1);

    assertToken(token, {
      accessToken: "x",
      accessTokenExpiresAt: expectedAccessTokenExpiresAt,
      client,
      user,
      scope: new Scope("read"),
    });
  } finally {
    generateAccessToken.restore();
    accessTokenExpiresAt.restore();
  }
});

it(
  generateTokenTests,
  "refresh token allowed without optional properties",
  async () => {
    const generateAccessToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateAccessToken",
      () => Promise.resolve("x"),
    );
    const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "accessTokenExpiresAt",
      () => Promise.resolve(undefined),
    );
    const generateRefreshToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateRefreshToken",
      () => Promise.resolve(undefined),
    );
    const refreshTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "refreshTokenExpiresAt",
      () => Promise.resolve(undefined),
    );
    try {
      const result = refreshTokenGrant.generateToken(client, user);
      assertStrictEquals(Promise.resolve(result), result);
      const token = await result;

      assertClientUserScopeCall(
        accessTokenExpiresAt,
        0,
        tokenService,
        client,
        user,
      );
      assertSpyCalls(accessTokenExpiresAt, 1);

      assertToken(token, {
        accessToken: "x",
        client,
        user,
      });
    } finally {
      generateAccessToken.restore();
      accessTokenExpiresAt.restore();
      generateRefreshToken.restore();
      refreshTokenExpiresAt.restore();
    }
  },
);

it(
  generateTokenTests,
  "refresh token allowed with optional properties",
  async () => {
    const generateAccessToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateAccessToken",
      () => Promise.resolve("x"),
    );
    const expectedAccessTokenExpiresAt: Date = new Date();
    const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "accessTokenExpiresAt",
      () => Promise.resolve(new Date(expectedAccessTokenExpiresAt)),
    );
    const generateRefreshToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateRefreshToken",
      () => Promise.resolve("y"),
    );
    const expectedRefreshTokenExpiresAt: Date = new Date(Date.now() + 1000);
    const refreshTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "refreshTokenExpiresAt",
      () => Promise.resolve(new Date(expectedRefreshTokenExpiresAt)),
    );
    try {
      const result = refreshTokenGrant.generateToken(
        client,
        user,
        new Scope("read"),
      );
      assertStrictEquals(Promise.resolve(result), result);
      const token = await result;

      assertClientUserScopeCall(
        accessTokenExpiresAt,
        0,
        tokenService,
        client,
        user,
        new Scope("read"),
      );
      assertSpyCalls(accessTokenExpiresAt, 1);

      assertToken(token, {
        accessToken: "x",
        accessTokenExpiresAt: expectedAccessTokenExpiresAt,
        refreshToken: "y",
        refreshTokenExpiresAt: expectedRefreshTokenExpiresAt,
        client,
        user,
        scope: new Scope("read"),
      });
    } finally {
      generateAccessToken.restore();
      accessTokenExpiresAt.restore();
      generateRefreshToken.restore();
      refreshTokenExpiresAt.restore();
    }
  },
);
