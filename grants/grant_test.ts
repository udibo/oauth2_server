import { AbstractGrant, ClientCredentials } from "./grant.ts";
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
  assertSpyCalls,
  assertStrictEquals,
  assertThrowsAsync,
  resolves,
  Spy,
  spy,
  SpyCall,
  Stub,
  stub,
  test,
  TestSuite,
} from "../test_deps.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { InvalidClient, InvalidScope } from "../errors.ts";
import {
  ClientService,
  RefreshTokenService,
  scope,
} from "../services/test_services.ts";
import { User } from "../models/user.ts";

const grantTests: TestSuite<void> = new TestSuite({ name: "Grant" });

const clientService = new ClientService();
const client: Client = (clientService as ClientService).client;
const tokenService = new RefreshTokenService();

class ExampleGrant extends AbstractGrant<Client, User, Scope> {
  token(
    _request: OAuth2Request<Client, User, Scope>,
    _client: Client,
  ): Promise<Token<Client, User, Scope>> {
    throw new Error("not implemented");
  }
}
const grant: ExampleGrant = new ExampleGrant({
  services: { clientService, tokenService },
});

const refreshTokenGrant: ExampleGrant = new ExampleGrant({
  services: { clientService, tokenService },
  allowRefreshToken: true,
});

test(grantTests, "parseScope", () => {
  assertScope(grant.parseScope(undefined), undefined);
  assertScope(grant.parseScope(null), undefined);
  assertScope(grant.parseScope(""), undefined);
  assertScope(grant.parseScope("read"), new Scope("read"));
  assertScope(grant.parseScope("read write"), new Scope("read write"));
});

const acceptedScopeTests: TestSuite<void> = new TestSuite({
  name: "acceptedScope",
  suite: grantTests,
});

test(
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

test(
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

test(
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

test(acceptedScopeTests, "invalid scope", async () => {
  const acceptedScope = stub(
    tokenService,
    "acceptedScope",
    () => Promise.resolve(false),
  );
  try {
    await assertThrowsAsync(
      () => grant.acceptedScope(client, user, scope),
      InvalidScope,
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

test(acceptedScopeTests, "scope required", async () => {
  const acceptedScope = stub(
    tokenService,
    "acceptedScope",
    () => Promise.resolve(false),
  );
  try {
    await assertThrowsAsync(
      () => grant.acceptedScope(client, user),
      InvalidScope,
      "scope required",
    );

    assertClientUserScopeCall(acceptedScope, 0, tokenService, client, user);
    assertSpyCalls(acceptedScope, 1);
  } finally {
    acceptedScope.restore();
  }
});

const getClientCredentialsTests: TestSuite<void> = new TestSuite({
  name: "getClientCredentials",
  suite: grantTests,
});

test(
  getClientCredentialsTests,
  "authorization header required if credentials not in body",
  async () => {
    const request = fakeTokenRequest();
    request.headers.delete("authorization");
    await assertThrowsAsync(
      () => grant.getClientCredentials(request),
      InvalidClient,
      "authorization header required",
    );
  },
);

test(
  getClientCredentialsTests,
  "from request body without secret",
  async () => {
    const request = fakeTokenRequest("client_id=1");
    request.headers.delete("authorization");
    const result: Promise<ClientCredentials> = grant.getClientCredentials(
      request,
    );
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1" });
  },
);

test(getClientCredentialsTests, "from request body with secret", async () => {
  const request = fakeTokenRequest(
    "client_id=1&client_secret=2",
  );
  request.headers.delete("authorization");
  const result: Promise<ClientCredentials> = grant.getClientCredentials(
    request,
  );
  assertEquals(result, Promise.resolve(result));
  assertEquals(await result, { clientId: "1", clientSecret: "2" });
});

test(
  getClientCredentialsTests,
  "from authorization header without secret",
  async () => {
    const request = fakeTokenRequest();
    request.headers.set("authorization", `basic ${btoa("1:")}`);
    const result: Promise<ClientCredentials> = grant.getClientCredentials(
      request,
    );
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1" });
  },
);

test(
  getClientCredentialsTests,
  "from authorization header with secret",
  async () => {
    const request = fakeTokenRequest();
    request.headers.set("authorization", `basic ${btoa("1:2")}`);
    const result: Promise<ClientCredentials> = grant.getClientCredentials(
      request,
    );
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1", clientSecret: "2" });
  },
);

test(
  getClientCredentialsTests,
  "ignores request body when authorization header is present",
  async () => {
    const request = fakeTokenRequest(
      "client_id=1&client_secret=2",
    );
    request.headers.set("authorization", `basic ${btoa("3:")}`);
    const result: Promise<ClientCredentials> = grant.getClientCredentials(
      request,
    );
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "3" });
  },
);

const getAuthenticatedClientTests: TestSuite<void> = new TestSuite({
  name: "getAuthenticatedClient",
  suite: grantTests,
});

test(getAuthenticatedClientTests, "getClientCredentials failed", async () => {
  const getClientCredentials: Spy<ExampleGrant> = spy(
    grant,
    "getClientCredentials",
  );
  const clientServiceGetAuthenticated: Stub<ClientService> = stub(
    clientService,
    "getAuthenticated",
    resolves(undefined),
  );
  try {
    const request = fakeTokenRequest();
    request.headers.delete("authorization");
    await assertThrowsAsync(
      () => grant.getAuthenticatedClient(request),
      InvalidClient,
      "authorization header required",
    );

    assertEquals(getClientCredentials.calls.length, 1);
    const call: SpyCall = getClientCredentials.calls[0];
    assertEquals(call.args.length, 1);
    assertStrictEquals(call.args[0], request);
    assertStrictEquals(call.self, grant);

    assertEquals(clientServiceGetAuthenticated.calls.length, 0);
  } finally {
    getClientCredentials.restore();
    clientServiceGetAuthenticated.restore();
  }
});

test(
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
      resolves(undefined),
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:")}`);
      await assertThrowsAsync(
        () => grant.getAuthenticatedClient(request),
        InvalidClient,
        "client authentication failed",
      );

      assertEquals(getClientCredentials.calls.length, 1);
      let call: SpyCall = getClientCredentials.calls[0];
      assertEquals(call.args.length, 1);
      assertStrictEquals(call.args[0], request);
      assertStrictEquals(call.self, grant);

      assertEquals(clientServiceGetAuthenticated.calls.length, 1);
      call = clientServiceGetAuthenticated.calls[0];
      assertEquals(call.args, ["1"]);
      assertStrictEquals(call.self, clientService);
    } finally {
      getClientCredentials.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

test(
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
      resolves(undefined),
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:2")}`);
      await assertThrowsAsync(
        () => grant.getAuthenticatedClient(request),
        InvalidClient,
        "client authentication failed",
      );

      assertEquals(getClientCredentials.calls.length, 1);
      let call: SpyCall = getClientCredentials.calls[0];
      assertEquals(call.args.length, 1);
      assertStrictEquals(call.args[0], request);
      assertStrictEquals(call.self, grant);

      assertEquals(clientServiceGetAuthenticated.calls.length, 1);
      call = clientServiceGetAuthenticated.calls[0];
      assertEquals(call.args, ["1", "2"]);
      assertStrictEquals(call.self, clientService);
    } finally {
      getClientCredentials.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

test(
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
      const result: Promise<Client> = grant.getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client: Client = await result;

      assertEquals(getClientCredentials.calls.length, 1);
      let call: SpyCall = getClientCredentials.calls[0];
      assertEquals(call.args.length, 1);
      assertStrictEquals(call.args[0], request);
      assertStrictEquals(call.self, grant);

      assertEquals(clientServiceGetAuthenticated.calls.length, 1);
      call = clientServiceGetAuthenticated.calls[0];
      assertEquals(call.args, ["1"]);
      assertStrictEquals(call.self, clientService);

      assertEquals(client, await call.returned);
    } finally {
      getClientCredentials.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

test(
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
      const result: Promise<Client> = grant.getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client: Client = await result;

      assertEquals(getClientCredentials.calls.length, 1);
      let call: SpyCall = getClientCredentials.calls[0];
      assertEquals(call.args.length, 1);
      assertStrictEquals(call.args[0], request);
      assertStrictEquals(call.self, grant);

      assertEquals(clientServiceGetAuthenticated.calls.length, 1);
      call = clientServiceGetAuthenticated.calls[0];
      assertEquals(call.args, ["1", "2"]);
      assertStrictEquals(call.self, clientService);

      assertEquals(client, await call.returned);
    } finally {
      getClientCredentials.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

const generateTokenTests: TestSuite<void> = new TestSuite({
  name: "generateToken",
  suite: grantTests,
});

const user: User = { username: "kyle" };

test(
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

test(generateTokenTests, "access token with optional properties", async () => {
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

test(
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

test(
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
