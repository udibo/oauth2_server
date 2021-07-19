import { ClientCredentials, Grant } from "./grant.ts";
import { OAuth2Request } from "../context.ts";
import { Client, ClientService } from "../models/client.ts";
import { RefreshTokenService, Token } from "../models/token.ts";
import {
  assertClientUserScopeCall,
  assertScope,
  assertToken,
} from "../asserts.ts";
import { ExampleRefreshTokenService } from "../models/token_test.ts";
import { Scope } from "../models/scope.ts";
import { User } from "../models/user.ts";
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
import { InvalidClient } from "../errors.ts";
import { ExampleClientService } from "../models/client_test.ts";

const grantTests: TestSuite<void> = new TestSuite({ name: "Grant" });

const clientService: ClientService = new ExampleClientService();
const client: Client = (clientService as ExampleClientService).client;
const tokenService: RefreshTokenService = new ExampleRefreshTokenService();

class ExampleGrant extends Grant {
  token(_request: OAuth2Request, _client: Client): Promise<Token> {
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

const getClientCredentialsTests: TestSuite<void> = new TestSuite({
  name: "getClientCredentials",
});

test(
  getClientCredentialsTests,
  "authorization header required if credentials not in body",
  async () => {
    const request: OAuth2Request = fakeTokenRequest();
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
    const request: OAuth2Request = fakeTokenRequest("client_id=1");
    request.headers.delete("authorization");
    const result: Promise<ClientCredentials> = grant.getClientCredentials(
      request,
    );
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1" });
  },
);

test(getClientCredentialsTests, "from request body with secret", async () => {
  const request: OAuth2Request = fakeTokenRequest(
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
    const request: OAuth2Request = fakeTokenRequest();
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
    const request: OAuth2Request = fakeTokenRequest();
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
    const request: OAuth2Request = fakeTokenRequest(
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
    const request: OAuth2Request = fakeTokenRequest();
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
      const request: OAuth2Request = fakeTokenRequest();
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
      const request: OAuth2Request = fakeTokenRequest();
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
      const request: OAuth2Request = fakeTokenRequest();
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
      const request: OAuth2Request = fakeTokenRequest();
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
      const token: Token = await result;

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
    const token: Token = await result;

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
      const token: Token = await result;

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
      const token: Token = await result;

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
