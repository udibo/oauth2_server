import { RefreshTokenGrant } from "./refresh_token.ts";
import {
  AccessTokenService,
  RefreshToken,
  RefreshTokenService,
} from "../models/token.ts";
import type { Client, ClientService } from "../models/client.ts";
import type { User } from "../models/user.ts";
import { Scope } from "../models/scope.ts";
import {
  assertEquals,
  assertStrictEquals,
  assertThrowsAsync,
  Spy,
  spy,
  SpyCall,
  Stub,
  stub,
  test,
  TestSuite,
} from "../test_deps.ts";
import {
  ExampleAccessTokenService,
  ExampleRefreshTokenService,
} from "../models/token_test.ts";
import {
  InvalidClient,
  InvalidGrant,
  InvalidRequest,
  ServerError,
} from "../errors.ts";
import { OAuth2Request } from "../context.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { assertClientUserScopeCall, assertToken } from "../asserts.ts";
import { ExampleClientService } from "../models/client_test.ts";

const refreshTokenGrantTests: TestSuite<void> = new TestSuite({
  name: "RefreshTokenGrant",
});

const handleTests: TestSuite<void> = new TestSuite({
  name: "handle",
  suite: refreshTokenGrantTests,
});

const client: Client = {
  id: "1",
  grants: ["refresh_token"],
};
const clientService: ClientService = new ExampleClientService({ client });

test(handleTests, "not implemented for AccessTokenService", async () => {
  const tokenService: AccessTokenService = new ExampleAccessTokenService();
  const getRefreshToken: Spy<AccessTokenService> = spy(
    tokenService,
    "getRefreshToken",
  );
  const refreshTokenGrant: RefreshTokenGrant = new RefreshTokenGrant({
    services: {
      clientService,
      tokenService,
    },
  });
  try {
    let request: OAuth2Request = fakeTokenRequest("refresh_token=example1");
    const result: Promise<RefreshToken> = refreshTokenGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      ServerError,
      "getRefreshToken not implemented",
    );
    assertStrictEquals(getRefreshToken.calls.length, 1);
    let call: SpyCall = getRefreshToken.calls[0];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, ["example1"]);

    request = fakeTokenRequest("refresh_token=example2");
    await assertThrowsAsync(
      () => refreshTokenGrant.handle(request, client),
      ServerError,
      "getRefreshToken not implemented",
    );
    assertStrictEquals(getRefreshToken.calls.length, 2);
    call = getRefreshToken.calls[1];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, ["example2"]);
  } finally {
    getRefreshToken.restore();
  }
});

const tokenService: RefreshTokenService = new ExampleRefreshTokenService();
const refreshTokenGrant: RefreshTokenGrant = new RefreshTokenGrant({
  services: {
    clientService,
    tokenService,
  },
});

test(handleTests, "request body required", async () => {
  const request: OAuth2Request = fakeTokenRequest();
  const result: Promise<RefreshToken> = refreshTokenGrant.handle(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(
    () => result,
    InvalidRequest,
    "request body required",
  );
});

test(handleTests, "refresh_token parameter required", async () => {
  let request: OAuth2Request = fakeTokenRequest("");
  const result: Promise<RefreshToken> = refreshTokenGrant.handle(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(
    () => result,
    InvalidRequest,
    "refresh_token parameter required",
  );

  request = fakeTokenRequest("refresh_token=");
  await assertThrowsAsync(
    () => refreshTokenGrant.handle(request, client),
    InvalidRequest,
    "refresh_token parameter required",
  );
});

const user: User = { username: "kyle" };
const scope: Scope = new Scope("read");

test(handleTests, "refresh token not found", async () => {
  const getRefreshToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "getRefreshToken",
    (_refreshToken: string) => undefined,
  );
  try {
    let request: OAuth2Request = fakeTokenRequest("refresh_token=example1");
    const result: Promise<RefreshToken> = refreshTokenGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "invalid refresh_token",
    );
    assertStrictEquals(getRefreshToken.calls.length, 1);
    let call: SpyCall = getRefreshToken.calls[0];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, ["example1"]);

    request = fakeTokenRequest("refresh_token=example2");
    await assertThrowsAsync(
      () => refreshTokenGrant.handle(request, client),
      InvalidGrant,
      "invalid refresh_token",
    );
    assertStrictEquals(getRefreshToken.calls.length, 2);
    call = getRefreshToken.calls[1];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, ["example2"]);
  } finally {
    getRefreshToken.restore();
  }
});

test(handleTests, "refresh_token was issued to another client", async () => {
  const getRefreshToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "getRefreshToken",
    (refreshToken: string) => ({
      accessToken: "fake",
      refreshToken,
      client: { ...client, id: "2" },
      user,
      scope,
    }),
  );
  try {
    let request: OAuth2Request = fakeTokenRequest("refresh_token=example1");
    const result: Promise<RefreshToken> = refreshTokenGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidClient,
      "refresh_token was issued to another client",
    );
    assertStrictEquals(getRefreshToken.calls.length, 1);
    let call: SpyCall = getRefreshToken.calls[0];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, ["example1"]);

    request = fakeTokenRequest("refresh_token=example2");
    await assertThrowsAsync(
      () => refreshTokenGrant.handle(request, client),
      InvalidClient,
      "refresh_token was issued to another client",
    );
    assertStrictEquals(getRefreshToken.calls.length, 2);
    call = getRefreshToken.calls[1];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, ["example2"]);
  } finally {
    getRefreshToken.restore();
  }
});

test(handleTests, "returns new token and revokes old", async () => {
  const getRefreshToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "getRefreshToken",
    (refreshToken: string) =>
      Promise.resolve({
        accessToken: "fake",
        refreshToken,
        client,
        user,
        scope,
      }),
  );
  const save: Spy<RefreshTokenService> = spy(tokenService, "save");
  const revoke: Spy<RefreshTokenService> = spy(tokenService, "revoke");
  const accessTokenExpiresAt: Date = new Date(Date.now() + 1000);
  const refreshTokenExpiresAt: Date = new Date(Date.now() + 2000);
  const generateToken: Stub<RefreshTokenGrant> = stub(
    refreshTokenGrant,
    "generateToken",
    (client: Client, user: User, scope: Scope) =>
      Promise.resolve({
        accessToken: "x",
        refreshToken: "y",
        accessTokenExpiresAt,
        refreshTokenExpiresAt,
        client,
        user,
        scope,
      }),
  );

  try {
    const request: OAuth2Request = fakeTokenRequest("refresh_token=example");
    const result: Promise<RefreshToken> = refreshTokenGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    const token: RefreshToken = await result;

    assertStrictEquals(getRefreshToken.calls.length, 1);
    let call: SpyCall = getRefreshToken.calls[0];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, ["example"]);

    assertStrictEquals(generateToken.calls.length, 1);
    call = generateToken.calls[0];
    assertClientUserScopeCall(call, refreshTokenGrant, client, user, scope);

    assertStrictEquals(revoke.calls.length, 1);
    call = revoke.calls[0];
    assertStrictEquals(call.args.length, 1);
    assertToken(call.args[0], {
      accessToken: "fake",
      refreshToken: "example",
      client,
      user,
      scope,
    });

    const expectedToken: RefreshToken = {
      accessToken: "x",
      refreshToken: "y",
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
      client,
      user,
      scope,
    };
    assertStrictEquals(save.calls.length, 1);
    call = save.calls[0];
    assertStrictEquals(call.args.length, 1);
    assertToken(call.args[0], expectedToken);
    assertToken(token, expectedToken);
  } finally {
    getRefreshToken.restore();
    save.restore();
    revoke.restore();
    generateToken.restore();
  }
});

test(
  handleTests,
  "returns new token with same refresh token and revokes old",
  async () => {
    const refreshTokenExpiresAt: Date = new Date(Date.now() + 2000);
    const getRefreshToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "getRefreshToken",
      (refreshToken: string) =>
        Promise.resolve({
          accessToken: "fake",
          refreshToken,
          refreshTokenExpiresAt,
          client,
          user,
          scope,
        }),
    );
    const save: Spy<RefreshTokenService> = spy(tokenService, "save");
    const revoke: Spy<RefreshTokenService> = spy(tokenService, "revoke");
    const accessTokenExpiresAt: Date = new Date(Date.now() + 1000);
    const generateToken: Stub<RefreshTokenGrant> = stub(
      refreshTokenGrant,
      "generateToken",
      (client: Client, user: User, scope: Scope) =>
        Promise.resolve({
          accessToken: "x",
          accessTokenExpiresAt,
          client,
          user,
          scope,
        }),
    );

    try {
      const request: OAuth2Request = fakeTokenRequest("refresh_token=example");
      const result: Promise<RefreshToken> = refreshTokenGrant.handle(
        request,
        client,
      );
      assertStrictEquals(Promise.resolve(result), result);
      const token: RefreshToken = await result;

      assertStrictEquals(getRefreshToken.calls.length, 1);
      let call: SpyCall = getRefreshToken.calls[0];
      assertStrictEquals(call.self, tokenService);
      assertEquals(call.args, ["example"]);

      assertStrictEquals(generateToken.calls.length, 1);
      call = generateToken.calls[0];
      assertClientUserScopeCall(call, refreshTokenGrant, client, user, scope);

      assertStrictEquals(revoke.calls.length, 1);
      call = revoke.calls[0];
      assertStrictEquals(call.args.length, 1);
      assertToken(call.args[0], {
        accessToken: "fake",
        refreshToken: "example",
        refreshTokenExpiresAt,
        client,
        user,
        scope,
      });

      const expectedToken: RefreshToken = {
        accessToken: "x",
        refreshToken: "example",
        accessTokenExpiresAt,
        refreshTokenExpiresAt,
        client,
        user,
        scope,
      };
      assertStrictEquals(save.calls.length, 1);
      call = save.calls[0];
      assertStrictEquals(call.args.length, 1);
      assertToken(call.args[0], expectedToken);
      assertToken(token, expectedToken);
    } finally {
      getRefreshToken.restore();
      save.restore();
      revoke.restore();
      generateToken.restore();
    }
  },
);

test(
  handleTests,
  "returns new token with same code and revokes old",
  async () => {
    const getRefreshToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "getRefreshToken",
      (refreshToken: string) =>
        Promise.resolve({
          accessToken: "fake",
          refreshToken,
          code: "z",
          client,
          user,
          scope,
        }),
    );
    const save: Spy<RefreshTokenService> = spy(tokenService, "save");
    const revoke: Spy<RefreshTokenService> = spy(tokenService, "revoke");
    const accessTokenExpiresAt: Date = new Date(Date.now() + 1000);
    const refreshTokenExpiresAt: Date = new Date(Date.now() + 2000);
    const generateToken: Stub<RefreshTokenGrant> = stub(
      refreshTokenGrant,
      "generateToken",
      (client: Client, user: User, scope: Scope) =>
        Promise.resolve({
          accessToken: "x",
          refreshToken: "y",
          accessTokenExpiresAt,
          refreshTokenExpiresAt,
          client,
          user,
          scope,
        }),
    );

    try {
      const request: OAuth2Request = fakeTokenRequest("refresh_token=example");
      const result: Promise<RefreshToken> = refreshTokenGrant.handle(
        request,
        client,
      );
      assertStrictEquals(Promise.resolve(result), result);
      const token: RefreshToken = await result;

      assertStrictEquals(getRefreshToken.calls.length, 1);
      let call: SpyCall = getRefreshToken.calls[0];
      assertStrictEquals(call.self, tokenService);
      assertEquals(call.args, ["example"]);

      assertStrictEquals(generateToken.calls.length, 1);
      call = generateToken.calls[0];
      assertClientUserScopeCall(call, refreshTokenGrant, client, user, scope);

      assertStrictEquals(revoke.calls.length, 1);
      call = revoke.calls[0];
      assertStrictEquals(call.args.length, 1);
      assertToken(call.args[0], {
        accessToken: "fake",
        refreshToken: "example",
        client,
        user,
        scope,
        code: "z",
      });

      const expectedToken: RefreshToken = {
        accessToken: "x",
        refreshToken: "y",
        accessTokenExpiresAt,
        refreshTokenExpiresAt,
        client,
        user,
        scope,
        code: "z",
      };
      assertStrictEquals(save.calls.length, 1);
      call = save.calls[0];
      assertStrictEquals(call.args.length, 1);
      assertToken(call.args[0], expectedToken);
      assertToken(token, expectedToken);
    } finally {
      getRefreshToken.restore();
      save.restore();
      revoke.restore();
      generateToken.restore();
    }
  },
);
