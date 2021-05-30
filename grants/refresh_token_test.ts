import { RefreshTokenGrant } from "./refresh_token.ts";
import {
  AccessTokenService,
  RefreshToken,
  RefreshTokenService,
} from "../models/token.ts";
import type { Client } from "../models/client.ts";
import type { User } from "../models/user.ts";
import { Scope } from "../models/scope.ts";
import { test, TestSuite } from "../deps/udibo/test_suite/mod.ts";
import {
  assertEquals,
  assertStrictEquals,
  assertThrowsAsync,
} from "../deps/std/testing/asserts.ts";
import { Spy, spy, SpyCall, Stub, stub } from "../deps/udibo/mock/mod.ts";
import {
  ExampleAccessTokenService,
  ExampleRefreshTokenService,
} from "../models/token_test.ts";
import { InvalidGrant, InvalidRequest, ServerError } from "../errors.ts";
import { OAuth2Request } from "../context.ts";
import { fakeTokenRequest } from "../test_context.ts";

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

test(handleTests, "not implemented for AccessTokenService", async () => {
  const tokenService: AccessTokenService = new ExampleAccessTokenService();
  const getRefreshToken: Spy<AccessTokenService> = spy(
    tokenService,
    "getRefreshToken",
  );
  const refreshTokenGrant: RefreshTokenGrant = new RefreshTokenGrant({
    services: {
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

const user: User = {};
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
      InvalidGrant,
      "refresh_token was issued to another client",
    );
    assertStrictEquals(getRefreshToken.calls.length, 1);
    let call: SpyCall = getRefreshToken.calls[0];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, ["example1"]);

    request = fakeTokenRequest("refresh_token=example2");
    await assertThrowsAsync(
      () => refreshTokenGrant.handle(request, client),
      InvalidGrant,
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
    (refreshToken: string) => ({
      accessToken: "fake",
      refreshToken,
      client,
      user,
      scope,
    }),
  );

  const expectedExpiresAts: Date[] = [
    new Date(Date.now() + 1000),
    new Date(new Date(Date.now() + 2000)),
  ];
  const expectedAccessTokens: string[] = ["access1", "access2"];
  const expectedRefreshTokens: string[] = ["refresh1", "refresh2"];

  const generateAccessToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "generateAccessToken",
    [...expectedAccessTokens],
  );
  const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
    tokenService,
    "accessTokenExpiresAt",
    [...expectedExpiresAts],
  );
  const generateRefreshToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "generateRefreshToken",
    [...expectedRefreshTokens],
  );
  const refreshTokenExpiresAt: Stub<RefreshTokenService> = stub(
    tokenService,
    "refreshTokenExpiresAt",
    [...expectedExpiresAts],
  );
  const save: Spy<RefreshTokenService> = spy(tokenService, "save");
  const revoke: Spy<RefreshTokenService> = spy(tokenService, "revoke");

  function assertCalls(
    idx: number,
    refreshToken: string,
    nextRefreshToken: RefreshToken,
  ): void {
    const length = idx + 1;
    assertStrictEquals(getRefreshToken.calls.length, length);
    let call: SpyCall = getRefreshToken.calls[idx];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, [refreshToken]);

    assertStrictEquals(generateAccessToken.calls.length, length);
    call = generateAccessToken.calls[idx];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, [client, user, scope]);

    assertStrictEquals(accessTokenExpiresAt.calls.length, length);
    call = accessTokenExpiresAt.calls[idx];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, [client, user, scope]);

    assertStrictEquals(generateRefreshToken.calls.length, length);
    call = generateRefreshToken.calls[idx];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, [client, user, scope]);

    assertStrictEquals(refreshTokenExpiresAt.calls.length, length);
    call = refreshTokenExpiresAt.calls[idx];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, [client, user, scope]);

    assertStrictEquals(save.calls.length, length);
    call = save.calls[idx];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, [{
      accessToken: expectedAccessTokens[idx],
      accessTokenExpiresAt: expectedExpiresAts[idx],
      refreshToken: expectedRefreshTokens[idx],
      refreshTokenExpiresAt: expectedExpiresAts[idx],
      client,
      user,
      scope,
    }]);

    assertStrictEquals(revoke.calls.length, length);
    call = revoke.calls[idx];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, [{
      accessToken: "fake",
      refreshToken,
      client,
      user,
      scope,
    }]);

    assertEquals(nextRefreshToken, {
      accessToken: expectedAccessTokens[idx],
      accessTokenExpiresAt: expectedExpiresAts[idx],
      refreshToken: expectedRefreshTokens[idx],
      refreshTokenExpiresAt: expectedExpiresAts[idx],
      client,
      user,
      scope,
    });
  }

  try {
    let request: OAuth2Request = fakeTokenRequest("refresh_token=example1");
    const result: Promise<RefreshToken> = refreshTokenGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    assertCalls(0, "example1", await result);

    request = fakeTokenRequest("refresh_token=example2");
    assertCalls(1, "example2", await refreshTokenGrant.handle(request, client));
  } finally {
    getRefreshToken.restore();
    generateAccessToken.restore();
    accessTokenExpiresAt.restore();
    generateRefreshToken.restore();
    refreshTokenExpiresAt.restore();
    save.restore();
    revoke.restore();
  }
});

test(
  handleTests,
  "returns new token with same code and revokes old",
  async () => {
    const getRefreshToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "getRefreshToken",
      (refreshToken: string) => ({
        accessToken: "fake",
        refreshToken,
        client,
        user,
        scope,
        code: "foo",
      }),
    );

    const expectedExpiresAts: Date[] = [
      new Date(Date.now() + 1000),
      new Date(new Date(Date.now() + 2000)),
    ];
    const expectedAccessTokens: string[] = ["access1", "access2"];
    const expectedRefreshTokens: string[] = ["refresh1", "refresh2"];

    const generateAccessToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateAccessToken",
      [...expectedAccessTokens],
    );
    const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "accessTokenExpiresAt",
      [...expectedExpiresAts],
    );
    const generateRefreshToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateRefreshToken",
      [...expectedRefreshTokens],
    );
    const refreshTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "refreshTokenExpiresAt",
      [...expectedExpiresAts],
    );
    const save: Spy<RefreshTokenService> = spy(tokenService, "save");
    const revoke: Spy<RefreshTokenService> = spy(tokenService, "revoke");

    function assertCalls(
      idx: number,
      refreshToken: string,
      nextRefreshToken: RefreshToken,
    ): void {
      const length = idx + 1;
      assertStrictEquals(getRefreshToken.calls.length, length);
      let call: SpyCall = getRefreshToken.calls[idx];
      assertStrictEquals(call.self, tokenService);
      assertEquals(call.args, [refreshToken]);

      assertStrictEquals(generateAccessToken.calls.length, length);
      call = generateAccessToken.calls[idx];
      assertStrictEquals(call.self, tokenService);
      assertEquals(call.args, [client, user, scope]);

      assertStrictEquals(accessTokenExpiresAt.calls.length, length);
      call = accessTokenExpiresAt.calls[idx];
      assertStrictEquals(call.self, tokenService);
      assertEquals(call.args, [client, user, scope]);

      assertStrictEquals(generateRefreshToken.calls.length, length);
      call = generateRefreshToken.calls[idx];
      assertStrictEquals(call.self, tokenService);
      assertEquals(call.args, [client, user, scope]);

      assertStrictEquals(refreshTokenExpiresAt.calls.length, length);
      call = refreshTokenExpiresAt.calls[idx];
      assertStrictEquals(call.self, tokenService);
      assertEquals(call.args, [client, user, scope]);

      assertStrictEquals(save.calls.length, length);
      call = save.calls[idx];
      assertStrictEquals(call.self, tokenService);
      assertEquals(call.args, [{
        accessToken: expectedAccessTokens[idx],
        accessTokenExpiresAt: expectedExpiresAts[idx],
        refreshToken: expectedRefreshTokens[idx],
        refreshTokenExpiresAt: expectedExpiresAts[idx],
        client,
        user,
        scope,
        code: "foo",
      }]);

      assertStrictEquals(revoke.calls.length, length);
      call = revoke.calls[idx];
      assertStrictEquals(call.self, tokenService);
      assertEquals(call.args, [{
        accessToken: "fake",
        refreshToken,
        client,
        user,
        scope,
        code: "foo",
      }]);

      assertEquals(nextRefreshToken, {
        accessToken: expectedAccessTokens[idx],
        accessTokenExpiresAt: expectedExpiresAts[idx],
        refreshToken: expectedRefreshTokens[idx],
        refreshTokenExpiresAt: expectedExpiresAts[idx],
        client,
        user,
        scope,
        code: "foo",
      });
    }

    try {
      let request: OAuth2Request = fakeTokenRequest("refresh_token=example1");
      const result: Promise<RefreshToken> = refreshTokenGrant.handle(
        request,
        client,
      );
      assertStrictEquals(Promise.resolve(result), result);
      assertCalls(0, "example1", await result);

      request = fakeTokenRequest("refresh_token=example2");
      assertCalls(
        1,
        "example2",
        await refreshTokenGrant.handle(request, client),
      );
    } finally {
      getRefreshToken.restore();
      generateAccessToken.restore();
      accessTokenExpiresAt.restore();
      generateRefreshToken.restore();
      refreshTokenExpiresAt.restore();
      save.restore();
      revoke.restore();
    }
  },
);
