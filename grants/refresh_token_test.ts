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

const refreshTokenGrantTests: TestSuite<void> = new TestSuite({
  name: "RefreshTokenGrant",
});

const handleTests: TestSuite<void> = new TestSuite({
  name: "handle",
  suite: refreshTokenGrantTests,
});

test(handleTests, "not implemented for AccessTokenService", async () => {
  const tokenService: AccessTokenService = new ExampleAccessTokenService();
  const getRefreshToken: Spy<AccessTokenService> = spy(
    tokenService,
    "getRefreshToken",
  );
  const refreshTokenGrant: RefreshTokenGrant = new RefreshTokenGrant({
    services: {
      token: tokenService,
    },
  });
  const result: Promise<RefreshToken> = refreshTokenGrant.handle("example1");
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(() => result, Error, "not implemented");
  assertStrictEquals(getRefreshToken.calls.length, 1);
  let call: SpyCall = getRefreshToken.calls[0];
  assertStrictEquals(call.self, tokenService);
  assertEquals(call.args, ["example1"]);

  await assertThrowsAsync(
    () => refreshTokenGrant.handle("example2"),
    Error,
    "not implemented",
  );
  assertStrictEquals(getRefreshToken.calls.length, 2);
  call = getRefreshToken.calls[1];
  assertStrictEquals(call.self, tokenService);
  assertEquals(call.args, ["example2"]);
});

const client: Client = {
  id: "1",
  grants: ["refresh_token"],
};
const user: User = {};
const scope: Scope = new Scope("read");

test(handleTests, "refresh token not found", async () => {
  const tokenService: RefreshTokenService = new ExampleRefreshTokenService();
  const getRefreshToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "getRefreshToken",
    (_refreshToken: string) => undefined,
  );
  const refreshTokenGrant: RefreshTokenGrant = new RefreshTokenGrant({
    services: {
      token: tokenService,
    },
  });
  const result: Promise<RefreshToken> = refreshTokenGrant.handle("example1");
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(
    () => result,
    Error,
    "refresh token not found",
  );
  assertStrictEquals(getRefreshToken.calls.length, 1);
  let call: SpyCall = getRefreshToken.calls[0];
  assertStrictEquals(call.self, tokenService);
  assertEquals(call.args, ["example1"]);

  await assertThrowsAsync(
    () => refreshTokenGrant.handle("example2"),
    Error,
    "refresh token not found",
  );
  assertStrictEquals(getRefreshToken.calls.length, 2);
  call = getRefreshToken.calls[1];
  assertStrictEquals(call.self, tokenService);
  assertEquals(call.args, ["example2"]);
});

test(handleTests, "client missing refresh_token grant", async () => {
  const tokenService: RefreshTokenService = new ExampleRefreshTokenService();
  const getRefreshToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "getRefreshToken",
    (refreshToken: string) => ({
      accessToken: "fake",
      refreshToken: refreshToken,
      client: {
        ...client,
        grants: [],
      },
      user,
    }),
  );
  const refreshTokenGrant: RefreshTokenGrant = new RefreshTokenGrant({
    services: {
      token: tokenService,
    },
  });
  const result: Promise<RefreshToken> = refreshTokenGrant.handle("example1");
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(
    () => result,
    Error,
    "refresh_token grant type not allowed for the client",
  );
  assertStrictEquals(getRefreshToken.calls.length, 1);
  let call: SpyCall = getRefreshToken.calls[0];
  assertStrictEquals(call.self, tokenService);
  assertEquals(call.args, ["example1"]);

  await assertThrowsAsync(
    () => refreshTokenGrant.handle("example2"),
    Error,
    "refresh_token grant type not allowed for the client",
  );
  assertStrictEquals(getRefreshToken.calls.length, 2);
  call = getRefreshToken.calls[1];
  assertStrictEquals(call.self, tokenService);
  assertEquals(call.args, ["example2"]);
});

test(handleTests, "returns new token and revokes old", async () => {
  const tokenService: RefreshTokenService = new ExampleRefreshTokenService();
  const getRefreshToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "getRefreshToken",
    (refreshToken: string) => ({
      accessToken: "fake",
      refreshToken: refreshToken,
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

  const refreshTokenGrant: RefreshTokenGrant = new RefreshTokenGrant({
    services: {
      token: tokenService,
    },
  });
  const result: Promise<RefreshToken> = refreshTokenGrant.handle("example1");
  assertStrictEquals(Promise.resolve(result), result);
  assertCalls(0, "example1", await result);
  assertCalls(1, "example2", await refreshTokenGrant.handle("example2"));
});
