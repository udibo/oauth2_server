import { PasswordGrant, PasswordGrantServices } from "./password.ts";
import { RefreshTokenService, Token } from "../models/token.ts";
import type { Client } from "../models/client.ts";
import type { User, UserService } from "../models/user.ts";
import { Scope, ScopeInterface } from "../models/scope.ts";
import { test, TestSuite } from "../deps/udibo/test_suite/mod.ts";
import {
  assert,
  assertEquals,
  assertStrictEquals,
  assertThrowsAsync,
} from "../deps/std/testing/asserts.ts";
import { Spy, spy, SpyCall, Stub, stub } from "../deps/udibo/mock/mod.ts";
import { ExampleUserService } from "../models/user_test.ts";
import {
  InvalidGrant,
  InvalidRequest,
  InvalidScope,
  ServerError,
} from "../errors.ts";
import { OAuth2Request } from "../context.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { ExampleRefreshTokenService } from "../models/token_test.ts";

const passwordGrantTests: TestSuite<void> = new TestSuite({
  name: "PasswordGrant",
});

const handleTests: TestSuite<void> = new TestSuite({
  name: "handle",
  suite: passwordGrantTests,
});

const client: Client = {
  id: "1",
  grants: ["password"],
};

const tokenService: RefreshTokenService = new ExampleRefreshTokenService();
const userService: UserService = new ExampleUserService();
const services: PasswordGrantServices = {
  tokenService,
  userService,
};
const passwordGrant: PasswordGrant = new PasswordGrant({ services });

test(handleTests, "not implemented for UserService", async () => {
  const getAuthenticated: Spy<UserService> = spy(
    userService,
    "getAuthenticated",
  );
  try {
    let request: OAuth2Request = fakeTokenRequest(
      "username=kyle&password=hunter2",
    );
    const result: Promise<Token> = passwordGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      ServerError,
      "userService.getAuthenticated not implemented",
    );
    assertStrictEquals(getAuthenticated.calls.length, 1);
    let call: SpyCall = getAuthenticated.calls[0];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, ["kyle", "hunter2"]);

    request = fakeTokenRequest("username=John&password=Doe");
    await assertThrowsAsync(
      () => passwordGrant.handle(request, client),
      ServerError,
      "userService.getAuthenticated not implemented",
    );
    assertStrictEquals(getAuthenticated.calls.length, 2);
    call = getAuthenticated.calls[1];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, ["John", "Doe"]);
  } finally {
    getAuthenticated.restore();
  }
});

test(handleTests, "request body required", async () => {
  const request: OAuth2Request = fakeTokenRequest();
  const result: Promise<Token> = passwordGrant.handle(
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

test(handleTests, "invalid scope", async () => {
  let request: OAuth2Request = fakeTokenRequest("scope=\\");
  const result: Promise<Token> = passwordGrant.handle(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(
    () => result,
    InvalidScope,
    "invalid scope",
  );

  request = fakeTokenRequest("scope= ");
  await assertThrowsAsync(
    () => passwordGrant.handle(request, client),
    InvalidScope,
    "invalid scope",
  );
});

test(handleTests, "username parameter required", async () => {
  let request: OAuth2Request = fakeTokenRequest("");
  const result: Promise<Token> = passwordGrant.handle(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(
    () => result,
    InvalidRequest,
    "username parameter required",
  );

  request = fakeTokenRequest("username=");
  await assertThrowsAsync(
    () => passwordGrant.handle(request, client),
    InvalidRequest,
    "username parameter required",
  );
});

test(handleTests, "password parameter required", async () => {
  let request: OAuth2Request = fakeTokenRequest("username=kyle");
  const result: Promise<Token> = passwordGrant.handle(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(
    () => result,
    InvalidRequest,
    "password parameter required",
  );

  request = fakeTokenRequest("username=kyle&password=");
  await assertThrowsAsync(
    () => passwordGrant.handle(request, client),
    InvalidRequest,
    "password parameter required",
  );
});

test(handleTests, "user authentication failed", async () => {
  const getAuthenticated: Stub<UserService> = stub(
    userService,
    "getAuthenticated",
    (_username: string, _password: string) => undefined,
  );
  try {
    let request: OAuth2Request = fakeTokenRequest(
      "username=kyle&password=hunter2",
    );
    const result: Promise<Token> = passwordGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "user authentication failed",
    );
    assertStrictEquals(getAuthenticated.calls.length, 1);
    let call: SpyCall = getAuthenticated.calls[0];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, ["kyle", "hunter2"]);

    request = fakeTokenRequest("username=John&password=Doe");
    await assertThrowsAsync(
      () => passwordGrant.handle(request, client),
      InvalidGrant,
      "user authentication failed",
    );
    assertStrictEquals(getAuthenticated.calls.length, 2);
    call = getAuthenticated.calls[1];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, ["John", "Doe"]);
  } finally {
    getAuthenticated.restore();
  }
});

function assertScope(
  actual: ScopeInterface | undefined,
  expected: ScopeInterface | undefined,
): void {
  if (expected && actual) {
    assert(typeof actual !== "string");
    assert(expected.equals(actual));
  } else {
    assertEquals(actual, expected);
  }
}

function assertToken(actual: Token, expected: Token): void {
  assertScope(actual.scope, expected.scope);
  assertEquals(actual, {
    ...expected,
    scope: actual.scope,
  });
}

function assertClientUserScopeCall(
  call: SpyCall,
  client: Client,
  user: User,
  expectedScope: Scope | undefined,
): void {
  assertStrictEquals(call.self, tokenService);
  assertEquals(call.args.length, 3);
  assertEquals(call.args.slice(0, 2), [client, user]);
  const actualScope: Scope | undefined = call.args[2];
  assertScope(actualScope, expectedScope);
}

test(handleTests, "returns accessToken", async () => {
  const getAuthenticated: Stub<UserService> = stub(
    userService,
    "getAuthenticated",
    (username: string, _password: string) => ({ username }),
  );

  const expectedAccessTokens: string[] = ["access1", "access2"];

  const expectedExpiresAts: Date[] = [
    new Date(Date.now() + 1000),
    new Date(new Date(Date.now() + 2000)),
  ];
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
  );
  const refreshTokenExpiresAt: Stub<RefreshTokenService> = stub(
    tokenService,
    "refreshTokenExpiresAt",
  );
  const save: Spy<RefreshTokenService> = spy(tokenService, "save");

  function assertCalls(
    idx: number,
    username: string,
    password: string,
    scopeText: string | undefined,
    result: Token,
  ): void {
    const length = idx + 1;
    assertStrictEquals(getAuthenticated.calls.length, length);
    let call: SpyCall = getAuthenticated.calls[idx];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, [username, password]);

    const user: User = { username };
    const expectedScope: Scope | undefined = scopeText
      ? new Scope(scopeText)
      : undefined;
    assertStrictEquals(generateAccessToken.calls.length, length);
    call = generateAccessToken.calls[idx];
    assertClientUserScopeCall(call, client, user, expectedScope);

    assertStrictEquals(accessTokenExpiresAt.calls.length, length);
    call = accessTokenExpiresAt.calls[idx];
    assertClientUserScopeCall(call, client, user, expectedScope);

    assertStrictEquals(generateRefreshToken.calls.length, 0);
    assertStrictEquals(refreshTokenExpiresAt.calls.length, 0);

    assertStrictEquals(save.calls.length, length);
    call = save.calls[idx];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args.length, 1);
    const expectedToken: Token = {
      accessToken: expectedAccessTokens[idx],
      accessTokenExpiresAt: expectedExpiresAts[idx],
      client,
      user,
      scope: expectedScope,
    };
    assertToken(call.args[0], expectedToken);

    assertToken(result, expectedToken);
  }

  try {
    let request: OAuth2Request = fakeTokenRequest(
      "username=kyle&password=hunter2",
    );
    const result: Promise<Token> = passwordGrant.handle(request, client);
    assertStrictEquals(Promise.resolve(result), result);
    assertCalls(0, "kyle", "hunter2", undefined, await result);

    request = fakeTokenRequest("username=John&password=Doe&scope=read");
    assertCalls(
      1,
      "John",
      "Doe",
      "read",
      await passwordGrant.handle(request, client),
    );
  } finally {
    getAuthenticated.restore();
    generateAccessToken.restore();
    accessTokenExpiresAt.restore();
    generateRefreshToken.restore();
    refreshTokenExpiresAt.restore();
    save.restore();
  }
});

test(handleTests, "returns refreshToken", async () => {
  const getAuthenticated: Stub<UserService> = stub(
    userService,
    "getAuthenticated",
    (username: string, _password: string) => ({ username }),
  );

  const expectedAccessTokens: string[] = ["access1", "access2"];
  const expectedRefreshTokens: string[] = ["refresh1", "refresh2"];
  const expectedAccessTokenExpiresAts: Date[] = [
    new Date(Date.now() + 1000),
    new Date(new Date(Date.now() + 2000)),
  ];
  const expectedRefreshTokenExpiresAts: Date[] = [
    new Date(Date.now() + 3000),
    new Date(new Date(Date.now() + 4000)),
  ];
  const generateAccessToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "generateAccessToken",
    [...expectedAccessTokens],
  );
  const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
    tokenService,
    "accessTokenExpiresAt",
    [...expectedAccessTokenExpiresAts],
  );
  const generateRefreshToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "generateRefreshToken",
    [...expectedRefreshTokens],
  );
  const refreshTokenExpiresAt: Stub<RefreshTokenService> = stub(
    tokenService,
    "refreshTokenExpiresAt",
    [...expectedRefreshTokenExpiresAts],
  );
  const save: Spy<RefreshTokenService> = spy(tokenService, "save");

  function assertCalls(
    idx: number,
    username: string,
    password: string,
    scopeText: string | undefined,
    result: Token,
  ): void {
    const length = idx + 1;
    assertStrictEquals(getAuthenticated.calls.length, length);
    let call: SpyCall = getAuthenticated.calls[idx];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, [username, password]);

    const user: User = { username };
    const expectedScope: Scope | undefined = scopeText
      ? new Scope(scopeText)
      : undefined;
    assertStrictEquals(generateAccessToken.calls.length, length);
    call = generateAccessToken.calls[idx];
    assertClientUserScopeCall(call, client, user, expectedScope);

    assertStrictEquals(accessTokenExpiresAt.calls.length, length);
    call = accessTokenExpiresAt.calls[idx];
    assertClientUserScopeCall(call, client, user, expectedScope);

    assertStrictEquals(generateRefreshToken.calls.length, length);
    call = generateRefreshToken.calls[idx];
    assertClientUserScopeCall(call, client, user, expectedScope);

    assertStrictEquals(refreshTokenExpiresAt.calls.length, length);
    call = refreshTokenExpiresAt.calls[idx];
    assertClientUserScopeCall(call, client, user, expectedScope);

    assertStrictEquals(save.calls.length, length);
    call = save.calls[idx];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args.length, 1);
    const expectedToken: Token = {
      accessToken: expectedAccessTokens[idx],
      accessTokenExpiresAt: expectedAccessTokenExpiresAts[idx],
      refreshToken: expectedRefreshTokens[idx],
      refreshTokenExpiresAt: expectedRefreshTokenExpiresAts[idx],
      client,
      user,
      scope: expectedScope,
    };
    assertToken(call.args[0], expectedToken);

    assertToken(result, expectedToken);
  }

  try {
    const passwordGrant = new PasswordGrant({ services, refreshToken: true });
    let request: OAuth2Request = fakeTokenRequest(
      "username=kyle&password=hunter2",
    );
    const result: Promise<Token> = passwordGrant.handle(request, client);
    assertStrictEquals(Promise.resolve(result), result);
    assertCalls(0, "kyle", "hunter2", undefined, await result);

    request = fakeTokenRequest("username=John&password=Doe&scope=read");
    assertCalls(
      1,
      "John",
      "Doe",
      "read",
      await passwordGrant.handle(request, client),
    );
  } finally {
    getAuthenticated.restore();
    generateAccessToken.restore();
    accessTokenExpiresAt.restore();
    generateRefreshToken.restore();
    refreshTokenExpiresAt.restore();
    save.restore();
  }
});
