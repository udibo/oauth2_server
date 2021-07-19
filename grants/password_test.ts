import { PasswordGrant, PasswordGrantServices } from "./password.ts";
import { RefreshTokenService, Token } from "../models/token.ts";
import type { Client, ClientService } from "../models/client.ts";
import type { User, UserService } from "../models/user.ts";
import { Scope } from "../models/scope.ts";
import {
  assertEquals,
  assertSpyCalls,
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
import { assertClientUserScopeCall, assertToken } from "../asserts.ts";
import { ExampleClientService } from "../models/client_test.ts";

const passwordGrantTests: TestSuite<void> = new TestSuite({
  name: "PasswordGrant",
});

const tokenTests: TestSuite<void> = new TestSuite({
  name: "token",
  suite: passwordGrantTests,
});

const client: Client = {
  id: "1",
  grants: ["password"],
};
const clientService: ClientService = new ExampleClientService({ client });
const tokenService: RefreshTokenService = new ExampleRefreshTokenService();
const userService: UserService = new ExampleUserService();
const services: PasswordGrantServices = {
  clientService,
  tokenService,
  userService,
};
const passwordGrant: PasswordGrant = new PasswordGrant({ services });

test(tokenTests, "not implemented for UserService", async () => {
  const getAuthenticated: Spy<UserService> = spy(
    userService,
    "getAuthenticated",
  );
  try {
    let request: OAuth2Request = fakeTokenRequest(
      "username=kyle&password=hunter2",
    );
    const result: Promise<Token> = passwordGrant.token(
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
      () => passwordGrant.token(request, client),
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

test(tokenTests, "request body required", async () => {
  const request: OAuth2Request = fakeTokenRequest();
  const result: Promise<Token> = passwordGrant.token(
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

test(tokenTests, "invalid scope", async () => {
  let request: OAuth2Request = fakeTokenRequest("scope=\\");
  const result: Promise<Token> = passwordGrant.token(
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
    () => passwordGrant.token(request, client),
    InvalidScope,
    "invalid scope",
  );
});

test(tokenTests, "username parameter required", async () => {
  let request: OAuth2Request = fakeTokenRequest("");
  const result: Promise<Token> = passwordGrant.token(
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
    () => passwordGrant.token(request, client),
    InvalidRequest,
    "username parameter required",
  );
});

test(tokenTests, "password parameter required", async () => {
  let request: OAuth2Request = fakeTokenRequest("username=kyle");
  const result: Promise<Token> = passwordGrant.token(
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
    () => passwordGrant.token(request, client),
    InvalidRequest,
    "password parameter required",
  );
});

test(tokenTests, "user authentication failed", async () => {
  const getAuthenticated: Stub<UserService> = stub(
    userService,
    "getAuthenticated",
    (_username: string, _password: string) => Promise.resolve(undefined),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest(
      "username=Kyle&password=Hunter2",
    );
    const result: Promise<Token> = passwordGrant.token(
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
    const call: SpyCall = getAuthenticated.calls[0];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, ["Kyle", "Hunter2"]);
  } finally {
    getAuthenticated.restore();
  }
});

test(tokenTests, "returns token", async () => {
  const getAuthenticated: Stub<UserService> = stub(
    userService,
    "getAuthenticated",
    (username: string, _password: string) => Promise.resolve({ username }),
  );
  const save: Spy<RefreshTokenService> = spy(tokenService, "save");
  const accessTokenExpiresAt: Date = new Date(Date.now() + 1000);
  const refreshTokenExpiresAt: Date = new Date(Date.now() + 2000);
  const generateToken: Stub<PasswordGrant> = stub(
    passwordGrant,
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
    const request: OAuth2Request = fakeTokenRequest(
      "username=Kyle&password=Hunter2&scope=read",
    );
    const result: Promise<Token> = passwordGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    const token: Token = await result;

    assertStrictEquals(getAuthenticated.calls.length, 1);
    let call: SpyCall = getAuthenticated.calls[0];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, ["Kyle", "Hunter2"]);
    const user: User = await call.returned;

    const scope: Scope = new Scope("read");
    assertClientUserScopeCall(
      generateToken,
      0,
      passwordGrant,
      client,
      user,
      scope,
    );
    assertSpyCalls(generateToken, 1);

    const expectedToken: Token = {
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
    getAuthenticated.restore();
    save.restore();
    generateToken.restore();
  }
});
