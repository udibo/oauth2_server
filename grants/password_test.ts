import { PasswordGrant, PasswordGrantServices } from "./password.ts";
import { Token } from "../models/token.ts";
import type { Client } from "../models/client.ts";
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
import {
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  ServerError,
} from "../errors.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { assertClientUserScopeCall, assertToken } from "../asserts.ts";
import {
  ClientService,
  RefreshTokenService,
  scope,
  UserService,
} from "../services/test_services.ts";
import { User } from "../models/user.ts";

const passwordGrantTests = describe({
  name: "PasswordGrant",
});

const tokenTests = describe({
  name: "token",
  suite: passwordGrantTests,
});

const client: Client = {
  id: "1",
  grants: ["password"],
};
const clientService = new ClientService({ client });
const tokenService = new RefreshTokenService({
  client,
});
const userService = new UserService();
const services: PasswordGrantServices<Client, User, Scope> = {
  clientService,
  tokenService,
  userService,
};
const passwordGrant = new PasswordGrant({ services });

it(tokenTests, "not implemented for UserService", async () => {
  const getAuthenticated: Spy<UserService> = spy(
    userService,
    "getAuthenticated",
  );
  try {
    let request = fakeTokenRequest(
      "username=kyle&password=hunter2",
    );
    const result = passwordGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      ServerError,
      "userService.getAuthenticated not implemented",
    );
    assertStrictEquals(getAuthenticated.calls.length, 1);
    let call = getAuthenticated.calls[0];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, ["kyle", "hunter2"]);

    request = fakeTokenRequest("username=John&password=Doe");
    await assertRejects(
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

it(tokenTests, "invalid scope", async () => {
  let request = fakeTokenRequest("scope=\\");
  const result = passwordGrant.token(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertRejects(
    () => result,
    InvalidScopeError,
    "invalid scope",
  );

  request = fakeTokenRequest("scope= ");
  await assertRejects(
    () => passwordGrant.token(request, client),
    InvalidScopeError,
    "invalid scope",
  );
});

it(tokenTests, "username parameter required", async () => {
  let request = fakeTokenRequest("");
  const result = passwordGrant.token(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertRejects(
    () => result,
    InvalidRequestError,
    "username parameter required",
  );

  request = fakeTokenRequest("username=");
  await assertRejects(
    () => passwordGrant.token(request, client),
    InvalidRequestError,
    "username parameter required",
  );
});

it(tokenTests, "password parameter required", async () => {
  let request = fakeTokenRequest("username=kyle");
  const result = passwordGrant.token(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertRejects(
    () => result,
    InvalidRequestError,
    "password parameter required",
  );

  request = fakeTokenRequest("username=kyle&password=");
  await assertRejects(
    () => passwordGrant.token(request, client),
    InvalidRequestError,
    "password parameter required",
  );
});

it(tokenTests, "user authentication failed", async () => {
  const getAuthenticated: Stub<UserService> = stub(
    userService,
    "getAuthenticated",
    (_username: string, _password: string) => Promise.resolve(undefined),
  );
  try {
    const request = fakeTokenRequest(
      "username=Kyle&password=Hunter2",
    );
    const result = passwordGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidGrantError,
      "user authentication failed",
    );
    assertStrictEquals(getAuthenticated.calls.length, 1);
    const call = getAuthenticated.calls[0];
    assertStrictEquals(call.self, userService);
    assertEquals(call.args, ["Kyle", "Hunter2"]);
  } finally {
    getAuthenticated.restore();
  }
});

it(tokenTests, "scope not accepted", async () => {
  const user = { username: "Kyle" };
  const getAuthenticated: Stub<UserService> = stub(
    userService,
    "getAuthenticated",
    (username: string, _password: string) => Promise.resolve({ username }),
  );
  const acceptedScope = stub(
    passwordGrant,
    "acceptedScope",
    () => Promise.reject(new InvalidScopeError("invalid scope")),
  );
  try {
    const request = fakeTokenRequest(
      "username=Kyle&password=Hunter2&scope=read write",
    );
    const result = passwordGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidScopeError,
      "invalid scope",
    );

    assertClientUserScopeCall(
      acceptedScope,
      0,
      passwordGrant,
      client,
      user,
      scope,
    );
    assertSpyCalls(acceptedScope, 1);
  } finally {
    getAuthenticated.restore();
    acceptedScope.restore();
  }
});

it(tokenTests, "returns token", async () => {
  const getAuthenticated = stub(
    userService,
    "getAuthenticated",
    (username: string, _password: string) => Promise.resolve({ username }),
  );
  const save = spy(tokenService, "save");
  const accessTokenExpiresAt: Date = new Date(Date.now() + 1000);
  const refreshTokenExpiresAt: Date = new Date(Date.now() + 2000);
  const generateToken = stub(
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
  const expectedScope = new Scope("read");
  const acceptedScope = stub(
    passwordGrant,
    "acceptedScope",
    () => Promise.resolve(expectedScope),
  );
  try {
    const request = fakeTokenRequest(
      "username=Kyle&password=Hunter2&scope=read write",
    );
    const result = passwordGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    const token = await result;

    assertStrictEquals(getAuthenticated.calls.length, 1);
    const getCall = getAuthenticated.calls[0];
    assertStrictEquals(getCall.self, userService);
    assertEquals(getCall.args, ["Kyle", "Hunter2"]);
    const user = await getCall.returned;

    assertClientUserScopeCall(
      acceptedScope,
      0,
      passwordGrant,
      client,
      user,
      scope,
    );
    assertSpyCalls(acceptedScope, 1);

    assertClientUserScopeCall(
      generateToken,
      0,
      passwordGrant,
      client,
      user,
      expectedScope,
    );
    assertSpyCalls(generateToken, 1);

    const expectedToken: Token<Client, User, Scope> = {
      accessToken: "x",
      refreshToken: "y",
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
      client,
      user: user!,
      scope: expectedScope,
    };
    assertStrictEquals(save.calls.length, 1);
    const saveCall = save.calls[0];
    assertStrictEquals(saveCall.args.length, 1);
    assertToken(saveCall.args[0], expectedToken);
    assertToken(token, expectedToken);
  } finally {
    getAuthenticated.restore();
    save.restore();
    generateToken.restore();
    acceptedScope.restore();
  }
});
