import {
  AuthorizationCodeGrant,
  AuthorizationCodeGrantServices,
} from "./authorization_code.ts";
import { RefreshTokenService, Token } from "../models/token.ts";
import type { Client, ClientService } from "../models/client.ts";
import type {
  AuthorizationCode,
  AuthorizationCodeService,
} from "../models/authorization_code.ts";
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
import { ExampleAuthorizationCodeService } from "../models/authorization_code_test.ts";
import { InvalidGrant, InvalidRequest } from "../errors.ts";
import { OAuth2Request } from "../context.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { ExampleRefreshTokenService } from "../models/token_test.ts";
import { User } from "../models/user.ts";
import { assertClientUserScopeCall, assertToken } from "../asserts.ts";
import { ExampleClientService } from "../models/client_test.ts";

const authorizationCodeGrantTests: TestSuite<void> = new TestSuite({
  name: "AuthorizationCodeGrant",
});

const handleTests: TestSuite<void> = new TestSuite({
  name: "handle",
  suite: authorizationCodeGrantTests,
});

const client: Client = {
  id: "1",
  grants: ["authorization_code"],
};
const clientService: ClientService = new ExampleClientService({ client });
const tokenService: RefreshTokenService = new ExampleRefreshTokenService();
const authorizationCodeService: AuthorizationCodeService =
  new ExampleAuthorizationCodeService();
const services: AuthorizationCodeGrantServices = {
  clientService,
  tokenService,
  authorizationCodeService,
};
const authorizationCodeGrant: AuthorizationCodeGrant =
  new AuthorizationCodeGrant({ services });

test(handleTests, "request body required", async () => {
  const request: OAuth2Request = fakeTokenRequest();
  const result: Promise<Token> = authorizationCodeGrant.handle(
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

test(handleTests, "code parameter required", async () => {
  let request: OAuth2Request = fakeTokenRequest("");
  const result: Promise<Token> = authorizationCodeGrant.handle(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(
    () => result,
    InvalidRequest,
    "code parameter required",
  );

  request = fakeTokenRequest("username=");
  await assertThrowsAsync(
    () => authorizationCodeGrant.handle(request, client),
    InvalidRequest,
    "code parameter required",
  );
});

test(handleTests, "code already used", async () => {
  const revokeCode: Stub<RefreshTokenService> = stub(
    tokenService,
    "revokeCode",
    (_code: string) => Promise.resolve(true),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("code=1");
    const result: Promise<Token> = authorizationCodeGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "code already used",
    );
    assertStrictEquals(revokeCode.calls.length, 1);
    const call: SpyCall = revokeCode.calls[0];
    assertStrictEquals(call.self, tokenService);
    assertEquals(call.args, ["1"]);
  } finally {
    revokeCode.restore();
  }
});

test(handleTests, "invalid code", async () => {
  const get: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "get",
    (_code: string) => Promise.resolve(undefined),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("code=1");
    const result: Promise<Token> = authorizationCodeGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "invalid code",
    );
    assertStrictEquals(get.calls.length, 1);
    const call: SpyCall = get.calls[0];
    assertStrictEquals(call.self, authorizationCodeService);
    assertEquals(call.args, ["1"]);
  } finally {
    get.restore();
  }
});

test(handleTests, "code was issued to another client", async () => {
  const originalGet = authorizationCodeService.get;
  const get: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "get",
    async (code: string) => ({
      ...await originalGet.call(authorizationCodeService, code),
      client: { id: "2" },
    }),
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("code=1");
    const result: Promise<Token> = authorizationCodeGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "code was issued to another client",
    );
    assertStrictEquals(get.calls.length, 1);
    const call: SpyCall = get.calls[0];
    assertStrictEquals(call.self, authorizationCodeService);
    assertEquals(call.args, ["1"]);
  } finally {
    get.restore();
  }
});

test(handleTests, "redirect_uri parameter required", async () => {
  const get: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "get",
  );
  try {
    let request: OAuth2Request = fakeTokenRequest("code=1");
    const result: Promise<Token> = authorizationCodeGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "redirect_uri parameter required",
    );
    assertStrictEquals(get.calls.length, 1);
    let call: SpyCall = get.calls[0];
    assertStrictEquals(call.self, authorizationCodeService);
    assertEquals(call.args, ["1"]);

    request = fakeTokenRequest("code=1&redirect_uri=");
    await assertThrowsAsync(
      () => authorizationCodeGrant.handle(request, client),
      InvalidGrant,
      "redirect_uri parameter required",
    );
    assertStrictEquals(get.calls.length, 2);
    call = get.calls[1];
    assertStrictEquals(call.self, authorizationCodeService);
    assertEquals(call.args, ["1"]);
  } finally {
    get.restore();
  }
});

test(handleTests, "incorrect redirect_uri", async () => {
  const get: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "get",
  );
  try {
    let request: OAuth2Request = fakeTokenRequest(
      `code=1&redirect_uri=${
        encodeURIComponent("http://oauth2.example.com/code")
      }`,
    );
    const result: Promise<Token> = authorizationCodeGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "incorrect redirect_uri",
    );
    assertStrictEquals(get.calls.length, 1);
    let call: SpyCall = get.calls[0];
    assertStrictEquals(call.self, authorizationCodeService);
    assertEquals(call.args, ["1"]);

    request = fakeTokenRequest(
      `code=1&redirect_uri=${
        encodeURIComponent("https://oauth2.example.com/code?client_id=1")
      }`,
    );
    await assertThrowsAsync(
      () => authorizationCodeGrant.handle(request, client),
      InvalidGrant,
      "incorrect redirect_uri",
    );
    assertStrictEquals(get.calls.length, 2);
    call = get.calls[1];
    assertStrictEquals(call.self, authorizationCodeService);
    assertEquals(call.args, ["1"]);
  } finally {
    get.restore();
  }
});

test(handleTests, "returns token", async () => {
  const get: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "get",
  );
  const save: Spy<RefreshTokenService> = spy(tokenService, "save");
  const accessTokenExpiresAt: Date = new Date(Date.now() + 1000);
  const refreshTokenExpiresAt: Date = new Date(Date.now() + 2000);
  const generateToken: Stub<AuthorizationCodeGrant> = stub(
    authorizationCodeGrant,
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
      `code=1&redirect_uri=${
        encodeURIComponent("https://oauth2.example.com/code")
      }`,
    );
    const result: Promise<Token> = authorizationCodeGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    const token: Token = await result;

    assertStrictEquals(get.calls.length, 1);
    let call: SpyCall = get.calls[0];
    assertStrictEquals(call.self, authorizationCodeService);
    assertEquals(call.args, ["1"]);
    const { user, scope }: AuthorizationCode = await call.returned;

    assertStrictEquals(generateToken.calls.length, 1);
    call = generateToken.calls[0];
    assertClientUserScopeCall(
      call,
      authorizationCodeGrant,
      client,
      user,
      scope,
    );

    const expectedToken: Token = {
      accessToken: "x",
      refreshToken: "y",
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
      client,
      user,
      scope,
      code: "1",
    };
    assertStrictEquals(save.calls.length, 1);
    call = save.calls[0];
    assertStrictEquals(call.args.length, 1);
    assertToken(call.args[0], expectedToken);
    assertToken(token, expectedToken);
  } finally {
    get.restore();
    save.restore();
    generateToken.restore();
  }
});
