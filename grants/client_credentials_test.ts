import {
  ClientCredentialsGrant,
  ClientCredentialsGrantServices,
} from "./client_credentials.ts";
import { RefreshTokenService, Token } from "../models/token.ts";
import { ClientService } from "../models/client.ts";
import type { Client } from "../models/client.ts";
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
  InvalidGrant,
  InvalidRequest,
  InvalidScope,
  ServerError,
} from "../errors.ts";
import { OAuth2Request } from "../context.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { ExampleRefreshTokenService } from "../models/token_test.ts";
import { assertClientUserScopeCall } from "../asserts.ts";
import { assertToken } from "../asserts.ts";
import { ExampleClientService } from "../models/client_test.ts";

const clientCredentialsGrantTests: TestSuite<void> = new TestSuite({
  name: "ClientCredentialsGrant",
});

const handleTests: TestSuite<void> = new TestSuite({
  name: "handle",
  suite: clientCredentialsGrantTests,
});

const client: Client = {
  id: "1",
  grants: ["client_credentials"],
};
const clientService: ClientService = new ExampleClientService({ client });
const tokenService: RefreshTokenService = new ExampleRefreshTokenService();
const services: ClientCredentialsGrantServices = {
  tokenService,
  clientService,
};
const clientCredentialsGrant: ClientCredentialsGrant =
  new ClientCredentialsGrant({ services });

test(handleTests, "not implemented for UserService", async () => {
  const getUser: Spy<ClientService> = spy(
    clientService,
    "getUser",
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("");
    const result: Promise<Token> = clientCredentialsGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      ServerError,
      "clientService.getUser not implemented",
    );
    assertStrictEquals(getUser.calls.length, 1);
    const call: SpyCall = getUser.calls[0];
    assertStrictEquals(call.self, clientService);
    assertEquals(call.args.length, 1);
    assertStrictEquals(call.args[0], client);
  } finally {
    getUser.restore();
  }
});

test(handleTests, "request body required", async () => {
  const request: OAuth2Request = fakeTokenRequest();
  const result: Promise<Token> = clientCredentialsGrant.handle(
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
  const result: Promise<Token> = clientCredentialsGrant.handle(
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
    () => clientCredentialsGrant.handle(request, client),
    InvalidScope,
    "invalid scope",
  );
});

test(handleTests, "no user for client", async () => {
  const getUser: Stub<ClientService> = stub(
    clientService,
    "getUser",
    () => undefined,
  );
  try {
    const request: OAuth2Request = fakeTokenRequest("");
    const result: Promise<Token> = clientCredentialsGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "no user for client",
    );
    assertStrictEquals(getUser.calls.length, 1);
    const call: SpyCall = getUser.calls[0];
    assertStrictEquals(call.self, clientService);
    assertEquals(call.args.length, 1);
    assertStrictEquals(call.args[0], client);
  } finally {
    getUser.restore();
  }
});

test(handleTests, "returns accessToken", async () => {
  const username = "kyle";
  const getUser: Stub<ClientService> = stub(
    clientService,
    "getUser",
    (_client: Client) => ({ username }),
  );
  const save: Spy<RefreshTokenService> = spy(tokenService, "save");
  const accessTokenExpiresAt: Date = new Date(Date.now() + 1000);
  const generateToken: Stub<ClientCredentialsGrant> = stub(
    clientCredentialsGrant,
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
    const request: OAuth2Request = fakeTokenRequest("scope=read");
    const result: Promise<Token> = clientCredentialsGrant.handle(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    const token: Token = await result;

    assertStrictEquals(getUser.calls.length, 1);
    let call: SpyCall = getUser.calls[0];
    assertStrictEquals(call.self, clientService);
    assertEquals(call.args.length, 1);
    assertStrictEquals(call.args[0], client);
    const user: User = await call.returned;

    const scope: Scope = new Scope("read");
    assertStrictEquals(generateToken.calls.length, 1);
    call = generateToken.calls[0];
    assertClientUserScopeCall(
      call,
      clientCredentialsGrant,
      client,
      user,
      scope,
    );

    const expectedToken: Token = {
      accessToken: "x",
      accessTokenExpiresAt,
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
    getUser.restore();
    generateToken.restore();
    save.restore();
  }
});
