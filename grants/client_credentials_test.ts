import {
  ClientCredentialsGrant,
  ClientCredentialsGrantServices,
} from "./client_credentials.ts";
import { Token } from "../models/token.ts";
import type { Client } from "../models/client.ts";
import type { User } from "../models/user.ts";
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
import {
  InvalidGrant,
  InvalidRequest,
  InvalidScope,
  ServerError,
} from "../errors.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { assertClientUserScopeCall } from "../asserts.ts";
import { assertToken } from "../asserts.ts";
import {
  ClientService,
  RefreshTokenService,
} from "../services/test_services.ts";

const clientCredentialsGrantTests: TestSuite<void> = new TestSuite({
  name: "ClientCredentialsGrant",
});

const tokenTests: TestSuite<void> = new TestSuite({
  name: "token",
  suite: clientCredentialsGrantTests,
});

const client: Client = {
  id: "1",
  grants: ["client_credentials"],
};
const clientService = new ClientService({ client });
const tokenService = new RefreshTokenService({
  client,
});
const services: ClientCredentialsGrantServices<Scope> = {
  tokenService,
  clientService,
};
const clientCredentialsGrant = new ClientCredentialsGrant({ services });

test(tokenTests, "not implemented for UserService", async () => {
  const getUser: Spy<ClientService> = spy(
    clientService,
    "getUser",
  );
  try {
    const request = fakeTokenRequest("");
    const result: Promise<Token<Scope>> = clientCredentialsGrant.token(
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

test(tokenTests, "request body required", async () => {
  const request = fakeTokenRequest();
  const result: Promise<Token<Scope>> = clientCredentialsGrant.token(
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
  let request = fakeTokenRequest("scope=\\");
  const result: Promise<Token<Scope>> = clientCredentialsGrant.token(
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
    () => clientCredentialsGrant.token(request, client),
    InvalidScope,
    "invalid scope",
  );
});

test(tokenTests, "no user for client", async () => {
  const getUser: Stub<ClientService> = stub(
    clientService,
    "getUser",
    () => undefined,
  );
  try {
    const request = fakeTokenRequest("");
    const result: Promise<Token<Scope>> = clientCredentialsGrant.token(
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

test(tokenTests, "returns accessToken", async () => {
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
    const request = fakeTokenRequest("scope=read");
    const result: Promise<Token<Scope>> = clientCredentialsGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    const token: Token<Scope> = await result;

    assertStrictEquals(getUser.calls.length, 1);
    let call: SpyCall = getUser.calls[0];
    assertStrictEquals(call.self, clientService);
    assertEquals(call.args.length, 1);
    assertStrictEquals(call.args[0], client);
    const user: User = await call.returned;

    const scope: Scope = new Scope("read");
    assertClientUserScopeCall(
      generateToken,
      0,
      clientCredentialsGrant,
      client,
      user,
      scope,
    );
    assertSpyCalls(generateToken, 1);

    const expectedToken: Token<Scope> = {
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
