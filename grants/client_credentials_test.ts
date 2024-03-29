import {
  ClientCredentialsGrant,
  ClientCredentialsGrantServices,
} from "./client_credentials.ts";
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
  InvalidScopeError,
  ServerError,
} from "../errors.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { assertClientUserScopeCall } from "../asserts.ts";
import { assertToken } from "../asserts.ts";
import {
  ClientService,
  RefreshTokenService,
  scope,
} from "../services/test_services.ts";
import { User } from "../models/user.ts";

const clientCredentialsGrantTests = describe("ClientCredentialsGrant");

const tokenTests = describe({
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
const services: ClientCredentialsGrantServices<Client, User, Scope> = {
  tokenService,
  clientService,
};
const clientCredentialsGrant = new ClientCredentialsGrant({ services });

it(tokenTests, "not implemented for UserService", async () => {
  const getUser: Spy<ClientService> = spy(
    clientService,
    "getUser",
  );
  try {
    const request = fakeTokenRequest("");
    const result = clientCredentialsGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      ServerError,
      "clientService.getUser not implemented",
    );
    assertStrictEquals(getUser.calls.length, 1);
    const call = getUser.calls[0];
    assertStrictEquals(call.self, clientService);
    assertEquals(call.args.length, 1);
    assertStrictEquals(call.args[0], client);
  } finally {
    getUser.restore();
  }
});

it(tokenTests, "invalid scope", async () => {
  const acceptedScope = spy(clientCredentialsGrant, "acceptedScope");
  try {
    let request = fakeTokenRequest("scope=\\");
    const result = clientCredentialsGrant.token(
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
      () => clientCredentialsGrant.token(request, client),
      InvalidScopeError,
      "invalid scope",
    );
  } finally {
    acceptedScope.restore();
  }
});

it(tokenTests, "no user for client", async () => {
  const getUser: Stub<ClientService> = stub(
    clientService,
    "getUser",
    () => undefined,
  );
  try {
    const request = fakeTokenRequest("");
    const result = clientCredentialsGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidGrantError,
      "no user for client",
    );
    assertStrictEquals(getUser.calls.length, 1);
    const call = getUser.calls[0];
    assertStrictEquals(call.self, clientService);
    assertEquals(call.args.length, 1);
    assertStrictEquals(call.args[0], client);
  } finally {
    getUser.restore();
  }
});

it(tokenTests, "scope not accepted", async () => {
  const user = { username: "kyle" };
  const getUser = stub(
    clientService,
    "getUser",
    (_client: Client) => Promise.resolve(user),
  );
  const acceptedScope = stub(
    clientCredentialsGrant,
    "acceptedScope",
    () => Promise.reject(new InvalidScopeError("invalid scope")),
  );
  try {
    const request = fakeTokenRequest("scope=read write");
    const result = clientCredentialsGrant.token(
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
      clientCredentialsGrant,
      client,
      user,
      scope,
    );
    assertSpyCalls(acceptedScope, 1);
  } finally {
    getUser.restore();
    acceptedScope.restore();
  }
});

it(tokenTests, "returns accessToken", async () => {
  const username = "kyle";
  const getUser = stub(
    clientService,
    "getUser",
    (_client: Client) => ({ username }),
  );
  const save = spy(tokenService, "save");
  const accessTokenExpiresAt: Date = new Date(Date.now() + 1000);
  const generateToken = stub(
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
  const expectedScope = new Scope("read");
  const acceptedScope = stub(
    clientCredentialsGrant,
    "acceptedScope",
    () => Promise.resolve(expectedScope),
  );

  try {
    const request = fakeTokenRequest("scope=read write");
    const result = clientCredentialsGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    const token = await result;

    assertStrictEquals(getUser.calls.length, 1);
    const getCall = getUser.calls[0];
    assertStrictEquals(getCall.self, clientService);
    assertEquals(getCall.args.length, 1);
    assertStrictEquals(getCall.args[0], client);
    const user = await getCall.returned;

    assertClientUserScopeCall(
      acceptedScope,
      0,
      clientCredentialsGrant,
      client,
      user,
      scope,
    );
    assertSpyCalls(acceptedScope, 1);

    assertClientUserScopeCall(
      generateToken,
      0,
      clientCredentialsGrant,
      client,
      user,
      expectedScope,
    );
    assertSpyCalls(generateToken, 1);

    const expectedToken: Token<Client, User, Scope> = {
      accessToken: "x",
      accessTokenExpiresAt,
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
    getUser.restore();
    generateToken.restore();
    save.restore();
    acceptedScope.restore();
  }
});
