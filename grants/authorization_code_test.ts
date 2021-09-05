import {
  AuthorizationCodeGrant,
  AuthorizationCodeGrantServices,
} from "./authorization_code.ts";
import { Token } from "../models/token.ts";
import type { Client } from "../models/client.ts";
import type { AuthorizationCode } from "../models/authorization_code.ts";
import { Scope } from "../models/scope.ts";
import {
  assertEquals,
  assertSpyCall,
  assertSpyCalls,
  assertStrictEquals,
  assertThrows,
  assertThrowsAsync,
  resolves,
  Spy,
  spy,
  SpyCall,
  Stub,
  stub,
  test,
  TestSuite,
} from "../test_deps.ts";
import {
  InvalidClient,
  InvalidGrant,
  InvalidRequest,
  ServerError,
} from "../errors.ts";
import { fakeTokenRequest } from "../test_context.ts";
import { User } from "../models/user.ts";
import {
  assertAuthorizationCode,
  assertClientUserScopeCall,
  assertToken,
} from "../asserts.ts";
import { ClientCredentials } from "./grant.ts";
import {
  ChallengeMethod,
  challengeMethods,
  generateCodeVerifier,
} from "../pkce.ts";
import {
  AuthorizationCodeService,
  ClientService,
  RefreshTokenService,
  scope,
  user,
} from "../services/test_services.ts";

const authorizationCodeGrantTests: TestSuite<void> = new TestSuite({
  name: "AuthorizationCodeGrant",
});

const client: Client = {
  id: "1",
  grants: ["authorization_code"],
  redirectUris: [
    "https://client.example.com/cb",
    "https://client2.example.com/cb",
  ],
};
const clientService = new ClientService({ client });
const tokenService = new RefreshTokenService({
  client,
});
const authorizationCodeService = new AuthorizationCodeService();
const services: AuthorizationCodeGrantServices<Scope> = {
  clientService,
  tokenService,
  authorizationCodeService,
};
const authorizationCodeGrant = new AuthorizationCodeGrant({ services });

const getClientCredentialsTests: TestSuite<void> = new TestSuite({
  name: "getClientCredentials",
  suite: authorizationCodeGrantTests,
});

test(
  getClientCredentialsTests,
  "from request body without secret",
  async () => {
    const request = fakeTokenRequest("client_id=1");
    request.headers.delete("authorization");
    const result: Promise<ClientCredentials> = authorizationCodeGrant
      .getClientCredentials(
        request,
      );
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1" });
  },
);

test(getClientCredentialsTests, "from request body with secret", async () => {
  const request = fakeTokenRequest(
    "client_id=1&client_secret=2",
  );
  request.headers.delete("authorization");
  const result: Promise<ClientCredentials> = authorizationCodeGrant
    .getClientCredentials(
      request,
    );
  assertEquals(result, Promise.resolve(result));
  assertEquals(await result, { clientId: "1", clientSecret: "2" });
});

test(
  getClientCredentialsTests,
  "from request body with code verifier",
  async () => {
    const request = fakeTokenRequest(
      "client_id=1&code_verifier=2",
    );
    request.headers.delete("authorization");
    const result: Promise<ClientCredentials> = authorizationCodeGrant
      .getClientCredentials(
        request,
      );
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1", codeVerifier: "2" });
  },
);

const getAuthenticatedClientTests: TestSuite<void> = new TestSuite({
  name: "getAuthenticatedClient",
  suite: authorizationCodeGrantTests,
});

test(getAuthenticatedClientTests, "getClientCredentials failed", async () => {
  const getClientCredentials: Spy<AuthorizationCodeGrant<Scope>> = spy(
    authorizationCodeGrant,
    "getClientCredentials",
  );
  const clientServiceGet: Spy<ClientService> = spy(clientService, "get");
  const clientServiceGetAuthenticated: Spy<ClientService> = spy(
    clientService,
    "getAuthenticated",
  );
  try {
    const request = fakeTokenRequest();
    request.headers.delete("authorization");
    await assertThrowsAsync(
      () => authorizationCodeGrant.getAuthenticatedClient(request),
      InvalidClient,
      "authorization header required",
    );

    assertSpyCall(getClientCredentials, 0, {
      self: authorizationCodeGrant,
      args: [request],
    });
    assertSpyCalls(getClientCredentials, 1);

    assertSpyCalls(clientServiceGet, 0);
    assertSpyCalls(clientServiceGetAuthenticated, 0);
  } finally {
    getClientCredentials.restore();
    clientServiceGet.restore();
    clientServiceGetAuthenticated.restore();
  }
});

test(
  getAuthenticatedClientTests,
  "client authentication failed without secret",
  async () => {
    const getClientCredentials: Spy<AuthorizationCodeGrant> = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet: Spy<ClientService> = spy(clientService, "get");
    const clientServiceGetAuthenticated: Stub<ClientService> = stub(
      clientService,
      "getAuthenticated",
      resolves(undefined),
    );
    try {
      const request = fakeTokenRequest("client_id=1");
      request.headers.delete("authorization");
      await assertThrowsAsync(
        () => authorizationCodeGrant.getAuthenticatedClient(request),
        InvalidClient,
        "client authentication failed",
      );

      assertSpyCall(getClientCredentials, 0, {
        self: authorizationCodeGrant,
        args: [request],
      });
      assertSpyCalls(getClientCredentials, 1);

      assertSpyCalls(clientServiceGet, 0);

      assertSpyCall(clientServiceGetAuthenticated, 0, {
        self: clientService,
        args: ["1"],
      });
      assertSpyCalls(clientServiceGetAuthenticated, 1);
    } finally {
      getClientCredentials.restore();
      clientServiceGet.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

test(
  getAuthenticatedClientTests,
  "client authentication failed with secret",
  async () => {
    const getClientCredentials: Spy<AuthorizationCodeGrant> = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet: Spy<ClientService> = spy(clientService, "get");
    const clientServiceGetAuthenticated: Stub<ClientService> = stub(
      clientService,
      "getAuthenticated",
      resolves(undefined),
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:2")}`);
      await assertThrowsAsync(
        () => authorizationCodeGrant.getAuthenticatedClient(request),
        InvalidClient,
        "client authentication failed",
      );

      assertSpyCall(getClientCredentials, 0, {
        self: authorizationCodeGrant,
        args: [request],
      });
      assertSpyCalls(getClientCredentials, 1);

      assertSpyCalls(clientServiceGet, 0);

      assertSpyCall(clientServiceGetAuthenticated, 0, {
        self: clientService,
        args: ["1", "2"],
      });
      assertSpyCalls(clientServiceGetAuthenticated, 1);
    } finally {
      getClientCredentials.restore();
      clientServiceGet.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

test(
  getAuthenticatedClientTests,
  "client authentication failed with PKCE",
  async () => {
    const getClientCredentials: Spy<AuthorizationCodeGrant> = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet: Stub<ClientService> = stub(
      clientService,
      "get",
      resolves(undefined),
    );
    const clientServiceGetAuthenticated: Spy<ClientService> = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const codeVerifier: string = generateCodeVerifier();
      const request = fakeTokenRequest(
        `client_id=1&code_verifier=${codeVerifier}`,
      );
      request.headers.delete("authorization");
      await assertThrowsAsync(
        () => authorizationCodeGrant.getAuthenticatedClient(request),
        InvalidClient,
        "client authentication failed",
      );

      assertSpyCall(getClientCredentials, 0, {
        self: authorizationCodeGrant,
        args: [request],
      });
      assertSpyCalls(getClientCredentials, 1);

      assertSpyCall(clientServiceGet, 0, {
        self: clientService,
        args: ["1"],
      });
      assertSpyCalls(clientServiceGet, 1);

      assertSpyCalls(clientServiceGetAuthenticated, 0);
    } finally {
      getClientCredentials.restore();
      clientServiceGet.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

test(
  getAuthenticatedClientTests,
  "returns client authenticated without secret",
  async () => {
    const getClientCredentials: Spy<AuthorizationCodeGrant> = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet: Spy<ClientService> = spy(clientService, "get");
    const clientServiceGetAuthenticated: Spy<ClientService> = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const request = fakeTokenRequest("client_id=1");
      request.headers.delete("authorization");
      const result: Promise<Client> = authorizationCodeGrant
        .getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client: Client = await result;

      assertSpyCall(getClientCredentials, 0, {
        self: authorizationCodeGrant,
        args: [request],
      });
      assertSpyCalls(getClientCredentials, 1);

      assertSpyCalls(clientServiceGet, 0);

      const call: SpyCall = assertSpyCall(clientServiceGetAuthenticated, 0, {
        self: clientService,
        args: ["1"],
      });
      assertSpyCalls(clientServiceGetAuthenticated, 1);

      assertEquals(client, await call.returned);
    } finally {
      getClientCredentials.restore();
      clientServiceGet.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

test(
  getAuthenticatedClientTests,
  "returns client authenticated with secret",
  async () => {
    const getClientCredentials: Spy<AuthorizationCodeGrant> = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet: Spy<ClientService> = spy(clientService, "get");
    const clientServiceGetAuthenticated: Spy<ClientService> = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:2")}`);
      const result: Promise<Client> = authorizationCodeGrant
        .getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client: Client = await result;

      assertSpyCall(getClientCredentials, 0, {
        self: authorizationCodeGrant,
        args: [request],
      });
      assertSpyCalls(getClientCredentials, 1);

      assertSpyCalls(clientServiceGet, 0);

      const call: SpyCall = assertSpyCall(clientServiceGetAuthenticated, 0, {
        self: clientService,
        args: ["1", "2"],
      });
      assertSpyCalls(clientServiceGetAuthenticated, 1);

      assertEquals(client, await call.returned);
    } finally {
      getClientCredentials.restore();
      clientServiceGet.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

test(
  getAuthenticatedClientTests,
  "returns client authenticated with PKCE",
  async () => {
    const getClientCredentials: Spy<AuthorizationCodeGrant> = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet: Spy<ClientService> = spy(clientService, "get");
    const clientServiceGetAuthenticated: Spy<ClientService> = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const codeVerifier: string = generateCodeVerifier();
      const request = fakeTokenRequest(
        `client_id=1&code_verifier=${codeVerifier}`,
      );
      const result: Promise<Client> = authorizationCodeGrant
        .getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client: Client = await result;

      assertSpyCall(getClientCredentials, 0, {
        self: authorizationCodeGrant,
        args: [request],
      });
      assertSpyCalls(getClientCredentials, 1);

      const call: SpyCall = assertSpyCall(clientServiceGet, 0, {
        self: clientService,
        args: ["1"],
      });
      assertSpyCalls(clientServiceGet, 1);

      assertSpyCalls(clientServiceGetAuthenticated, 0);

      assertEquals(client, await call.returned);
    } finally {
      getClientCredentials.restore();
      clientServiceGet.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

const getChallengeMethodTests: TestSuite<void> = new TestSuite({
  name: "getChallengeMethod",
  suite: authorizationCodeGrantTests,
});

test(getChallengeMethodTests, "with default challenge methods", () => {
  assertStrictEquals(authorizationCodeGrant.getChallengeMethod(), undefined);
  assertStrictEquals(
    authorizationCodeGrant.getChallengeMethod("plain"),
    undefined,
  );
  assertStrictEquals(
    authorizationCodeGrant.getChallengeMethod("other"),
    undefined,
  );
  assertStrictEquals(
    authorizationCodeGrant.getChallengeMethod("s256"),
    undefined,
  );
  assertStrictEquals(
    authorizationCodeGrant.getChallengeMethod("S256"),
    challengeMethods["S256"],
  );
});

test(getChallengeMethodTests, "with custom challenge methods", () => {
  const plain: ChallengeMethod = (verifier: string) => verifier;
  const other: ChallengeMethod = (verifier: string) => verifier.toLowerCase();
  const grant: AuthorizationCodeGrant = new AuthorizationCodeGrant({
    services,
    challengeMethods: { ...challengeMethods, plain, other },
  });
  assertStrictEquals(grant.getChallengeMethod(), plain);
  assertStrictEquals(grant.getChallengeMethod("plain"), plain);
  assertStrictEquals(grant.getChallengeMethod("other"), other);
  assertStrictEquals(grant.getChallengeMethod("s256"), undefined);
  assertStrictEquals(
    grant.getChallengeMethod("S256"),
    challengeMethods["S256"],
  );
});

const validateChallengeMethodTests: TestSuite<void> = new TestSuite({
  name: "validateChallengeMethod",
  suite: authorizationCodeGrantTests,
});

test(validateChallengeMethodTests, "with default challenge methods", () => {
  assertStrictEquals(authorizationCodeGrant.validateChallengeMethod(), false);
  assertStrictEquals(
    authorizationCodeGrant.validateChallengeMethod("plain"),
    false,
  );
  assertStrictEquals(
    authorizationCodeGrant.validateChallengeMethod("other"),
    false,
  );
  assertStrictEquals(
    authorizationCodeGrant.validateChallengeMethod("s256"),
    false,
  );
  assertStrictEquals(
    authorizationCodeGrant.validateChallengeMethod("S256"),
    true,
  );
});

test(validateChallengeMethodTests, "with custom challenge methods", () => {
  const plain: ChallengeMethod = (verifier: string) => verifier;
  const other: ChallengeMethod = (verifier: string) => verifier.toLowerCase();
  const grant: AuthorizationCodeGrant = new AuthorizationCodeGrant({
    services,
    challengeMethods: { ...challengeMethods, plain, other },
  });
  assertStrictEquals(grant.validateChallengeMethod(), true);
  assertStrictEquals(grant.validateChallengeMethod("plain"), true);
  assertStrictEquals(grant.validateChallengeMethod("other"), true);
  assertStrictEquals(grant.validateChallengeMethod("another"), false);
  assertStrictEquals(grant.validateChallengeMethod("s256"), false);
  assertStrictEquals(grant.validateChallengeMethod("S256"), true);
});

interface VerifyCodeContext {
  codeVerifier: string;
  authorizationCode: AuthorizationCode<Scope>;
}

const verifyCodeTests: TestSuite<VerifyCodeContext> = new TestSuite({
  name: "verifyCode",
  suite: authorizationCodeGrantTests,
  beforeEach(context: VerifyCodeContext) {
    context.codeVerifier = generateCodeVerifier();
    context.authorizationCode = {
      code: "123",
      expiresAt: new Date(Date.now() + 60000),
      redirectUri: "https://client.example.com/cb",
      client,
      user,
      scope,
      challengeMethod: "S256",
      challenge: challengeMethods["S256"](context.codeVerifier),
    };
  },
});

test(
  verifyCodeTests,
  "returns false if code has no challenge",
  ({ codeVerifier, authorizationCode }) => {
    delete authorizationCode.challenge;
    delete authorizationCode.challengeMethod;
    assertStrictEquals(
      authorizationCodeGrant.verifyCode(authorizationCode, codeVerifier),
      false,
    );
  },
);

test(
  verifyCodeTests,
  "returns false if verifier is incorrect",
  ({ authorizationCode }) => {
    const codeVerifier: string = generateCodeVerifier();
    assertStrictEquals(
      authorizationCodeGrant.verifyCode(authorizationCode, codeVerifier),
      false,
    );
  },
);

test(
  verifyCodeTests,
  "returns true if verifier is correct",
  ({ codeVerifier, authorizationCode }) => {
    assertStrictEquals(
      authorizationCodeGrant.verifyCode(authorizationCode, codeVerifier),
      true,
    );
  },
);

test(
  verifyCodeTests,
  "throws if challenge method is not implemented",
  ({ codeVerifier, authorizationCode }) => {
    delete authorizationCode.challengeMethod;
    assertThrows(
      () => authorizationCodeGrant.verifyCode(authorizationCode, codeVerifier),
      ServerError,
      "code_challenge_method not implemented",
    );
    authorizationCode.challengeMethod = "plain";
    assertThrows(
      () => authorizationCodeGrant.verifyCode(authorizationCode, codeVerifier),
      ServerError,
      "code_challenge_method not implemented",
    );
  },
);

const tokenTests: TestSuite<void> = new TestSuite({
  name: "token",
  suite: authorizationCodeGrantTests,
});

test(tokenTests, "request body required", async () => {
  const request = fakeTokenRequest();
  const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
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

test(tokenTests, "code parameter required", async () => {
  let request = fakeTokenRequest("");
  const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
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
    () => authorizationCodeGrant.token(request, client),
    InvalidRequest,
    "code parameter required",
  );
});

test(tokenTests, "code already used", async () => {
  const revokeCode: Stub<RefreshTokenService> = stub(
    tokenService,
    "revokeCode",
    (_code: string) => Promise.resolve(true),
  );
  try {
    const request = fakeTokenRequest("code=1");
    const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "code already used",
    );

    assertSpyCall(revokeCode, 0, {
      self: tokenService,
      args: ["1"],
    });
    assertSpyCalls(revokeCode, 1);
  } finally {
    revokeCode.restore();
  }
});

test(tokenTests, "invalid code", async () => {
  const get: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "get",
    (_code: string) => Promise.resolve(undefined),
  );
  try {
    const request = fakeTokenRequest("code=1");
    const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "invalid code",
    );

    assertSpyCall(get, 0, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 1);
  } finally {
    get.restore();
  }
});

test(tokenTests, "expired code", async () => {
  const originalGet = authorizationCodeService.get;
  const get: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "get",
    async (code: string) => ({
      ...await originalGet.call(authorizationCodeService, code),
      expiresAt: new Date(Date.now() - 60000),
    }),
  );
  try {
    const request = fakeTokenRequest("code=1");
    const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "invalid code",
    );

    assertSpyCall(get, 0, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 1);
  } finally {
    get.restore();
  }
});

test(tokenTests, "code was issued to another client", async () => {
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
    const request = fakeTokenRequest("code=1");
    const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidClient,
      "code was issued to another client",
    );

    assertSpyCall(get, 0, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 1);
  } finally {
    get.restore();
  }
});

test(tokenTests, "redirect_uri parameter required", async () => {
  const get: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "get",
  );
  try {
    let request = fakeTokenRequest("code=1");
    const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "redirect_uri parameter required",
    );

    assertSpyCall(get, 0, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 1);

    request = fakeTokenRequest("code=1&redirect_uri=");
    await assertThrowsAsync(
      () => authorizationCodeGrant.token(request, client),
      InvalidGrant,
      "redirect_uri parameter required",
    );

    assertSpyCall(get, 1, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 2);
  } finally {
    get.restore();
  }
});

test(tokenTests, "incorrect redirect_uri", async () => {
  const get: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "get",
  );
  try {
    let request = fakeTokenRequest(
      `code=1&redirect_uri=${
        encodeURIComponent("http://client.example.com/cb")
      }`,
    );
    const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "incorrect redirect_uri",
    );

    assertSpyCall(get, 0, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 1);

    request = fakeTokenRequest(
      `code=1&redirect_uri=${
        encodeURIComponent("https://client.example.com/cb?client_id=1")
      }`,
    );
    await assertThrowsAsync(
      () => authorizationCodeGrant.token(request, client),
      InvalidGrant,
      "incorrect redirect_uri",
    );

    assertSpyCall(get, 1, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 2);
  } finally {
    get.restore();
  }
});

test(tokenTests, "did not expect redirect_uri parameter", async () => {
  const originalGet = authorizationCodeService.get;
  const get: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "get",
    async (code: string) => ({
      ...await originalGet.call(authorizationCodeService, code),
      redirectUri: undefined,
    }),
  );
  try {
    const request = fakeTokenRequest(
      `code=1&redirect_uri=${
        encodeURIComponent("http://client.example.com/cb")
      }`,
    );
    const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      InvalidGrant,
      "did not expect redirect_uri parameter",
    );

    assertSpyCall(get, 0, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 1);
  } finally {
    get.restore();
  }
});

test(
  tokenTests,
  "client authentication failed with PKCE because of incorrect code_verifier",
  async () => {
    const codeVerifiers: string[] = [
      generateCodeVerifier(),
      generateCodeVerifier(),
    ];
    const get: Stub<AuthorizationCodeService> = stub(
      authorizationCodeService,
      "get",
      (code: string) =>
        Promise.resolve({
          code,
          expiresAt: new Date(Date.now() + 60000),
          redirectUri: "https://client.example.com/cb",
          client,
          user,
          scope,
          challengeMethod: "S256",
          challenge: challengeMethods["S256"](codeVerifiers[0]),
        }),
    );
    try {
      const request = fakeTokenRequest(
        `code=1&code_verifier=${codeVerifiers[1]}&redirect_uri=${
          encodeURIComponent("https://client.example.com/cb")
        }`,
      );
      const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
        request,
        client,
      );
      assertStrictEquals(Promise.resolve(result), result);
      await assertThrowsAsync(
        () => result,
        InvalidClient,
        "client authentication failed",
      );

      assertSpyCall(get, 0, {
        self: authorizationCodeService,
        args: ["1"],
      });
      assertSpyCalls(get, 1);
    } finally {
      get.restore();
    }
  },
);

test(
  tokenTests,
  "client authentication failed with PKCE because of missing code_verifier",
  async () => {
    const codeVerifier: string = generateCodeVerifier();
    const get: Stub<AuthorizationCodeService> = stub(
      authorizationCodeService,
      "get",
      (code: string) =>
        Promise.resolve({
          code,
          expiresAt: new Date(Date.now() + 60000),
          redirectUri: "https://client.example.com/cb",
          client,
          user,
          scope,
          challengeMethod: "S256",
          challenge: challengeMethods["S256"](codeVerifier),
        }),
    );
    try {
      const request = fakeTokenRequest(
        `code=1&redirect_uri=${
          encodeURIComponent("https://client.example.com/cb")
        }`,
      );
      const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
        request,
        client,
      );
      assertStrictEquals(Promise.resolve(result), result);
      await assertThrowsAsync(
        () => result,
        InvalidClient,
        "client authentication failed",
      );

      assertSpyCall(get, 0, {
        self: authorizationCodeService,
        args: ["1"],
      });
      assertSpyCalls(get, 1);
    } finally {
      get.restore();
    }
  },
);

test(tokenTests, "returns token", async () => {
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
    const request = fakeTokenRequest(
      `code=1&redirect_uri=${
        encodeURIComponent("https://client.example.com/cb")
      }`,
    );
    const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    const token: Token<Scope> = await result;

    const call: SpyCall = assertSpyCall(get, 0, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 1);
    const { user, scope }: AuthorizationCode<Scope> = await call.returned;

    assertClientUserScopeCall(
      generateToken,
      0,
      authorizationCodeGrant,
      client,
      user,
      scope,
    );
    assertSpyCalls(generateToken, 1);

    const expectedToken: Token<Scope> = {
      accessToken: "x",
      refreshToken: "y",
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
      client,
      user,
      scope,
      code: "1",
    };
    assertSpyCall(save, 0, {
      self: tokenService,
      args: [expectedToken],
    });
    assertSpyCalls(save, 1);

    assertToken(token, expectedToken);
  } finally {
    get.restore();
    save.restore();
    generateToken.restore();
  }
});

test(
  tokenTests,
  "returns token using client authenticated with PKCE",
  async () => {
    const codeVerifier: string = generateCodeVerifier();
    const get: Stub<AuthorizationCodeService> = stub(
      authorizationCodeService,
      "get",
      (code: string) =>
        Promise.resolve({
          code,
          expiresAt: new Date(Date.now() + 60000),
          redirectUri: "https://client.example.com/cb",
          client,
          user,
          scope,
          challengeMethod: "S256",
          challenge: challengeMethods["S256"](codeVerifier),
        }),
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
      const request = fakeTokenRequest(
        `code=1&code_verifier=${codeVerifier}&redirect_uri=${
          encodeURIComponent("https://client.example.com/cb")
        }`,
      );
      const result: Promise<Token<Scope>> = authorizationCodeGrant.token(
        request,
        client,
      );
      assertStrictEquals(Promise.resolve(result), result);
      const token: Token<Scope> = await result;

      const call: SpyCall = assertSpyCall(get, 0, {
        self: authorizationCodeService,
        args: ["1"],
      });
      assertSpyCalls(get, 1);
      const { user, scope }: AuthorizationCode<Scope> = await call.returned;

      assertClientUserScopeCall(
        generateToken,
        0,
        authorizationCodeGrant,
        client,
        user,
        scope,
      );
      assertSpyCalls(generateToken, 1);

      const expectedToken: Token<Scope> = {
        accessToken: "x",
        refreshToken: "y",
        accessTokenExpiresAt,
        refreshTokenExpiresAt,
        client,
        user,
        scope,
        code: "1",
      };
      assertSpyCall(save, 0, {
        self: tokenService,
        args: [expectedToken],
      });
      assertSpyCalls(save, 1);

      assertToken(token, expectedToken);
    } finally {
      get.restore();
      save.restore();
      generateToken.restore();
    }
  },
);

const generateAuthorizationCodeTests: TestSuite<void> = new TestSuite({
  name: "generateAuthorizationCode",
  suite: authorizationCodeGrantTests,
});

test(generateAuthorizationCodeTests, "generateCode error", async () => {
  const generateCode: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "generateCode",
    () => Promise.reject(new ServerError("generateCode failed")),
  );
  const expiresAt: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "expiresAt",
  );
  const save: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "save",
  );
  try {
    await assertThrowsAsync(
      () =>
        authorizationCodeGrant.generateAuthorizationCode({
          client,
          user,
        }),
      ServerError,
      "generateCode failed",
    );
    assertClientUserScopeCall(
      generateCode,
      0,
      authorizationCodeService,
      client,
      user,
    );
    assertSpyCalls(generateCode, 1);
    assertSpyCalls(expiresAt, 0);
    assertSpyCalls(save, 0);
  } finally {
    generateCode.restore();
    expiresAt.restore();
    save.restore();
  }
});

test(generateAuthorizationCodeTests, "expiresAt error", async () => {
  const generateCode: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "generateCode",
  );
  const expiresAt: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "expiresAt",
    () => Promise.reject(new ServerError("expiresAt failed")),
  );
  const save: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "save",
  );
  try {
    await assertThrowsAsync(
      () =>
        authorizationCodeGrant.generateAuthorizationCode({
          client,
          user,
        }),
      ServerError,
      "expiresAt failed",
    );
    assertClientUserScopeCall(
      generateCode,
      0,
      authorizationCodeService,
      client,
      user,
    );
    assertSpyCalls(generateCode, 1);
    assertClientUserScopeCall(
      expiresAt,
      0,
      authorizationCodeService,
      client,
      user,
    );
    assertSpyCalls(expiresAt, 1);
    assertSpyCalls(save, 0);
  } finally {
    generateCode.restore();
    expiresAt.restore();
    save.restore();
  }
});

test(generateAuthorizationCodeTests, "save error", async () => {
  const generateCode: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "generateCode",
    () => Promise.resolve("1"),
  );
  const expectedExpiresAt = new Date(Date.now() + 60000);
  const expiresAt: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "expiresAt",
    () => Promise.resolve(expectedExpiresAt),
  );
  const save: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "save",
    () => Promise.reject(new ServerError("save failed")),
  );
  try {
    await assertThrowsAsync(
      () =>
        authorizationCodeGrant.generateAuthorizationCode({
          client,
          user,
        }),
      ServerError,
      "save failed",
    );
    assertClientUserScopeCall(
      generateCode,
      0,
      authorizationCodeService,
      client,
      user,
    );
    assertSpyCalls(generateCode, 1);
    assertClientUserScopeCall(
      generateCode,
      0,
      authorizationCodeService,
      client,
      user,
    );
    assertSpyCalls(expiresAt, 1);
    const call: SpyCall = assertSpyCall(save, 0, {
      self: authorizationCodeService,
    });
    assertEquals(call.args.length, 1);
    assertAuthorizationCode(call.args[0], {
      code: "1",
      expiresAt: expectedExpiresAt,
      client,
      user,
    });
    assertSpyCalls(save, 1);
  } finally {
    generateCode.restore();
    expiresAt.restore();
    save.restore();
  }
});

test(
  generateAuthorizationCodeTests,
  "without optional properties",
  async () => {
    const generateCode: Stub<AuthorizationCodeService> = stub(
      authorizationCodeService,
      "generateCode",
      () => Promise.resolve("1"),
    );
    const expectedExpiresAt = new Date(Date.now() + 60000);
    const expiresAt: Stub<AuthorizationCodeService> = stub(
      authorizationCodeService,
      "expiresAt",
      () => Promise.resolve(expectedExpiresAt),
    );
    const save: Spy<AuthorizationCodeService> = spy(
      authorizationCodeService,
      "save",
    );
    try {
      const expectedAuthorizationCode = {
        code: "1",
        expiresAt: expectedExpiresAt,
        client,
        user,
      };
      assertEquals(
        await authorizationCodeGrant.generateAuthorizationCode({
          client,
          user,
        }),
        expectedAuthorizationCode,
      );
      assertClientUserScopeCall(
        generateCode,
        0,
        authorizationCodeService,
        client,
        user,
      );
      assertSpyCalls(generateCode, 1);
      assertClientUserScopeCall(
        generateCode,
        0,
        authorizationCodeService,
        client,
        user,
      );
      assertSpyCalls(expiresAt, 1);
      const call: SpyCall = assertSpyCall(save, 0, {
        self: authorizationCodeService,
      });
      assertEquals(call.args.length, 1);
      assertAuthorizationCode(call.args[0], expectedAuthorizationCode);
      assertSpyCalls(save, 1);
    } finally {
      generateCode.restore();
      expiresAt.restore();
      save.restore();
    }
  },
);

test(generateAuthorizationCodeTests, "with optional properties", async () => {
  const generateCode: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "generateCode",
    () => Promise.resolve("1"),
  );
  const expectedExpiresAt = new Date(Date.now() + 60000);
  const expiresAt: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "expiresAt",
    () => Promise.resolve(expectedExpiresAt),
  );
  const save: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "save",
  );
  try {
    const verifier: string = generateCodeVerifier();
    const challenge: string = challengeMethods.S256(verifier);
    const expectedAuthorizationCode = {
      code: "1",
      expiresAt: expectedExpiresAt,
      redirectUri: "https://client.example.com/cb",
      challengeMethod: "S256",
      challenge,
      client,
      user,
      scope,
    };
    assertEquals(
      await authorizationCodeGrant.generateAuthorizationCode({
        redirectUri: "https://client.example.com/cb",
        challengeMethod: "S256",
        challenge,
        client,
        user,
        scope,
      }),
      expectedAuthorizationCode,
    );
    assertClientUserScopeCall(
      generateCode,
      0,
      authorizationCodeService,
      client,
      user,
      scope,
    );
    assertSpyCalls(generateCode, 1);
    assertClientUserScopeCall(
      generateCode,
      0,
      authorizationCodeService,
      client,
      user,
      scope,
    );
    assertSpyCalls(expiresAt, 1);
    const call: SpyCall = assertSpyCall(save, 0, {
      self: authorizationCodeService,
    });
    assertEquals(call.args.length, 1);
    assertAuthorizationCode(call.args[0], expectedAuthorizationCode);
    assertSpyCalls(save, 1);
  } finally {
    generateCode.restore();
    expiresAt.restore();
    save.restore();
  }
});
