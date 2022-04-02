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
  assertRejects,
  assertSpyCall,
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
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  ServerError,
} from "../errors.ts";
import { fakeTokenRequest } from "../test_context.ts";
import {
  assertAuthorizationCode,
  assertClientUserScopeCall,
  assertToken,
} from "../asserts.ts";
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
import { User } from "../models/user.ts";

const authorizationCodeGrantTests = describe({
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
const services: AuthorizationCodeGrantServices<Client, User, Scope> = {
  clientService,
  tokenService,
  authorizationCodeService,
};
const authorizationCodeGrant = new AuthorizationCodeGrant({ services });

const getClientCredentialsTests = describe({
  name: "getClientCredentials",
  suite: authorizationCodeGrantTests,
});

it(
  getClientCredentialsTests,
  "from request body without secret",
  async () => {
    const request = fakeTokenRequest("client_id=1");
    request.headers.delete("authorization");
    const result = authorizationCodeGrant
      .getClientCredentials(request);
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1" });
  },
);

it(getClientCredentialsTests, "from request body with secret", async () => {
  const request = fakeTokenRequest(
    "client_id=1&client_secret=2",
  );
  request.headers.delete("authorization");
  const result = authorizationCodeGrant
    .getClientCredentials(request);
  assertEquals(result, Promise.resolve(result));
  assertEquals(await result, { clientId: "1", clientSecret: "2" });
});

it(
  getClientCredentialsTests,
  "from request body with code verifier",
  async () => {
    const request = fakeTokenRequest(
      "client_id=1&code_verifier=2",
    );
    request.headers.delete("authorization");
    const result = authorizationCodeGrant
      .getClientCredentials(request);
    assertEquals(result, Promise.resolve(result));
    assertEquals(await result, { clientId: "1", codeVerifier: "2" });
  },
);

const getAuthenticatedClientTests = describe({
  name: "getAuthenticatedClient",
  suite: authorizationCodeGrantTests,
});

it(getAuthenticatedClientTests, "getClientCredentials failed", async () => {
  const getClientCredentials = spy(
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
    await assertRejects(
      () => authorizationCodeGrant.getAuthenticatedClient(request),
      InvalidClientError,
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

it(
  getAuthenticatedClientTests,
  "client authentication failed without secret",
  async () => {
    const getClientCredentials = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet: Spy<ClientService> = spy(clientService, "get");
    const clientServiceGetAuthenticated: Stub<ClientService> = stub(
      clientService,
      "getAuthenticated",
      () => Promise.resolve(),
    );
    try {
      const request = fakeTokenRequest("client_id=1");
      request.headers.delete("authorization");
      await assertRejects(
        () => authorizationCodeGrant.getAuthenticatedClient(request),
        InvalidClientError,
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

it(
  getAuthenticatedClientTests,
  "client authentication failed with secret",
  async () => {
    const getClientCredentials = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet: Spy<ClientService> = spy(clientService, "get");
    const clientServiceGetAuthenticated: Stub<ClientService> = stub(
      clientService,
      "getAuthenticated",
      () => Promise.resolve(),
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:2")}`);
      await assertRejects(
        () => authorizationCodeGrant.getAuthenticatedClient(request),
        InvalidClientError,
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

it(
  getAuthenticatedClientTests,
  "client authentication failed with PKCE",
  async () => {
    const getClientCredentials = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet = stub(
      clientService,
      "get",
      () => Promise.resolve(),
    );
    const clientServiceGetAuthenticated = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const codeVerifier: string = generateCodeVerifier();
      const request = fakeTokenRequest(
        `client_id=1&code_verifier=${codeVerifier}`,
      );
      request.headers.delete("authorization");
      await assertRejects(
        () => authorizationCodeGrant.getAuthenticatedClient(request),
        InvalidClientError,
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

it(
  getAuthenticatedClientTests,
  "returns client authenticated without secret",
  async () => {
    const getClientCredentials = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet = spy(clientService, "get");
    const clientServiceGetAuthenticated = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const request = fakeTokenRequest("client_id=1");
      request.headers.delete("authorization");
      const result = authorizationCodeGrant
        .getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client: Client = await result;

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
      const call = clientServiceGetAuthenticated.calls[0];
      assertSpyCalls(clientServiceGetAuthenticated, 1);

      assertEquals(client, await call.returned);
    } finally {
      getClientCredentials.restore();
      clientServiceGet.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

it(
  getAuthenticatedClientTests,
  "returns client authenticated with secret",
  async () => {
    const getClientCredentials = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet = spy(clientService, "get");
    const clientServiceGetAuthenticated = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const request = fakeTokenRequest();
      request.headers.set("authorization", `basic ${btoa("1:2")}`);
      const result = authorizationCodeGrant
        .getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client: Client = await result;

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
      const call = clientServiceGetAuthenticated.calls[0];
      assertSpyCalls(clientServiceGetAuthenticated, 1);

      assertEquals(client, await call.returned);
    } finally {
      getClientCredentials.restore();
      clientServiceGet.restore();
      clientServiceGetAuthenticated.restore();
    }
  },
);

it(
  getAuthenticatedClientTests,
  "returns client authenticated with PKCE",
  async () => {
    const getClientCredentials = spy(
      authorizationCodeGrant,
      "getClientCredentials",
    );
    const clientServiceGet = spy(clientService, "get");
    const clientServiceGetAuthenticated = spy(
      clientService,
      "getAuthenticated",
    );
    try {
      const codeVerifier: string = generateCodeVerifier();
      const request = fakeTokenRequest(
        `client_id=1&code_verifier=${codeVerifier}`,
      );
      const result = authorizationCodeGrant
        .getAuthenticatedClient(request);
      assertStrictEquals(Promise.resolve(result), result);
      const client = await result;

      assertSpyCall(getClientCredentials, 0, {
        self: authorizationCodeGrant,
        args: [request],
      });
      assertSpyCalls(getClientCredentials, 1);

      assertSpyCall(clientServiceGet, 0, {
        self: clientService,
        args: ["1"],
      });
      const call = clientServiceGet.calls[0];
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

const getChallengeMethodTests = describe({
  name: "getChallengeMethod",
  suite: authorizationCodeGrantTests,
});

it(getChallengeMethodTests, "with default challenge methods", () => {
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

it(getChallengeMethodTests, "with custom challenge methods", () => {
  const plain: ChallengeMethod = (verifier: string) =>
    Promise.resolve(verifier);
  const other: ChallengeMethod = (verifier: string) =>
    Promise.resolve(verifier.toLowerCase());
  const grant = new AuthorizationCodeGrant({
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

const validateChallengeMethodTests = describe({
  name: "validateChallengeMethod",
  suite: authorizationCodeGrantTests,
});

it(validateChallengeMethodTests, "with default challenge methods", () => {
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

it(validateChallengeMethodTests, "with custom challenge methods", () => {
  const plain: ChallengeMethod = (verifier: string) =>
    Promise.resolve(verifier);
  const other: ChallengeMethod = (verifier: string) =>
    Promise.resolve(verifier.toLowerCase());
  const grant = new AuthorizationCodeGrant({
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
  authorizationCode: AuthorizationCode<Client, User, Scope>;
}

const verifyCodeTests = describe<VerifyCodeContext>({
  name: "verifyCode",
  suite: authorizationCodeGrantTests,
  async beforeEach() {
    this.codeVerifier = generateCodeVerifier();
    this.authorizationCode = {
      code: "123",
      expiresAt: new Date(Date.now() + 60000),
      redirectUri: "https://client.example.com/cb",
      client,
      user,
      scope,
      challengeMethod: "S256",
      challenge: await challengeMethods["S256"](this.codeVerifier),
    };
  },
});

it(
  verifyCodeTests,
  "returns false if code has no challenge",
  async function () {
    const { codeVerifier, authorizationCode } = this;
    delete authorizationCode.challenge;
    delete authorizationCode.challengeMethod;
    assertStrictEquals(
      await authorizationCodeGrant.verifyCode(authorizationCode, codeVerifier),
      false,
    );
  },
);

it(
  verifyCodeTests,
  "returns false if verifier is incorrect",
  async function () {
    const codeVerifier: string = generateCodeVerifier();
    assertStrictEquals(
      await authorizationCodeGrant.verifyCode(
        this.authorizationCode,
        codeVerifier,
      ),
      false,
    );
  },
);

it(
  verifyCodeTests,
  "returns true if verifier is correct",
  async function () {
    const { codeVerifier, authorizationCode } = this;
    assertStrictEquals(
      await authorizationCodeGrant.verifyCode(authorizationCode, codeVerifier),
      true,
    );
  },
);

it(
  verifyCodeTests,
  "throws if challenge method is not implemented",
  async function () {
    const { codeVerifier, authorizationCode } = this;
    delete authorizationCode.challengeMethod;
    await assertRejects(
      () => authorizationCodeGrant.verifyCode(authorizationCode, codeVerifier),
      ServerError,
      "code_challenge_method not implemented",
    );
    authorizationCode.challengeMethod = "plain";
    await assertRejects(
      () => authorizationCodeGrant.verifyCode(authorizationCode, codeVerifier),
      ServerError,
      "code_challenge_method not implemented",
    );
  },
);

const tokenTests = describe({
  name: "token",
  suite: authorizationCodeGrantTests,
});

it(tokenTests, "code parameter required", async () => {
  let request = fakeTokenRequest("");
  const result = authorizationCodeGrant.token(
    request,
    client,
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertRejects(
    () => result,
    InvalidRequestError,
    "code parameter required",
  );

  request = fakeTokenRequest("username=");
  await assertRejects(
    () => authorizationCodeGrant.token(request, client),
    InvalidRequestError,
    "code parameter required",
  );
});

it(tokenTests, "code already used", async () => {
  const revokeCode: Stub<RefreshTokenService> = stub(
    tokenService,
    "revokeCode",
    (_code: string) => Promise.resolve(true),
  );
  try {
    const request = fakeTokenRequest("code=1");
    const result = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidGrantError,
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

it(tokenTests, "invalid code", async () => {
  const get: Stub<AuthorizationCodeService> = stub(
    authorizationCodeService,
    "get",
    (_code: string) => Promise.resolve(undefined),
  );
  try {
    const request = fakeTokenRequest("code=1");
    const result = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidGrantError,
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

it(tokenTests, "expired code", async () => {
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
    const result = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidGrantError,
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

it(tokenTests, "code was issued to another client", async () => {
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
    const result = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidClientError,
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

it(tokenTests, "redirect_uri parameter required", async () => {
  const get: Spy<AuthorizationCodeService> = spy(
    authorizationCodeService,
    "get",
  );
  try {
    let request = fakeTokenRequest("code=1");
    const result = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidGrantError,
      "redirect_uri parameter required",
    );

    assertSpyCall(get, 0, {
      self: authorizationCodeService,
      args: ["1"],
    });
    assertSpyCalls(get, 1);

    request = fakeTokenRequest("code=1&redirect_uri=");
    await assertRejects(
      () => authorizationCodeGrant.token(request, client),
      InvalidGrantError,
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

it(tokenTests, "incorrect redirect_uri", async () => {
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
    const result = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidGrantError,
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
    await assertRejects(
      () => authorizationCodeGrant.token(request, client),
      InvalidGrantError,
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

it(tokenTests, "did not expect redirect_uri parameter", async () => {
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
    const result = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    await assertRejects(
      () => result,
      InvalidGrantError,
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

it(
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
      async (code: string) => ({
        code,
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: "https://client.example.com/cb",
        client,
        user,
        scope,
        challengeMethod: "S256",
        challenge: await challengeMethods["S256"](codeVerifiers[0]),
      }),
    );
    try {
      const request = fakeTokenRequest(
        `code=1&code_verifier=${codeVerifiers[1]}&redirect_uri=${
          encodeURIComponent("https://client.example.com/cb")
        }`,
      );
      const result = authorizationCodeGrant.token(
        request,
        client,
      );
      assertStrictEquals(Promise.resolve(result), result);
      await assertRejects(
        () => result,
        InvalidClientError,
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

it(
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
      const result = authorizationCodeGrant.token(
        request,
        client,
      );
      assertStrictEquals(Promise.resolve(result), result);
      await assertRejects(
        () => result,
        InvalidClientError,
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

it(tokenTests, "returns token", async () => {
  const get = spy(
    authorizationCodeService,
    "get",
  );
  const save = spy(tokenService, "save");
  const accessTokenExpiresAt = new Date(Date.now() + 1000);
  const refreshTokenExpiresAt = new Date(Date.now() + 2000);
  const generateToken = stub(
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
    const result = authorizationCodeGrant.token(
      request,
      client,
    );
    assertStrictEquals(Promise.resolve(result), result);
    const token = await result;

    assertSpyCall(get, 0, {
      self: authorizationCodeService,
      args: ["1"],
    });
    const call = get.calls[0];
    assertSpyCalls(get, 1);
    const { user, scope } = await call
      .returned as AuthorizationCode<Client, User, Scope>;

    assertClientUserScopeCall(
      generateToken,
      0,
      authorizationCodeGrant,
      client,
      user,
      scope,
    );
    assertSpyCalls(generateToken, 1);

    const expectedToken: Token<Client, User, Scope> = {
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

it(
  tokenTests,
  "returns token using client authenticated with PKCE",
  async () => {
    const codeVerifier = generateCodeVerifier();
    const get = stub(
      authorizationCodeService,
      "get",
      async (code: string) => ({
        code,
        expiresAt: new Date(Date.now() + 60000),
        redirectUri: "https://client.example.com/cb",
        client,
        user,
        scope,
        challengeMethod: "S256",
        challenge: await challengeMethods["S256"](codeVerifier),
      }),
    );
    const save = spy(tokenService, "save");
    const accessTokenExpiresAt = new Date(Date.now() + 1000);
    const refreshTokenExpiresAt = new Date(Date.now() + 2000);
    const generateToken = stub(
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
      const result = authorizationCodeGrant.token(
        request,
        client,
      );
      assertStrictEquals(Promise.resolve(result), result);
      const token = await result;

      assertSpyCall(get, 0, {
        self: authorizationCodeService,
        args: ["1"],
      });
      const call = get.calls[0];
      assertSpyCalls(get, 1);
      const { user, scope } = await call
        .returned as AuthorizationCode<Client, User, Scope>;

      assertClientUserScopeCall(
        generateToken,
        0,
        authorizationCodeGrant,
        client,
        user,
        scope,
      );
      assertSpyCalls(generateToken, 1);

      const expectedToken: Token<Client, User, Scope> = {
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

const generateAuthorizationCodeTests = describe({
  name: "generateAuthorizationCode",
  suite: authorizationCodeGrantTests,
});

it(generateAuthorizationCodeTests, "generateCode error", async () => {
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
    await assertRejects(
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

it(generateAuthorizationCodeTests, "expiresAt error", async () => {
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
    await assertRejects(
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

it(generateAuthorizationCodeTests, "save error", async () => {
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
    await assertRejects(
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
    assertSpyCall(save, 0, {
      self: authorizationCodeService,
    });
    const call = save.calls[0];
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

it(
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
      assertSpyCall(save, 0, {
        self: authorizationCodeService,
      });
      const call = save.calls[0];
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

it(generateAuthorizationCodeTests, "with optional properties", async () => {
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
    const challenge: string = await challengeMethods.S256(verifier);
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
    assertSpyCall(save, 0, {
      self: authorizationCodeService,
    });
    const call = save.calls[0];
    assertEquals(call.args.length, 1);
    assertAuthorizationCode(call.args[0], expectedAuthorizationCode);
    assertSpyCalls(save, 1);
  } finally {
    generateCode.restore();
    expiresAt.restore();
    save.restore();
  }
});
