import { Grant } from "./grant.ts";
import { test, TestSuite } from "../deps/udibo/test_suite/mod.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";
import { RefreshTokenService, Token } from "../models/token.ts";
import {
  assertClientUserScopeCall,
  assertScope,
  assertToken,
} from "../asserts.ts";
import { ExampleRefreshTokenService } from "../models/token_test.ts";
import { Scope } from "../models/scope.ts";
import { User } from "../models/user.ts";
import { assertStrictEquals } from "../deps/std/testing/asserts.ts";
import { SpyCall, Stub, stub } from "../deps/udibo/mock/mod.ts";

const grantTests: TestSuite<void> = new TestSuite({ name: "Grant" });

class ExampleGrant extends Grant {
  handle(_request: OAuth2Request, _client: Client): Promise<Token> {
    throw new Error("not implemented");
  }
}
const tokenService: RefreshTokenService = new ExampleRefreshTokenService();
const grant: ExampleGrant = new ExampleGrant({ services: { tokenService } });
const refreshTokenGrant: ExampleGrant = new ExampleGrant({
  services: { tokenService },
  allowRefreshToken: true,
});

test(grantTests, "parseScope", () => {
  assertScope(grant.parseScope(undefined), undefined);
  assertScope(grant.parseScope(null), undefined);
  assertScope(grant.parseScope(""), undefined);
  assertScope(grant.parseScope("read"), new Scope("read"));
  assertScope(grant.parseScope("read write"), new Scope("read write"));
});

const generateTokenTests: TestSuite<void> = new TestSuite({
  name: "generateToken",
});

const client: Client = { id: "1", grants: [] };
const user: User = { username: "kyle" };

test(
  generateTokenTests,
  "access token without optional properties",
  async () => {
    const generateAccessToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateAccessToken",
      () => Promise.resolve("x"),
    );
    const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "accessTokenExpiresAt",
      () => Promise.resolve(undefined),
    );
    try {
      const result = grant.generateToken(client, user);
      assertStrictEquals(Promise.resolve(result), result);
      const token: Token = await result;

      assertStrictEquals(accessTokenExpiresAt.calls.length, 1);
      const call: SpyCall = accessTokenExpiresAt.calls[0];
      assertClientUserScopeCall(call, tokenService, client, user);

      assertToken(token, {
        accessToken: "x",
        client,
        user,
      });
    } finally {
      generateAccessToken.restore();
      accessTokenExpiresAt.restore();
    }
  },
);

test(generateTokenTests, "access token with optional properties", async () => {
  const generateAccessToken: Stub<RefreshTokenService> = stub(
    tokenService,
    "generateAccessToken",
    () => Promise.resolve("x"),
  );
  const expectedAccessTokenExpiresAt: Date = new Date();
  const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
    tokenService,
    "accessTokenExpiresAt",
    () => Promise.resolve(new Date(expectedAccessTokenExpiresAt)),
  );
  try {
    const result = grant.generateToken(client, user, new Scope("read"));
    assertStrictEquals(Promise.resolve(result), result);
    const token: Token = await result;

    assertStrictEquals(accessTokenExpiresAt.calls.length, 1);
    const call: SpyCall = accessTokenExpiresAt.calls[0];
    assertClientUserScopeCall(
      call,
      tokenService,
      client,
      user,
      new Scope("read"),
    );

    assertToken(token, {
      accessToken: "x",
      accessTokenExpiresAt: expectedAccessTokenExpiresAt,
      client,
      user,
      scope: new Scope("read"),
    });
  } finally {
    generateAccessToken.restore();
    accessTokenExpiresAt.restore();
  }
});

test(
  generateTokenTests,
  "refresh token allowed without optional properties",
  async () => {
    const generateAccessToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateAccessToken",
      () => Promise.resolve("x"),
    );
    const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "accessTokenExpiresAt",
      () => Promise.resolve(undefined),
    );
    const generateRefreshToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateRefreshToken",
      () => Promise.resolve(undefined),
    );
    const refreshTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "refreshTokenExpiresAt",
      () => Promise.resolve(undefined),
    );
    try {
      const result = refreshTokenGrant.generateToken(client, user);
      assertStrictEquals(Promise.resolve(result), result);
      const token: Token = await result;

      assertStrictEquals(accessTokenExpiresAt.calls.length, 1);
      const call: SpyCall = accessTokenExpiresAt.calls[0];
      assertClientUserScopeCall(call, tokenService, client, user);

      assertToken(token, {
        accessToken: "x",
        client,
        user,
      });
    } finally {
      generateAccessToken.restore();
      accessTokenExpiresAt.restore();
      generateRefreshToken.restore();
      refreshTokenExpiresAt.restore();
    }
  },
);

test(
  generateTokenTests,
  "refresh token allowed with optional properties",
  async () => {
    const generateAccessToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateAccessToken",
      () => Promise.resolve("x"),
    );
    const expectedAccessTokenExpiresAt: Date = new Date();
    const accessTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "accessTokenExpiresAt",
      () => Promise.resolve(new Date(expectedAccessTokenExpiresAt)),
    );
    const generateRefreshToken: Stub<RefreshTokenService> = stub(
      tokenService,
      "generateRefreshToken",
      () => Promise.resolve("y"),
    );
    const expectedRefreshTokenExpiresAt: Date = new Date(Date.now() + 1000);
    const refreshTokenExpiresAt: Stub<RefreshTokenService> = stub(
      tokenService,
      "refreshTokenExpiresAt",
      () => Promise.resolve(new Date(expectedRefreshTokenExpiresAt)),
    );
    try {
      const result = refreshTokenGrant.generateToken(
        client,
        user,
        new Scope("read"),
      );
      assertStrictEquals(Promise.resolve(result), result);
      const token: Token = await result;

      assertStrictEquals(accessTokenExpiresAt.calls.length, 1);
      const call: SpyCall = accessTokenExpiresAt.calls[0];
      assertClientUserScopeCall(
        call,
        tokenService,
        client,
        user,
        new Scope("read"),
      );

      assertToken(token, {
        accessToken: "x",
        accessTokenExpiresAt: expectedAccessTokenExpiresAt,
        refreshToken: "y",
        refreshTokenExpiresAt: expectedRefreshTokenExpiresAt,
        client,
        user,
        scope: new Scope("read"),
      });
    } finally {
      generateAccessToken.restore();
      accessTokenExpiresAt.restore();
      generateRefreshToken.restore();
      refreshTokenExpiresAt.restore();
    }
  },
);
