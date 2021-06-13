import {
  AccessToken,
  AccessTokenService,
  RefreshToken,
  RefreshTokenService,
  Token,
  TokenServiceInterface,
} from "./token.ts";
import type { Client } from "./client.ts";
import type { User } from "./user.ts";
import { Scope } from "./scope.ts";
import { v4 } from "../deps.ts";
import {
  assert,
  assertEquals,
  assertStrictEquals,
  assertThrowsAsync,
  FakeTime,
  test,
  TestSuite,
} from "../test_deps.ts";
import { ServerError } from "../errors.ts";

const client: Client = {
  id: "1",
  grants: ["refresh_token"],
};
const user: User = { username: "kyle" };
const scope: Scope = new Scope("read");

export class ExampleAccessTokenService extends AccessTokenService {
  /** Retrieves an existing token. */
  getAccessToken(accessToken: string): Promise<AccessToken | undefined> {
    return Promise.resolve({
      accessToken,
      client,
      user,
    });
  }

  /** Saves a token. */
  save<T extends Token>(token: T): Promise<T> {
    return Promise.resolve(token);
  }

  /** Revokes a token. */
  revoke(_token: Token): Promise<boolean> {
    return Promise.resolve(true);
  }

  /** Revokes all tokens generated from an authorization code. */
  revokeCode(_code: string): Promise<boolean> {
    return Promise.resolve(false);
  }
}

const accessTokenService: TokenServiceInterface =
  new ExampleAccessTokenService();

const accessTokenServiceTests: TestSuite<void> = new TestSuite({
  name: "AccessTokenService",
});

test(accessTokenServiceTests, "generateAccessToken", async () => {
  const result: Promise<string> = accessTokenService.generateAccessToken(
    client,
    user,
    scope,
  );
  assertStrictEquals(Promise.resolve(result), result);
  assert(v4.validate(await result));
  assert(
    v4.validate(
      await accessTokenService.generateAccessToken(client, user, scope),
    ),
  );
});

test(
  accessTokenServiceTests,
  "generateRefreshToken not implemented",
  async () => {
    const result: Promise<string | undefined> = accessTokenService
      .generateRefreshToken(
        client,
        user,
        scope,
      );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      ServerError,
      "generateRefreshToken not implemented",
    );
    await assertThrowsAsync(
      () => accessTokenService.generateRefreshToken(client, user, scope),
      ServerError,
      "generateRefreshToken not implemented",
    );
  },
);

test(accessTokenServiceTests, "accessTokenExpiresAt", async () => {
  const time: FakeTime = new FakeTime();
  try {
    const hour: number = 60 * 60 * 1000;
    const result = accessTokenService.accessTokenExpiresAt(client, user, scope);
    assertStrictEquals(Promise.resolve(result), result);
    assertEquals(await result, new Date(Date.now() + hour));
    assertEquals(
      await accessTokenService.accessTokenExpiresAt(client, user, scope),
      new Date(Date.now() + hour),
    );
    time.tick(1234);
    assertEquals(
      await accessTokenService.accessTokenExpiresAt(client, user, scope),
      new Date(Date.now() + hour),
    );
  } finally {
    time.restore();
  }
});

test(
  accessTokenServiceTests,
  "accessTokenExpiresAt with client.accessTokenLifetime",
  async () => {
    const time: FakeTime = new FakeTime();
    try {
      const client: Client = {
        id: "1",
        grants: [],
        accessTokenLifetime: 5 * 60,
      };
      const fiveMinutes: number = 5 * 60 * 1000;
      const result = accessTokenService.accessTokenExpiresAt(
        client,
        user,
        scope,
      );
      assertStrictEquals(Promise.resolve(result), result);
      assertEquals(await result, new Date(Date.now() + fiveMinutes));
      assertEquals(
        await accessTokenService.accessTokenExpiresAt(client, user, scope),
        new Date(Date.now() + fiveMinutes),
      );
      time.tick(1234);
      assertEquals(
        await accessTokenService.accessTokenExpiresAt(client, user, scope),
        new Date(Date.now() + fiveMinutes),
      );
    } finally {
      time.restore();
    }
  },
);

test(
  accessTokenServiceTests,
  "refreshTokenExpiresAt not implemented",
  async () => {
    const result: Promise<Date | undefined> = accessTokenService
      .refreshTokenExpiresAt(
        client,
        user,
        scope,
      );
    assertStrictEquals(Promise.resolve(result), result);
    await assertThrowsAsync(
      () => result,
      ServerError,
      "refreshTokenExpiresAt not implemented",
    );
    await assertThrowsAsync(
      () => accessTokenService.refreshTokenExpiresAt(client, user, scope),
      ServerError,
      "refreshTokenExpiresAt not implemented",
    );
  },
);

test(accessTokenServiceTests, "getRefreshToken not implemented", async () => {
  const result: Promise<Token | void> = accessTokenService.getRefreshToken(
    "fake",
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(
    () => result,
    ServerError,
    "getRefreshToken not implemented",
  );
  await assertThrowsAsync(
    () => accessTokenService.getRefreshToken("fake"),
    ServerError,
    "getRefreshToken not implemented",
  );
});

export class ExampleRefreshTokenService extends RefreshTokenService {
  /** Retrieves an existing token. */
  getAccessToken(accessToken: string): Promise<AccessToken | undefined> {
    return Promise.resolve({
      accessToken,
      client,
      user,
    });
  }

  /** Retrieves an existing token. */
  getRefreshToken(refreshToken: string): Promise<RefreshToken | undefined> {
    return Promise.resolve({
      accessToken: "fake",
      refreshToken,
      client,
      user,
    });
  }

  /** Saves a token. */
  save<T extends Token>(token: T): Promise<T> {
    return Promise.resolve(token);
  }

  /** Revokes a token. */
  revoke(_token: Token): Promise<boolean> {
    return Promise.resolve(true);
  }

  /** Revokes all tokens generated from an authorization code. */
  revokeCode(_code: string): Promise<boolean> {
    return Promise.resolve(false);
  }
}

const refreshTokenService: TokenServiceInterface =
  new ExampleRefreshTokenService();

const refreshTokenServiceTests: TestSuite<void> = new TestSuite({
  name: "RefreshTokenService",
});

test(refreshTokenServiceTests, "generateAccessToken", async () => {
  const result: Promise<string> = refreshTokenService.generateAccessToken(
    client,
    user,
    scope,
  );
  assertStrictEquals(Promise.resolve(result), result);
  assert(v4.validate(await result));
  assert(
    v4.validate(
      await refreshTokenService.generateAccessToken(client, user, scope),
    ),
  );
});

test(refreshTokenServiceTests, "accessTokenExpiresAt", async () => {
  const time: FakeTime = new FakeTime();
  try {
    const hour: number = 60 * 60 * 1000;
    const result: Promise<Date | undefined> = refreshTokenService
      .accessTokenExpiresAt(
        client,
        user,
        scope,
      );
    assertStrictEquals(Promise.resolve(result), result);
    assertEquals(await result, new Date(Date.now() + hour));
    assertEquals(
      await refreshTokenService.accessTokenExpiresAt(client, user, scope),
      new Date(Date.now() + hour),
    );
    time.tick(1234);
    assertEquals(
      await refreshTokenService.accessTokenExpiresAt(client, user, scope),
      new Date(Date.now() + hour),
    );
  } finally {
    time.restore();
  }
});

test(
  refreshTokenServiceTests,
  "accessTokenExpiresAt with client.accessTokenLifetime",
  async () => {
    const time: FakeTime = new FakeTime();
    try {
      const client: Client = {
        id: "1",
        grants: [],
        accessTokenLifetime: 5 * 60,
        refreshTokenLifetime: 24 * 60 * 60,
      };
      const fiveMinutes = 5 * 60 * 1000;
      const result: Promise<Date | undefined> = refreshTokenService
        .accessTokenExpiresAt(
          client,
          user,
          scope,
        );
      assertStrictEquals(Promise.resolve(result), result);
      assertEquals(await result, new Date(Date.now() + fiveMinutes));
      assertEquals(
        await refreshTokenService.accessTokenExpiresAt(client, user, scope),
        new Date(Date.now() + fiveMinutes),
      );
      time.tick(1234);
      assertEquals(
        await refreshTokenService.accessTokenExpiresAt(client, user, scope),
        new Date(Date.now() + fiveMinutes),
      );
    } finally {
      time.restore();
    }
  },
);

test(refreshTokenServiceTests, "generateRefreshToken", async () => {
  const result: Promise<string | undefined> = refreshTokenService
    .generateRefreshToken(
      client,
      user,
      scope,
    );
  assertStrictEquals(Promise.resolve(result), result);
  assert(v4.validate((await result) as string));
  assert(
    v4.validate(
      (await refreshTokenService.generateRefreshToken(
        client,
        user,
        scope,
      )) as string,
    ),
  );
});

test(refreshTokenServiceTests, "refreshTokenExpiresAt", async () => {
  const time: FakeTime = new FakeTime();
  try {
    const twoWeeks: number = 14 * 24 * 60 * 60 * 1000;
    const result: Promise<Date | undefined> = refreshTokenService
      .refreshTokenExpiresAt(
        client,
        user,
        scope,
      );
    assertStrictEquals(Promise.resolve(result), result);
    assertEquals(await result, new Date(Date.now() + twoWeeks));
    assertEquals(
      await refreshTokenService.refreshTokenExpiresAt(client, user, scope),
      new Date(Date.now() + twoWeeks),
    );
    time.tick(1234);
    assertEquals(
      await refreshTokenService.refreshTokenExpiresAt(client, user, scope),
      new Date(Date.now() + twoWeeks),
    );
  } finally {
    time.restore();
  }
});

test(
  refreshTokenServiceTests,
  "refreshTokenExpiresAt with client.refreshTokenLifetime",
  async () => {
    const time: FakeTime = new FakeTime();
    try {
      const client: Client = {
        id: "1",
        grants: [],
        accessTokenLifetime: 5 * 60,
        refreshTokenLifetime: 24 * 60 * 60,
      };
      const day = 24 * 60 * 60 * 1000;
      const result: Promise<Date | undefined> = refreshTokenService
        .refreshTokenExpiresAt(
          client,
          user,
          scope,
        );
      assertStrictEquals(Promise.resolve(result), result);
      assertEquals(await result, new Date(Date.now() + day));
      assertEquals(
        await refreshTokenService.refreshTokenExpiresAt(client, user, scope),
        new Date(Date.now() + day),
      );
      time.tick(1234);
      assertEquals(
        await refreshTokenService.refreshTokenExpiresAt(client, user, scope),
        new Date(Date.now() + day),
      );
    } finally {
      time.restore();
    }
  },
);
