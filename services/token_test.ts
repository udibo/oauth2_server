import { Client } from "../models/client.ts";
import { ScopeInterface } from "../models/scope.ts";
import {
  assert,
  assertEquals,
  assertRejects,
  assertStrictEquals,
  FakeTime,
  test,
  TestSuite,
  v4,
} from "../test_deps.ts";
import { ServerError } from "../errors.ts";
import {
  AccessTokenService,
  client,
  RefreshTokenService,
  scope,
  user,
} from "./test_services.ts";

const accessTokenService = new AccessTokenService();

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
    await assertRejects(
      () => result,
      ServerError,
      "generateRefreshToken not implemented",
    );
    await assertRejects(
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
    await assertRejects(
      () => result,
      ServerError,
      "refreshTokenExpiresAt not implemented",
    );
    await assertRejects(
      () => accessTokenService.refreshTokenExpiresAt(client, user, scope),
      ServerError,
      "refreshTokenExpiresAt not implemented",
    );
  },
);

test(accessTokenServiceTests, "getRefreshToken not implemented", async () => {
  const result = accessTokenService.getRefreshToken("fake");
  assertStrictEquals(Promise.resolve(result), result);
  await assertRejects(
    () => result,
    ServerError,
    "getRefreshToken not implemented",
  );
  await assertRejects(
    () => accessTokenService.getRefreshToken("fake"),
    ServerError,
    "getRefreshToken not implemented",
  );
});

test(
  accessTokenServiceTests,
  "acceptedScope defaults to always passing",
  async () => {
    let result: Promise<ScopeInterface | undefined | false> = accessTokenService
      .acceptedScope(client, user);
    assertStrictEquals(Promise.resolve(result), result);
    assertStrictEquals(await result, undefined);
    result = accessTokenService.acceptedScope(client, user, scope);
    assertStrictEquals(Promise.resolve(result), result);
    assertStrictEquals(await result, scope);
  },
);

const refreshTokenService = new RefreshTokenService();

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
