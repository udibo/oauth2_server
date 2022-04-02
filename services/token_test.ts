import { Client } from "../models/client.ts";
import {
  assert,
  assertEquals,
  assertRejects,
  assertStrictEquals,
  describe,
  FakeTime,
  it,
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

const accessTokenServiceTests = describe("AccessTokenService");

it(accessTokenServiceTests, "generateAccessToken", async () => {
  const result = accessTokenService.generateAccessToken(
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

it(
  accessTokenServiceTests,
  "generateRefreshToken not implemented",
  async () => {
    const result = accessTokenService
      .generateRefreshToken(client, user, scope);
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

it(accessTokenServiceTests, "accessTokenExpiresAt", async () => {
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

it(
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

it(
  accessTokenServiceTests,
  "refreshTokenExpiresAt not implemented",
  async () => {
    const result = accessTokenService
      .refreshTokenExpiresAt(client, user, scope);
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

it(accessTokenServiceTests, "getRefreshToken not implemented", async () => {
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

it(
  accessTokenServiceTests,
  "acceptedScope defaults to always passing",
  async () => {
    let result = accessTokenService.acceptedScope(client, user);
    assertStrictEquals(Promise.resolve(result), result);
    assertStrictEquals(await result, undefined);
    result = accessTokenService.acceptedScope(client, user, scope);
    assertStrictEquals(Promise.resolve(result), result);
    assertStrictEquals(await result, scope);
  },
);

const refreshTokenService = new RefreshTokenService();

const refreshTokenServiceTests = describe("RefreshTokenService");

it(refreshTokenServiceTests, "generateAccessToken", async () => {
  const result = refreshTokenService.generateAccessToken(
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

it(refreshTokenServiceTests, "accessTokenExpiresAt", async () => {
  const time = new FakeTime();
  try {
    const hour = 60 * 60 * 1000;
    const result = refreshTokenService
      .accessTokenExpiresAt(client, user, scope);
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

it(
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
      const result = refreshTokenService
        .accessTokenExpiresAt(client, user, scope);
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

it(refreshTokenServiceTests, "generateRefreshToken", async () => {
  const result = refreshTokenService
    .generateRefreshToken(client, user, scope);
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

it(refreshTokenServiceTests, "refreshTokenExpiresAt", async () => {
  const time = new FakeTime();
  try {
    const twoWeeks = 14 * 24 * 60 * 60 * 1000;
    const result = refreshTokenService
      .refreshTokenExpiresAt(client, user, scope);
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

it(
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
      const result = refreshTokenService
        .refreshTokenExpiresAt(client, user, scope);
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
