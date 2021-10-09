import {
  assert,
  assertEquals,
  assertStrictEquals,
  FakeTime,
  test,
  TestSuite,
  v4,
} from "../test_deps.ts";
import {
  AuthorizationCodeService,
  client,
  scope,
  user,
} from "./test_services.ts";

const authorizationCodeService = new AuthorizationCodeService();

const authorizationCodeServiceTests: TestSuite<void> = new TestSuite({
  name: "AuthorizationCodeService",
});

test(authorizationCodeServiceTests, "generateAuthorizationCode", async () => {
  const result = authorizationCodeService.generateCode(
    client,
    user,
    scope,
  );
  assertStrictEquals(Promise.resolve(result), result);
  assert(v4.validate(await result));
  assert(
    v4.validate(
      await authorizationCodeService.generateCode(client, user, scope),
    ),
  );
});

test(authorizationCodeServiceTests, "accessTokenExpiresAt", async () => {
  const time: FakeTime = new FakeTime();
  try {
    const fiveMinutes: number = 5 * 60 * 1000;
    const result = authorizationCodeService.expiresAt(client, user, scope);
    assertStrictEquals(Promise.resolve(result), result);
    assertEquals(await result, new Date(Date.now() + fiveMinutes));
    assertEquals(
      await authorizationCodeService.expiresAt(client, user, scope),
      new Date(Date.now() + fiveMinutes),
    );
    time.tick(1234);
    assertEquals(
      await authorizationCodeService.expiresAt(client, user, scope),
      new Date(Date.now() + fiveMinutes),
    );
  } finally {
    time.restore();
  }
});
