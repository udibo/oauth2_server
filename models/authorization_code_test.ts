import {
  AuthorizationCode,
  AuthorizationCodeService,
  AuthorizationCodeServiceInterface,
} from "./authorization_code.ts";
import { User } from "./user.ts";
import { Client } from "./client.ts";
import { Scope } from "./scope.ts";
import { v4 } from "../deps.ts";
import {
  assert,
  assertEquals,
  assertStrictEquals,
  FakeTime,
  test,
  TestSuite,
} from "../test_deps.ts";

const client: Client = {
  id: "1",
  grants: ["authorization_code"],
};
const user: User = {};
const scope: Scope = new Scope("read");

export class ExampleAuthorizationCodeService extends AuthorizationCodeService {
  /** Retrieves an existing authorization code. */
  get(code: string): Promise<AuthorizationCode | undefined> {
    return Promise.resolve({
      code,
      expiresAt: new Date(Date.now() + 60000),
      redirectUri: "https://oauth2.example.com/code",
      client,
      user,
      scope,
    });
  }

  /** Saves an authorization code. */
  save(authorizationCode: AuthorizationCode): Promise<AuthorizationCode> {
    return Promise.resolve(authorizationCode);
  }

  /** Revokes an authorization code. */
  revoke(_authorizationCode: AuthorizationCode): Promise<boolean> {
    return Promise.resolve(true);
  }
}

const authorizationCodeService: AuthorizationCodeServiceInterface =
  new ExampleAuthorizationCodeService();

const authorizationCodeServiceTests: TestSuite<void> = new TestSuite({
  name: "AuthorizationCodeService",
});

test(authorizationCodeServiceTests, "generateAuthorizationCode", async () => {
  const result: Promise<string> = authorizationCodeService.generateCode(
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
