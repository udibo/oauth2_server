import {
  assert,
  assertEquals,
  assertSpyCall,
  assertStrictEquals,
  Spy,
} from "./test_deps.ts";
import { ClientInterface } from "./models/client.ts";
import { ScopeInterface } from "./models/scope.ts";
import { Token } from "./models/token.ts";
import { AuthorizationCode } from "./models/authorization_code.ts";

export function assertScope<Scope extends ScopeInterface>(
  actual: unknown,
  expected: Scope | null | undefined,
): void {
  try {
    if (expected && actual) {
      assert(expected.equals(actual as Scope));
    } else {
      assertEquals(actual, expected);
    }
  } catch {
    assertEquals(
      actual ? [...actual as Scope].sort() : actual,
      expected ? [...expected].sort() : expected,
    );
  }
}

function assertWithoutScope<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
>(
  actual: unknown,
  expected:
    | Partial<AuthorizationCode<Client, User, Scope>>
    | Partial<Token<Client, User, Scope>>,
): void {
  const actualWithoutScope = {
    ...(actual as (
      | Partial<AuthorizationCode<Client, User, Scope>>
      | Partial<Token<Client, User, Scope>>
    )),
  };
  delete actualWithoutScope.scope;
  const expectedWithoutScope = { ...expected };
  delete expectedWithoutScope.scope;
  assertEquals(actualWithoutScope, expectedWithoutScope);
}

export function assertToken<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
>(
  actual: unknown,
  expected: Partial<Token<Client, User, Scope>> | null | undefined,
): void {
  assert(
    !!actual === !!expected,
    actual ? "did not expect token" : "expected token",
  );
  if (actual && expected) {
    assertScope(
      (actual as Partial<Token<Client, User, Scope>>).scope,
      expected.scope,
    );
    assertWithoutScope(actual, expected);
  }
}

export function assertAuthorizationCode<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
>(
  actual: unknown,
  expected: Partial<AuthorizationCode<Client, User, Scope>> | null | undefined,
): void {
  assert(
    !!actual === !!expected,
    actual
      ? "did not expect authorization code"
      : "expected authorization code",
  );
  if (actual && expected) {
    assertScope(
      (actual as Partial<AuthorizationCode<Client, User, Scope>>).scope,
      expected.scope,
    );
    assertWithoutScope(actual, expected);
  }
}

export function assertClientUserScopeCall<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
>(
  spy: Spy,
  callIndex: number,
  self: unknown,
  client: Client,
  user: User,
  scope?: Scope | null,
): void {
  assertSpyCall(spy, callIndex);
  const call = spy.calls[callIndex];
  assertStrictEquals(call.self, self);
  assertEquals(call.args.slice(0, 2), [client, user]);
  const actualScope: ScopeInterface | undefined = call.args[2];
  assertScope(actualScope, scope);
}
