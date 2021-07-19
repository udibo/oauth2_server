import {
  assert,
  assertEquals,
  assertSpyCall,
  assertStrictEquals,
  Spy,
  SpyCall,
  Stub,
} from "./test_deps.ts";
import { Client } from "./models/client.ts";
import { ScopeInterface } from "./models/scope.ts";
import { Token } from "./models/token.ts";
import { User } from "./models/user.ts";
import { AuthorizationCode } from "./models/authorization_code.ts";

export function assertScope(
  actual: ScopeInterface | undefined,
  expected: ScopeInterface | undefined,
): void {
  try {
    if (expected && actual) {
      assert(expected.equals(actual));
    } else {
      assertEquals(actual, expected);
    }
  } catch {
    assertEquals(
      actual ? [...actual].sort() : actual,
      expected ? [...expected].sort() : expected,
    );
  }
}

function assertWithoutScope(
  actual: Partial<AuthorizationCode> | Partial<Token>,
  expected: Partial<AuthorizationCode> | Partial<Token>,
): void {
  const actualWithoutScope = { ...actual };
  delete actualWithoutScope.scope;
  const expectedWithoutScope = { ...expected };
  delete expectedWithoutScope.scope;
  assertEquals(actualWithoutScope, expectedWithoutScope);
}

export function assertToken(
  actual: Partial<Token> | undefined,
  expected: Partial<Token> | undefined,
): void {
  // add test coverage for this new assertion
  assert(
    !!actual === !!expected,
    actual ? "did not expect token" : "expected token",
  );
  if (actual && expected) {
    assertScope(actual.scope, expected.scope);
    assertWithoutScope(actual, expected);
  }
}

export function assertAuthorizationCode(
  actual: Partial<AuthorizationCode> | undefined,
  expected: Partial<AuthorizationCode> | undefined,
): void {
  // add test coverage for this new assertion
  assert(
    !!actual === !!expected,
    actual
      ? "did not expect authorization code"
      : "expected authorization code",
  );
  if (actual && expected) {
    assertScope(actual.scope, expected.scope);
    assertWithoutScope(actual, expected);
  }
}

export function assertClientUserScopeCall(
  // deno-lint-ignore no-explicit-any
  spy: Spy<any> | Stub<any>,
  callIndex: number,
  // deno-lint-ignore no-explicit-any
  self: any,
  client: Client,
  user: User,
  expectedScope?: ScopeInterface,
): void {
  const call: SpyCall = assertSpyCall(spy, callIndex);
  assertStrictEquals(call.self, self);
  assertEquals(call.args.slice(0, 2), [client, user]);
  const actualScope: ScopeInterface | undefined = call.args[2];
  assertScope(actualScope, expectedScope);
}
