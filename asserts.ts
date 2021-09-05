import {
  assert,
  assertEquals,
  assertSpyCall,
  assertStrictEquals,
  assertThrows,
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

function assertWithoutScope<Scope extends ScopeInterface>(
  actual: Partial<AuthorizationCode<Scope>> | Partial<Token<Scope>>,
  expected: Partial<AuthorizationCode<Scope>> | Partial<Token<Scope>>,
): void {
  const actualWithoutScope = { ...actual };
  delete actualWithoutScope.scope;
  const expectedWithoutScope = { ...expected };
  delete expectedWithoutScope.scope;
  assertEquals(actualWithoutScope, expectedWithoutScope);
}

export function assertToken<Scope extends ScopeInterface>(
  actual: Partial<Token<Scope>> | undefined,
  expected: Partial<Token<Scope>> | undefined,
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

export function assertAuthorizationCode<Scope extends ScopeInterface>(
  actual: Partial<AuthorizationCode<Scope>> | undefined,
  expected: Partial<AuthorizationCode<Scope>> | undefined,
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

// replace with assertError from std if suggestion gets implemented
// https://github.com/denoland/deno_std/issues/1182
export interface Constructor {
  // deno-lint-ignore no-explicit-any
  new (...args: any[]): any;
}

export function assertError(
  error: Error,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
) {
  assertThrows(
    () => {
      throw error;
    },
    ErrorClass,
    msgIncludes,
    msg,
  );
}
