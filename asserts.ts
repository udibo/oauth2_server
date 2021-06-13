import {
  assert,
  assertEquals,
  assertStrictEquals,
  SpyCall,
} from "./test_deps.ts";
import { Client } from "./models/client.ts";
import { ScopeInterface } from "./models/scope.ts";
import { Token } from "./models/token.ts";
import { User } from "./models/user.ts";

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

export function assertToken(actual: Token, expected: Token): void {
  assertScope(actual.scope, expected.scope);
  const actualWithoutScope = { ...actual };
  delete actualWithoutScope.scope;
  const expectedWithoutScope = { ...expected };
  delete expectedWithoutScope.scope;
  assertEquals(actualWithoutScope, expectedWithoutScope);
}

export function assertClientUserScopeCall(
  call: SpyCall,
  // deno-lint-ignore no-explicit-any
  self: any,
  client: Client,
  user: User,
  expectedScope?: ScopeInterface,
): void {
  assertStrictEquals(call.self, self);
  assertEquals(call.args.length, 3);
  assertEquals(call.args.slice(0, 2), [client, user]);
  const actualScope: ScopeInterface | undefined = call.args[2];
  assertScope(actualScope, expectedScope);
}
