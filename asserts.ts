import {
  assert,
  assertEquals,
  AssertionError,
  assertSpyCall,
  assertStrictEquals,
  assertThrows,
  Spy,
  SpyCall,
  Stub,
} from "./test_deps.ts";
import { ClientInterface } from "./models/client.ts";
import { ScopeInterface } from "./models/scope.ts";
import { Token } from "./models/token.ts";
import { AuthorizationCode } from "./models/authorization_code.ts";

export function assertScope<Scope extends ScopeInterface>(
  actual: Scope | null | undefined,
  expected: Scope | null | undefined,
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

function assertWithoutScope<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
>(
  actual:
    | Partial<AuthorizationCode<Client, User, Scope>>
    | Partial<Token<Client, User, Scope>>,
  expected:
    | Partial<AuthorizationCode<Client, User, Scope>>
    | Partial<Token<Client, User, Scope>>,
): void {
  const actualWithoutScope = { ...actual };
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
  actual: Partial<Token<Client, User, Scope>> | null | undefined,
  expected: Partial<Token<Client, User, Scope>> | null | undefined,
): void {
  assert(
    !!actual === !!expected,
    actual ? "did not expect token" : "expected token",
  );
  if (actual && expected) {
    assertScope(actual.scope, expected.scope);
    assertWithoutScope(actual, expected);
  }
}

export function assertAuthorizationCode<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
>(
  actual: Partial<AuthorizationCode<Client, User, Scope>> | null | undefined,
  expected: Partial<AuthorizationCode<Client, User, Scope>> | null | undefined,
): void {
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

export function assertClientUserScopeCall<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
>(
  // deno-lint-ignore no-explicit-any
  spy: Spy<any> | Stub<any>,
  callIndex: number,
  // deno-lint-ignore no-explicit-any
  self: any,
  client: Client,
  user: User,
  expectedScope?: Scope | null,
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
  error: unknown,
  ErrorClass?: Constructor,
  msgIncludes?: string,
  msg?: string,
): void;
export function assertError(
  error: unknown,
  errorCallback: (e: Error) => unknown,
  msg?: string,
): void;
export function assertError(
  error: unknown,
  errorClassOrCallback?: Constructor | ((e: Error) => unknown),
  msgIncludesOrMsg?: string,
  msg?: string,
): void {
  if (error instanceof Error === false) {
    throw new AssertionError(`Expected "error" to be an Error object.`);
  }
  assertThrows(
    () => {
      throw error;
    },
    errorClassOrCallback as Constructor,
    msgIncludesOrMsg,
    msg,
  );
}
