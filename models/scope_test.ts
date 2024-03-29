import { SCOPE, Scope, SCOPE_TOKEN } from "./scope.ts";
import {
  assertEquals,
  assertStrictEquals,
  assertThrows,
  describe,
  it,
} from "../test_deps.ts";
import { InvalidScopeError } from "../errors.ts";

it("SCOPE", () => {
  assertStrictEquals(SCOPE.test(""), true);
  assertStrictEquals(SCOPE.test("a"), true);
  assertStrictEquals(SCOPE.test(" "), false);
  assertStrictEquals(SCOPE.test(" a"), false);
  assertStrictEquals(SCOPE.test("a "), false);
  assertStrictEquals(SCOPE.test("a  b"), false);
  assertStrictEquals(SCOPE.test("a b a c"), true);
  assertStrictEquals(SCOPE.test("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~"), true);
  assertStrictEquals(SCOPE.test('"'), false);
  assertStrictEquals(SCOPE.test('a"b'), false);
  assertStrictEquals(SCOPE.test('a b"c a d'), false);
  assertStrictEquals(SCOPE.test("\\"), false);
  assertStrictEquals(SCOPE.test("a\\b"), false);
  assertStrictEquals(SCOPE.test("a b\\c a d"), false);
});

it("SCOPE_TOKEN", () => {
  assertEquals("".match(SCOPE_TOKEN), null);
  assertEquals("a".match(SCOPE_TOKEN), ["a"]);
  assertEquals("a b a c".match(SCOPE_TOKEN), ["a", "b", "a", "c"]);
  assertEquals("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~".match(SCOPE_TOKEN), [
    "!#0A[]a~",
    "!#1B[]b~",
    "!#0A[]a~",
    "!#2C[]c~",
  ]);
});

const scopeTests = describe("Scope");

it(scopeTests, "constructor validation", () => {
  new Scope("a");
  assertThrows(() => new Scope(" "), InvalidScopeError, "invalid scope");
  assertThrows(() => new Scope(" a"), InvalidScopeError, "invalid scope");
  assertThrows(() => new Scope("a "), InvalidScopeError, "invalid scope");
  assertThrows(() => new Scope("a  b"), InvalidScopeError, "invalid scope");
  new Scope("a b a c");
  new Scope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
  assertThrows(() => new Scope('"'), InvalidScopeError, "invalid scope");
  assertThrows(() => new Scope('a"b'), InvalidScopeError, "invalid scope");
  assertThrows(() => new Scope('a b"ca d'), InvalidScopeError, "invalid scope");
  assertThrows(() => new Scope("\\"), InvalidScopeError, "invalid scope");
  assertThrows(() => new Scope("a\\b"), InvalidScopeError, "invalid scope");
  assertThrows(
    () => new Scope("a b\\c a d"),
    InvalidScopeError,
    "invalid scope",
  );
});

it(scopeTests, "toString", () => {
  let scope = new Scope("a");
  assertStrictEquals(scope.toString(), "a");
  assertStrictEquals(scope.toString(), "a");
  scope = new Scope("a b a c");
  assertStrictEquals(scope.toString(), "a b c");
  assertStrictEquals(scope.toString(), "a b c");
  scope = new Scope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
  assertStrictEquals(scope.toString(), "!#0A[]a~ !#1B[]b~ !#2C[]c~");
  assertStrictEquals(scope.toString(), "!#0A[]a~ !#1B[]b~ !#2C[]c~");
});

it(scopeTests, "toJSON", () => {
  let scope = new Scope("a");
  assertStrictEquals(scope.toJSON(), "a");
  assertStrictEquals(scope.toJSON(), "a");
  scope = new Scope("a b a c");
  assertStrictEquals(scope.toJSON(), "a b c");
  assertStrictEquals(scope.toJSON(), "a b c");
  scope = new Scope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
  assertStrictEquals(scope.toJSON(), "!#0A[]a~ !#1B[]b~ !#2C[]c~");
  assertStrictEquals(scope.toJSON(), "!#0A[]a~ !#1B[]b~ !#2C[]c~");
});

it(scopeTests, "from", () => {
  assertStrictEquals(Scope.from("a").toString(), "a");
  let scope: Scope = new Scope("a");
  assertStrictEquals(Scope.from(scope).toString(), "a");
  assertStrictEquals(scope.toString(), "a");

  assertStrictEquals(Scope.from("a b a c").toString(), "a b c");
  scope = new Scope("a b a c");
  assertStrictEquals(Scope.from(scope).toString(), "a b c");
  assertStrictEquals(scope.toString(), "a b c");

  assertStrictEquals(
    Scope.from("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~").toString(),
    "!#0A[]a~ !#1B[]b~ !#2C[]c~",
  );
  scope = new Scope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
  assertStrictEquals(
    Scope.from(scope).toString(),
    "!#0A[]a~ !#1B[]b~ !#2C[]c~",
  );
  assertStrictEquals(scope.toString(), "!#0A[]a~ !#1B[]b~ !#2C[]c~");
});

it(scopeTests, "has", () => {
  let scope = new Scope("a");
  assertStrictEquals(scope.has("a"), true);
  assertStrictEquals(scope.has(new Scope("a")), true);
  assertStrictEquals(scope.has("b"), false);
  assertStrictEquals(scope.has(new Scope("b")), false);

  scope = new Scope("a b c");
  assertStrictEquals(scope.has("a"), true);
  assertStrictEquals(scope.has(new Scope("a")), true);
  assertStrictEquals(scope.has("b"), true);
  assertStrictEquals(scope.has(new Scope("b")), true);
  assertStrictEquals(scope.has("c"), true);
  assertStrictEquals(scope.has(new Scope("c")), true);
  assertStrictEquals(scope.has("d"), false);
  assertStrictEquals(scope.has(new Scope("d")), false);
  assertStrictEquals(scope.has("a b"), true);
  assertStrictEquals(scope.has(new Scope("a b")), true);
  assertStrictEquals(scope.has("b c"), true);
  assertStrictEquals(scope.has(new Scope("b c")), true);
  assertStrictEquals(scope.has("c d"), false);
  assertStrictEquals(scope.has(new Scope("c d")), false);
  assertStrictEquals(scope.has("d a"), false);
  assertStrictEquals(scope.has(new Scope("d a")), false);
  assertStrictEquals(scope.has("a b c"), true);
  assertStrictEquals(scope.has(new Scope("a b c")), true);
  assertStrictEquals(scope.has("b c a"), true);
  assertStrictEquals(scope.has(new Scope("b c a")), true);
  assertStrictEquals(scope.has("a d c"), false);
  assertStrictEquals(scope.has(new Scope("a d c")), false);

  scope = new Scope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
  assertStrictEquals(scope.has("!#0A[]a~ !#2C[]c~"), true);
  assertStrictEquals(
    scope.has(new Scope("!#0A[]a~ !#2C[]c~")),
    true,
  );
  assertStrictEquals(scope.has("!#2C[]c~ !#1B[]b~ !#0A[]a~"), true);
  assertStrictEquals(
    scope.has(new Scope("!#2C[]c~ !#1B[]b~ !#0A[]a~")),
    true,
  );
  assertStrictEquals(scope.has("!#2C[]c~ !#3D[]d~ !#0A[]a~"), false);
  assertStrictEquals(
    scope.has(new Scope("!#2C[]c~ !#3D[]d~ !#0A[]a~")),
    false,
  );
});

it(scopeTests, "add", () => {
  const scope: Scope = new Scope();
  assertStrictEquals(scope.add("a"), scope);
  assertStrictEquals(scope.toString(), "a");
  assertStrictEquals(scope.add(new Scope("b")), scope);
  assertStrictEquals(scope.toString(), "a b");
  assertStrictEquals(scope.add("c d c a e"), scope);
  assertStrictEquals(scope.toString(), "a b c d e");
  assertStrictEquals(scope.add(new Scope("b f e b f g")), scope);
  assertStrictEquals(scope.toString(), "a b c d e f g");
});

it(scopeTests, "remove", () => {
  const scope: Scope = new Scope("a b c d e f g");
  assertStrictEquals(scope.remove("a"), scope);
  assertStrictEquals(scope.toString(), "b c d e f g");
  assertStrictEquals(scope.remove(new Scope("b")), scope);
  assertStrictEquals(scope.toString(), "c d e f g");
  assertStrictEquals(scope.remove("c d c a e"), scope);
  assertStrictEquals(scope.toString(), "f g");
  assertStrictEquals(scope.remove(new Scope("b f e b f g")), scope);
  assertStrictEquals(scope.toString(), "");
});

it(scopeTests, "equals", () => {
  let scope = new Scope("a");
  assertStrictEquals(scope.equals("a"), true);
  assertStrictEquals(scope.equals(new Scope("a")), true);
  assertStrictEquals(scope.equals("b"), false);
  assertStrictEquals(scope.equals(new Scope("b")), false);

  scope = new Scope("a b c");
  assertStrictEquals(scope.equals("a"), false);
  assertStrictEquals(scope.equals(new Scope("a")), false);
  assertStrictEquals(scope.equals("a b"), false);
  assertStrictEquals(scope.equals(new Scope("a b")), false);

  assertStrictEquals(scope.equals("a b c"), true);
  assertStrictEquals(scope.equals(new Scope("a b c")), true);
  assertStrictEquals(scope.equals("b c a"), true);
  assertStrictEquals(scope.equals(new Scope("b c a")), true);

  assertStrictEquals(scope.equals("a d c"), false);
  assertStrictEquals(scope.equals(new Scope("a d c")), false);
  assertStrictEquals(scope.equals("a b c d"), false);
  assertStrictEquals(scope.equals(new Scope("a b c d")), false);
});

it(scopeTests, "clear", () => {
  const scope: Scope = new Scope("a b c");
  scope.add("d");
  assertStrictEquals(scope.toString(), "a b c d");
  assertStrictEquals(scope.clear(), scope);
  assertStrictEquals(scope.toString(), "");
  scope.add("a b").add("b c d");
  assertStrictEquals(scope.toString(), "a b c d");
  assertStrictEquals(scope.clear(), scope);
  assertStrictEquals(scope.toString(), "");
});

it(scopeTests, "union", () => {
  const scopes: [Scope, Scope] = [
    new Scope("a b c e"),
    new Scope("b d e f"),
  ];
  const unionScope = Scope.union(scopes[0], scopes[1]);
  assertStrictEquals(unionScope.toString(), "a b c e d f");
  assertStrictEquals(scopes[0].toString(), "a b c e");
  assertStrictEquals(scopes[1].toString(), "b d e f");
});

it(scopeTests, "intersection", () => {
  const scopes: [Scope, Scope] = [
    new Scope("a b c e"),
    new Scope("b d e f"),
  ];
  const intersectionScope = Scope.intersection(scopes[0], scopes[1]);
  assertStrictEquals(intersectionScope.toString(), "b e");
  assertStrictEquals(scopes[0].toString(), "a b c e");
  assertStrictEquals(scopes[1].toString(), "b d e f");
});

it(scopeTests, "iterator", () => {
  assertEquals([...(new Scope("a c b d"))].sort(), ["a", "b", "c", "d"]);
});
