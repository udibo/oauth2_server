import { assertScope, assertToken } from "./asserts.ts";
import { AssertionError, assertThrows } from "./deps/std/testing/asserts.ts";
import { test, TestSuite } from "./deps/udibo/test_suite/mod.ts";
import { Client } from "./models/client.ts";
import { Scope } from "./models/scope.ts";
import { Token } from "./models/token.ts";
import { User } from "./models/user.ts";

const assertsTests: TestSuite<void> = new TestSuite({
  name: "asserts",
});

test(assertsTests, "assertScope", () => {
  assertScope(undefined, undefined);
  assertScope(new Scope(), new Scope());
  assertScope(new Scope("read"), new Scope("read"));
  assertScope(new Scope("read write"), new Scope("read write"));
  assertScope(new Scope("read write"), new Scope("write read"));

  assertThrows(
    () => assertScope(new Scope(), undefined),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () => assertScope(undefined, new Scope()),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () => assertScope(new Scope("read"), undefined),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () => assertScope(undefined, new Scope("read")),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () => assertScope(new Scope("read"), new Scope("read write")),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () => assertScope(new Scope("read write"), new Scope("read")),
    AssertionError,
    "Values are not equal",
  );
});

const client: Client = { id: "1", grants: [] };
const user: User = { username: "kyle" };

test(assertsTests, "assertToken", () => {
  const expectedToken: Token = {
    accessToken: "x",
    client: { id: "1", grants: [] },
    user: { username: "kyle" },
  };
  assertToken({ accessToken: "x", client, user }, { ...expectedToken });
  assertToken({ accessToken: "x", client, user, scope: new Scope() }, {
    ...expectedToken,
    scope: new Scope(),
  });
  assertToken({ accessToken: "x", client, user, scope: new Scope("read") }, {
    ...expectedToken,
    scope: new Scope("read"),
  });
  assertToken({
    accessToken: "x",
    client,
    user,
    scope: new Scope("read write"),
  }, { ...expectedToken, scope: new Scope("read write") });
  assertToken({
    accessToken: "x",
    client,
    user,
    scope: new Scope("read write"),
  }, { ...expectedToken, scope: new Scope("write read") });

  assertThrows(
    () =>
      assertToken({ accessToken: "x", client, user }, {
        ...expectedToken,
        accessToken: "y",
      }),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertToken({ accessToken: "x", client, user }, {
        ...expectedToken,
        scope: new Scope(),
      }),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertToken(
        { accessToken: "x", client, user, scope: new Scope() },
        expectedToken,
      ),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertToken({ accessToken: "x", client, user }, {
        ...expectedToken,
        scope: new Scope("read"),
      }),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertToken(
        { accessToken: "x", client, user, scope: new Scope("read") },
        expectedToken,
      ),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertToken(
        { accessToken: "x", client, user, scope: new Scope("read") },
        {
          ...expectedToken,
          scope: new Scope("read write"),
        },
      ),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertToken({
        accessToken: "x",
        client,
        user,
        scope: new Scope("read write"),
      }, {
        ...expectedToken,
        scope: new Scope("read"),
      }),
    AssertionError,
    "Values are not equal",
  );
});
