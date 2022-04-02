import {
  assertAuthorizationCode,
  assertScope,
  assertToken,
} from "./asserts.ts";
import { AssertionError, assertThrows, describe, it } from "./test_deps.ts";
import { Client } from "./models/client.ts";
import { Scope } from "./models/scope.ts";
import { Token } from "./models/token.ts";
import { AuthorizationCode } from "./models/authorization_code.ts";
import { User } from "./models/user.ts";

const assertsTests = describe("asserts");

it(assertsTests, "assertScope", () => {
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

it(assertsTests, "assertToken", () => {
  const expectedToken: Token<Client, User, Scope> = {
    accessToken: "x",
    client: { id: "1", grants: [] },
    user: { username: "kyle" },
  };
  assertToken(undefined, undefined);
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
    () => assertToken({ accessToken: "x", client, user }, undefined),
    AssertionError,
    "did not expect token",
  );
  assertThrows(
    () => assertToken(undefined, { ...expectedToken }),
    AssertionError,
    "expected token",
  );

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

it(assertsTests, "assertAuthorizationCode", () => {
  const expiresAt = new Date(Date.now() + 60000);
  const expectedAuthorizationCode: AuthorizationCode<Client, User, Scope> = {
    code: "x",
    expiresAt,
    client: { id: "1", grants: [] },
    user: { username: "kyle" },
  };
  assertAuthorizationCode(undefined, undefined);
  assertAuthorizationCode({ code: "x", expiresAt, client, user }, {
    ...expectedAuthorizationCode,
  });
  assertAuthorizationCode({
    code: "x",
    expiresAt,
    client,
    user,
    scope: new Scope(),
  }, {
    ...expectedAuthorizationCode,
    scope: new Scope(),
  });
  assertAuthorizationCode({
    code: "x",
    expiresAt,
    client,
    user,
    scope: new Scope("read"),
  }, {
    ...expectedAuthorizationCode,
    scope: new Scope("read"),
  });
  assertAuthorizationCode({
    code: "x",
    expiresAt,
    client,
    user,
    scope: new Scope("read write"),
  }, { ...expectedAuthorizationCode, scope: new Scope("read write") });
  assertAuthorizationCode({
    code: "x",
    expiresAt,
    client,
    user,
    scope: new Scope("read write"),
  }, { ...expectedAuthorizationCode, scope: new Scope("write read") });

  assertThrows(
    () =>
      assertAuthorizationCode(
        { code: "x", expiresAt, client, user },
        undefined,
      ),
    AssertionError,
    "did not expect authorization code",
  );
  assertThrows(
    () => assertAuthorizationCode(undefined, { ...expectedAuthorizationCode }),
    AssertionError,
    "expected authorization code",
  );

  assertThrows(
    () =>
      assertAuthorizationCode({ code: "x", expiresAt, client, user }, {
        ...expectedAuthorizationCode,
        code: "y",
      }),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertAuthorizationCode({ code: "x", expiresAt, client, user }, {
        ...expectedAuthorizationCode,
        scope: new Scope(),
      }),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertAuthorizationCode(
        { code: "x", expiresAt, client, user, scope: new Scope() },
        expectedAuthorizationCode,
      ),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertAuthorizationCode({ code: "x", expiresAt, client, user }, {
        ...expectedAuthorizationCode,
        scope: new Scope("read"),
      }),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertAuthorizationCode(
        { code: "x", expiresAt, client, user, scope: new Scope("read") },
        expectedAuthorizationCode,
      ),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertAuthorizationCode(
        { code: "x", expiresAt, client, user, scope: new Scope("read") },
        {
          ...expectedAuthorizationCode,
          scope: new Scope("read write"),
        },
      ),
    AssertionError,
    "Values are not equal",
  );
  assertThrows(
    () =>
      assertAuthorizationCode({
        code: "x",
        expiresAt,
        client,
        user,
        scope: new Scope("read write"),
      }, {
        ...expectedAuthorizationCode,
        scope: new Scope("read"),
      }),
    AssertionError,
    "Values are not equal",
  );
});
