import { BasicAuth, parseBasicAuth } from "./basic_auth.ts";
import { assertEquals, assertThrows } from "./deps/std/testing/asserts.ts";
import { test, TestSuite } from "./deps/udibo/test_suite/mod.ts";
import { InvalidClient } from "./errors.ts";

const parseBasicAuthTests: TestSuite<void> = new TestSuite({
  name: "parseBasicAuth",
});

test(parseBasicAuthTests, "authorization header required", () => {
  assertThrows(
    () => parseBasicAuth(null),
    InvalidClient,
    "authorization header required",
  );
  assertThrows(
    () => parseBasicAuth(""),
    InvalidClient,
    "authorization header required",
  );
});

test(parseBasicAuthTests, "unsupported authorization header", () => {
  assertThrows(
    () => parseBasicAuth("x"),
    InvalidClient,
    "unsupported authorization header",
  );
  assertThrows(
    () => parseBasicAuth("basic"),
    InvalidClient,
    "unsupported authorization header",
  );
  assertThrows(
    () => parseBasicAuth("Bearer mF_9.B5f-4.1JqM"),
    InvalidClient,
    "unsupported authorization header",
  );
});

test(
  parseBasicAuthTests,
  "authorization header is not correctly encoded",
  () => {
    assertThrows(
      () => parseBasicAuth("basic x"),
      InvalidClient,
      "authorization header is not correctly encoded",
    );
    assertThrows(
      () => parseBasicAuth(`basic ${btoa("kyle")}=`),
      InvalidClient,
      "authorization header is not correctly encoded",
    );
  },
);

test(parseBasicAuthTests, "authorization header is malformed", () => {
  assertThrows(
    () => parseBasicAuth(`basic ${btoa("kyle")}`),
    InvalidClient,
    "authorization header is malformed",
  );
  assertThrows(
    () => parseBasicAuth(`basic ${btoa(":")}`),
    InvalidClient,
    "authorization header is malformed",
  );
  assertThrows(
    () => parseBasicAuth(`basic ${btoa(":hunter2")}`),
    InvalidClient,
    "authorization header is malformed",
  );
});

test(parseBasicAuthTests, "returns correct name and pass", () => {
  let basicAuth: BasicAuth = parseBasicAuth(`basic ${btoa("kyle:")}`);
  assertEquals(basicAuth, { name: "kyle", pass: "" });
  basicAuth = parseBasicAuth(`BASIC ${btoa("kyle:hunter2")}`);
  assertEquals(basicAuth, { name: "kyle", pass: "hunter2" });
  basicAuth = parseBasicAuth(`BaSiC ${btoa("Kyle:Hunter2")}`);
  assertEquals(basicAuth, { name: "Kyle", pass: "Hunter2" });
});
