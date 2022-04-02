import { BasicAuth, parseBasicAuth } from "./basic_auth.ts";
import { assertEquals, assertThrows, describe, it } from "./test_deps.ts";
import { InvalidClientError } from "./errors.ts";

const parseBasicAuthTests = describe("parseBasicAuth");

it(parseBasicAuthTests, "authorization header required", () => {
  assertThrows(
    () => parseBasicAuth(null),
    InvalidClientError,
    "authorization header required",
  );
  assertThrows(
    () => parseBasicAuth(""),
    InvalidClientError,
    "authorization header required",
  );
});

it(parseBasicAuthTests, "unsupported authorization header", () => {
  assertThrows(
    () => parseBasicAuth("x"),
    InvalidClientError,
    "unsupported authorization header",
  );
  assertThrows(
    () => parseBasicAuth("basic"),
    InvalidClientError,
    "unsupported authorization header",
  );
  assertThrows(
    () => parseBasicAuth("Bearer mF_9.B5f-4.1JqM"),
    InvalidClientError,
    "unsupported authorization header",
  );
});

it(
  parseBasicAuthTests,
  "authorization header is not correctly encoded",
  () => {
    assertThrows(
      () => parseBasicAuth("basic x"),
      InvalidClientError,
      "authorization header is not correctly encoded",
    );
    assertThrows(
      () => parseBasicAuth(`basic ${btoa("kyle")}=`),
      InvalidClientError,
      "authorization header is not correctly encoded",
    );
  },
);

it(parseBasicAuthTests, "authorization header is malformed", () => {
  assertThrows(
    () => parseBasicAuth(`basic ${btoa("kyle")}`),
    InvalidClientError,
    "authorization header is malformed",
  );
  assertThrows(
    () => parseBasicAuth(`basic ${btoa(":")}`),
    InvalidClientError,
    "authorization header is malformed",
  );
  assertThrows(
    () => parseBasicAuth(`basic ${btoa(":hunter2")}`),
    InvalidClientError,
    "authorization header is malformed",
  );
});

it(parseBasicAuthTests, "returns correct name and pass", () => {
  let basicAuth: BasicAuth = parseBasicAuth(`basic ${btoa("kyle:")}`);
  assertEquals(basicAuth, { name: "kyle", pass: "" });
  basicAuth = parseBasicAuth(`BASIC ${btoa("kyle:hunter2")}`);
  assertEquals(basicAuth, { name: "kyle", pass: "hunter2" });
  basicAuth = parseBasicAuth(`BaSiC ${btoa("Kyle:Hunter2")}`);
  assertEquals(basicAuth, { name: "Kyle", pass: "Hunter2" });
});
