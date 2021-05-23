import { camelCase, snakeCase } from "./common.ts";
import { test, TestSuite } from "./deps/udibo/test_suite/mod.ts";
import { assertStrictEquals } from "./deps/std/testing/asserts.ts";

const commonTests: TestSuite<void> = new TestSuite({
  name: "common",
});

test(commonTests, "camelCase", () => {
  assertStrictEquals(camelCase("a_b_c"), "aBC");
  assertStrictEquals(camelCase("A-B-C"), "aBC");
  assertStrictEquals(camelCase("two_words"), "twoWords");
  assertStrictEquals(camelCase("TWO-WORDS"), "twoWords");
});

test(commonTests, "snakeCase", () => {
  assertStrictEquals(snakeCase("aBC"), "a_b_c");
  assertStrictEquals(snakeCase("ABC"), "a_b_c");
  assertStrictEquals(snakeCase("twoWords"), "two_words");
  assertStrictEquals(snakeCase("TwoWords"), "two_words");
});
