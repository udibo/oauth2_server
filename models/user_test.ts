import { User, UserService, UserServiceInterface } from "./user.ts";
import { test, TestSuite } from "../deps/udibo/test_suite/mod.ts";
import {
  assertStrictEquals,
  assertThrowsAsync,
} from "../deps/std/testing/asserts.ts";

const userService: UserServiceInterface = new UserService();

const userServiceTests: TestSuite<void> = new TestSuite({
  name: "UserService",
});

test(userServiceTests, "getUser not implemented", async () => {
  const result: Promise<User | void> = userService.get("Kyle", "hunter2");
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(() => result, Error, "not implemented");
  await assertThrowsAsync(
    () => userService.get("Kyle", "hunter2"),
    Error,
    "not implemented",
  );
});
