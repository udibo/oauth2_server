import { User, UserService, UserServiceInterface } from "./user.ts";
import { test, TestSuite } from "../deps/udibo/test_suite/mod.ts";
import {
  assertStrictEquals,
  assertThrowsAsync,
} from "../deps/std/testing/asserts.ts";
import { ServerError } from "../errors.ts";

class ExampleUserService extends UserService {}

const userService: UserServiceInterface = new ExampleUserService();

const userServiceTests: TestSuite<void> = new TestSuite({
  name: "UserService",
});

test(userServiceTests, "getAuthenticated not implemented", async () => {
  const result: Promise<User | void> = userService.getAuthenticated(
    "Kyle",
    "hunter2",
  );
  assertStrictEquals(Promise.resolve(result), result);
  await assertThrowsAsync(() => result, Error, "not implemented");
  await assertThrowsAsync(
    () => userService.getAuthenticated("Kyle", "hunter2"),
    ServerError,
    "not implemented",
  );
});
