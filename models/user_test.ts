import { User, UserService, UserServiceInterface } from "./user.ts";
import {
  assertStrictEquals,
  assertThrowsAsync,
  test,
  TestSuite,
} from "../test_deps.ts";
import { ServerError } from "../errors.ts";

export class ExampleUserService extends UserService {}

const userService: UserServiceInterface = new ExampleUserService();

const userServiceTests: TestSuite<void> = new TestSuite({
  name: "UserService",
});

test(userServiceTests, "getAuthenticated not implemented", async () => {
  const result: Promise<User | undefined> = userService.getAuthenticated(
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
