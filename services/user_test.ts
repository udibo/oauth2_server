import {
  assertStrictEquals,
  assertThrowsAsync,
  test,
  TestSuite,
} from "../test_deps.ts";
import { ServerError } from "../errors.ts";
import { UserService } from "./test_services.ts";

const userService = new UserService();

const userServiceTests: TestSuite<void> = new TestSuite({
  name: "UserService",
});

test(userServiceTests, "getAuthenticated not implemented", async () => {
  const result = userService.getAuthenticated(
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
