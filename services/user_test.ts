import {
  assertRejects,
  assertStrictEquals,
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
  await assertRejects(() => result, Error, "not implemented");
  await assertRejects(
    () => userService.getAuthenticated("Kyle", "hunter2"),
    ServerError,
    "not implemented",
  );
});
