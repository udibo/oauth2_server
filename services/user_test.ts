import {
  assertEquals,
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

test(userServiceTests, "hashPassword", async () => {
  const result = userService.hashPassword("hunter1");
  assertStrictEquals(Promise.resolve(result), result);
  assertEquals(
    await result,
    "73660a4f7bbfb98b3e04cd38b257f69b017fbb52d5d864a59459cc9e40c92e6a",
  );
  assertEquals(
    await userService.hashPassword("hunter2"),
    "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7",
  );

  assertEquals(
    await userService.hashPassword("hunter1", "salt1"),
    "4e3cff67fb50b608d58046330a2daea4c6c97e7b97b8ed8095bf95496fb85e61",
  );
  assertEquals(
    await userService.hashPassword("hunter2", "salt1"),
    "551127e9557988f8c6752c1776bbe77b0ab4415f7f3e1f0b90dd72bfc23076d6",
  );
  assertEquals(
    await userService.hashPassword("hunter1", "salt2"),
    "77b5f0f8e2d3c93fdb73ef0ea0a727ff86321b3585fdcd38c26bd60d376b6c1e",
  );
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
