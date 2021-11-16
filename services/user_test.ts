import {
  assertEquals,
  assertNotEquals,
  assertRejects,
  assertStrictEquals,
  test,
  TestSuite,
} from "../test_deps.ts";
import { ServerError } from "../errors.ts";
import { UserService } from "./test_services.ts";
import { generateSalt, hashPassword } from "./user.ts";

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

test("generateSalt", () => {
  const salts = [
    generateSalt(),
    generateSalt(),
  ];
  assertNotEquals(salts[0], salts[1]);
  assertEquals(salts[0].length, 32);
  assertEquals(salts[1].length, 32);
});

test("hashPassword", async () => {
  const passwords = ["hunter1", "hunter2"];
  const salts = [
    "ba387b742a3e1917d084d067e3a65b63",
    "f6f979051fadff4f12a87c99206cab14",
  ];
  const result = hashPassword(passwords[0], salts[0]);
  assertStrictEquals(Promise.resolve(result), result);
  assertEquals(
    await result,
    "ef43ab3f512a1187e64f7595d1d0b5861f88498dc15362e27ff26b8bb23dd131",
  );
  assertEquals(
    await hashPassword(passwords[0], salts[0]),
    "ef43ab3f512a1187e64f7595d1d0b5861f88498dc15362e27ff26b8bb23dd131",
  );
  assertEquals(
    await hashPassword(passwords[0], salts[1]),
    "76b80d04d5d3de41c912378f05fab2570435855ea665da0710fc98efe62d4545",
  );

  assertEquals(
    await hashPassword(passwords[1], salts[0]),
    "02d3216c2cf31e04112c92955fc8352f2713905e8184b6375481b1d01a5358eb",
  );
  assertEquals(
    await hashPassword(passwords[1], salts[1]),
    "331b0dac7b339cf16de6be2166cc469b2e72b5088204b1f381e54dc94d92cc7c",
  );
});
