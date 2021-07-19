import {
  errorHandler,
  getAccessToken,
  OAuth2Request,
  OAuth2Response,
} from "./context.ts";
import { InvalidClient, InvalidGrant } from "./errors.ts";
import { fakeResourceRequest, fakeResponse } from "./test_context.ts";
import { assertEquals, Spy, spy, test, TestSuite } from "./test_deps.ts";

const contextTests: TestSuite<void> = new TestSuite({ name: "context" });

const errorHandlerTests: TestSuite<void> = new TestSuite({
  name: "errorHandler",
  suite: contextTests,
});

test(errorHandlerTests, "OAuth2Error without optional properties", async () => {
  const response: OAuth2Response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await errorHandler(
      response,
      new InvalidGrant(),
    ),
    undefined,
  );
  assertEquals(response.status, 400);
  assertEquals([...response.headers.entries()], []);
  assertEquals(response.body, {
    error: "invalid_grant",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

test(errorHandlerTests, "OAuth2Error with optional properties", async () => {
  const response: OAuth2Response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await errorHandler(
      response,
      new InvalidGrant({
        message: "invalid refresh_token",
        uri: "https://example.com/",
      }),
    ),
    undefined,
  );
  assertEquals(response.status, 400);
  assertEquals([...response.headers.entries()], []);
  assertEquals(response.body, {
    error: "invalid_grant",
    error_description: "invalid refresh_token",
    error_uri: "https://example.com/",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

test(errorHandlerTests, "OAuth2Error with 401 status", async () => {
  const response: OAuth2Response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await errorHandler(
      response,
      new InvalidClient("client authentication failed"),
    ),
    undefined,
  );
  assertEquals(response.status, 401);
  assertEquals([...response.headers.entries()], [
    ["www-authenticate", 'Basic realm="Service"'],
  ]);
  assertEquals(response.body, {
    error: "invalid_client",
    error_description: "client authentication failed",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

test(errorHandlerTests, "Error", async () => {
  const response: OAuth2Response = fakeResponse();
  const redirectSpy: Spy<OAuth2Response> = spy(response, "redirect");
  assertEquals(
    await errorHandler(
      response,
      new Error("unknown"),
    ),
    undefined,
  );
  assertEquals(response.status, 500);
  assertEquals([...response.headers.entries()], []);
  assertEquals(response.body, {
    error: "server_error",
    error_description: "unknown",
  });
  assertEquals(redirectSpy.calls.length, 0);
});

const getAccessTokenTests: TestSuite<void> = new TestSuite({
  name: "getAccessToken",
  suite: contextTests,
});

test(getAccessTokenTests, "GET request with no access token", async () => {
  const request: OAuth2Request = fakeResourceRequest("");
  const result = getAccessToken(request);
  assertEquals(Promise.resolve(result), result);
  assertEquals(await result, null);
});

test(
  getAccessTokenTests,
  "GET request with access token in authorization header",
  async () => {
    const request: OAuth2Request = fakeResourceRequest("abc");
    const result = getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);

test(getAccessTokenTests, "POST request with no access token", async () => {
  const request: OAuth2Request = fakeResourceRequest("");
  const result = getAccessToken(request);
  assertEquals(Promise.resolve(result), result);
  assertEquals(await result, null);
});

test(
  getAccessTokenTests,
  "POST request with access token in authorization header",
  async () => {
    const request: OAuth2Request = fakeResourceRequest("abc", {});
    const result = getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);

test(
  getAccessTokenTests,
  "POST request with access token in request body",
  async () => {
    const request: OAuth2Request = fakeResourceRequest("", {
      access_token: "abc",
    });
    const result = getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);

test(
  getAccessTokenTests,
  "POST request with access token in authorization header and body",
  async () => {
    const request: OAuth2Request = fakeResourceRequest("abc", {
      access_token: "def",
    });
    const result = getAccessToken(request);
    assertEquals(Promise.resolve(result), result);
    assertEquals(await result, "abc");
  },
);
