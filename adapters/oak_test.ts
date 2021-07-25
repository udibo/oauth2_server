import {
  assertEquals,
  assertSpyCall,
  assertSpyCalls,
  assertStrictEquals,
  Spy,
  spy,
  test,
  TestSuite,
} from "../test_deps.ts";
import { BodyForm, Request, Response } from "./oak_deps.ts";
import { OakOAuth2Request, OakOAuth2Response } from "./oak.ts";

const requestTests = new TestSuite({ name: "OakOAuth2Request" });

test(requestTests, "get", () => {
  const original: Request = {
    url: new URL("https://example.com/resource/1"),
    method: "GET",
    headers: new Headers({authorization:"bearer 123"}),
    hasBody: false,
  } as Request;
  const wrapped: OakOAuth2Request = new OakOAuth2Request(original);
  assertStrictEquals(wrapped.url, original.url);
  assertStrictEquals(wrapped.method, original.method);
  assertStrictEquals(wrapped.headers, original.headers);
  assertStrictEquals(wrapped.hasBody, original.hasBody);
  assertStrictEquals(wrapped.body, undefined);
});

test(requestTests, "post", async () => {
  const expectedBody: URLSearchParams = new URLSearchParams({
    grant_type: "client_credentials",
  });
  const original: Request = {
    url: new URL("https://example.com/token"),
    method: "POST",
    headers: new Headers({authorization:`basic ${btoa("1:")}`}),
    hasBody: true,
    body: (): BodyForm => ({
      type: "form",
      value: Promise.resolve(expectedBody),
    }),
  } as Request;
  const wrapped: OakOAuth2Request = new OakOAuth2Request(original);
  assertStrictEquals(wrapped.url, original.url);
  assertStrictEquals(wrapped.method, original.method);
  assertStrictEquals(wrapped.headers, original.headers);
  assertStrictEquals(wrapped.hasBody, original.hasBody);
  assertStrictEquals(Promise.resolve(wrapped.body), wrapped.body);
  assertStrictEquals(await wrapped.body, expectedBody);
});

test(requestTests, "post with sync body error", () => {
  const original: Request = {
    url: new URL("https://example.com/token"),
    method: "POST",
    headers: new Headers({authorization:`basic ${btoa("1:")}`}),
    hasBody: true,
    body: (): BodyForm => {
      throw new Error("failed");
    },
  } as Request;
  const wrapped: OakOAuth2Request = new OakOAuth2Request(original);
  assertStrictEquals(wrapped.url, original.url);
  assertStrictEquals(wrapped.method, original.method);
  assertStrictEquals(wrapped.headers, original.headers);
  assertStrictEquals(wrapped.hasBody, original.hasBody);
  assertStrictEquals(wrapped.body, undefined);
});

test(requestTests, "post with async body error", async () => {
  const original: Request = {
    url: new URL("https://example.com/token"),
    method: "POST",
    headers: new Headers({authorization:`basic ${btoa("1:")}`}),
    hasBody: true,
    body: (): BodyForm => ({
      type: "form",
      value: Promise.reject(new Error("failed")),
    }),
  } as Request;
  const wrapped: OakOAuth2Request = new OakOAuth2Request(original);
  assertStrictEquals(wrapped.url, original.url);
  assertStrictEquals(wrapped.method, original.method);
  assertStrictEquals(wrapped.headers, original.headers);
  assertStrictEquals(wrapped.hasBody, original.hasBody);
  assertStrictEquals(Promise.resolve(wrapped.body), wrapped.body);
  assertEquals(await wrapped.body, new URLSearchParams());
});

const responseTests = new TestSuite({ name: "OakOAuth2Response" });

test(responseTests, "redirect", () => {
  const original: Response = {
    redirect: (_url: string | URL) => undefined,
  } as Response;
  const redirect: Spy<Response> = spy(original, "redirect");
  const wrapped: OakOAuth2Response = new OakOAuth2Response(original);
  assertSpyCalls(redirect, 0);
  wrapped.redirect("https://example.com");
  assertSpyCall(redirect, 0, {
    self: original,
    args: ["https://example.com"],
  })
  assertSpyCalls(redirect, 1);
  const url: URL = new URL("https://example.com");
  wrapped.redirect(url);
  assertSpyCall(redirect, 1, {
    self: original,
    args: [url],
  })
  assertSpyCalls(redirect, 2);
})

test(responseTests, "without body", () => {
  const headers: Headers = new Headers({"Content-Type": `application/json`});
  const original: Response = {
    status: 404,
    headers,
  } as Response;
  const wrapped: OakOAuth2Response = new OakOAuth2Response(original);
  assertStrictEquals(wrapped.status, 404);
  assertStrictEquals(wrapped.headers, headers);
  assertStrictEquals(wrapped.body, undefined);
  assertStrictEquals(original.status, 404);
  assertStrictEquals(original.headers, headers);
  assertStrictEquals(original.body, undefined);

  wrapped.status = 200;
  wrapped.headers.set("Cache-Control", "no-store");
  assertStrictEquals(wrapped.status, 200);
  assertStrictEquals(wrapped.headers, headers);
  assertStrictEquals(wrapped.body, undefined);
  assertStrictEquals(original.status, 200)
  assertStrictEquals(original.headers, headers);
  assertStrictEquals(original.body, undefined);
});

test(responseTests, "with sync body value", () => {
  const headers: Headers = new Headers({"Content-Type": `application/json`});
  const original: Response = {
    status: 200,
    headers,
  } as Response;
  const wrapped: OakOAuth2Response = new OakOAuth2Response(original);
  const body = {x:2, y:3};
  wrapped.body = body;
  assertStrictEquals(wrapped.status, 200);
  assertStrictEquals(wrapped.headers, headers);
  assertStrictEquals(wrapped.body, body);
  assertStrictEquals(original.status, 200)
  assertStrictEquals(original.headers, headers);
  assertStrictEquals(original.body, body);
});

test(responseTests, "with async body value", () => {
  const headers: Headers = new Headers({"Content-Type": `application/json`});
  const original: Response = {
    status: 200,
    headers,
  } as Response;
  const wrapped: OakOAuth2Response = new OakOAuth2Response(original);
  const body = Promise.resolve({x:2, y:3});
  wrapped.body = body;
  assertStrictEquals(wrapped.status, 200);
  assertStrictEquals(wrapped.headers, headers);
  assertStrictEquals(wrapped.body, body);
  assertStrictEquals(original.status, 200)
  assertStrictEquals(original.headers, headers);
  assertStrictEquals(typeof original.body, "function");
  const result = (original.body as CallableFunction)();
  assertStrictEquals(result, body);
});

test(responseTests, "with body function", () => {
  const headers: Headers = new Headers({"Content-Type": `application/json`});
  const original: Response = {
    status: 200,
    headers,
  } as Response;
  const wrapped: OakOAuth2Response = new OakOAuth2Response(original);
  const bodyValue = {x:2, y:3};
  const body = () => bodyValue
  wrapped.body = body;
  assertStrictEquals(wrapped.status, 200);
  assertStrictEquals(wrapped.headers, headers);
  assertStrictEquals(wrapped.body, body);
  assertStrictEquals(original.status, 200)
  assertStrictEquals(original.headers, headers);
  assertStrictEquals(original.body, body);
  const result = (original.body as CallableFunction)();
  assertStrictEquals(result, bodyValue);
});
