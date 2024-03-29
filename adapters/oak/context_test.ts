import {
  assertEquals,
  assertRejects,
  assertSpyCall,
  assertSpyCalls,
  assertStrictEquals,
  describe,
  it,
  Spy,
  spy,
} from "../../test_deps.ts";
import { BodyForm, Context, Request, Response } from "./deps.ts";
import { OakOAuth2Request, OakOAuth2Response } from "./context.ts";

const requestTests = describe("OakOAuth2Request");

it(requestTests, "get", async () => {
  const expectedBody = new URLSearchParams();
  const original: Request = {
    url: new URL("https://example.com/resource/1"),
    method: "GET",
    headers: new Headers({ authorization: "bearer 123" }),
    body: (): BodyForm => ({
      type: "form",
      value: Promise.resolve(expectedBody),
    }),
  } as Request;
  const wrapped = new OakOAuth2Request(
    { request: original } as Context,
  );
  assertStrictEquals(wrapped.url, original.url);
  assertStrictEquals(wrapped.method, original.method);
  assertStrictEquals(wrapped.headers, original.headers);
  assertStrictEquals(Promise.resolve(wrapped.body), wrapped.body);
  assertStrictEquals(await wrapped.body, expectedBody);
});

it(requestTests, "post", async () => {
  const expectedBody: URLSearchParams = new URLSearchParams({
    grant_type: "client_credentials",
  });
  const original: Request = {
    url: new URL("https://example.com/token"),
    method: "POST",
    headers: new Headers({ authorization: `basic ${btoa("1:")}` }),
    body: (): BodyForm => ({
      type: "form",
      value: Promise.resolve(expectedBody),
    }),
  } as Request;
  const wrapped = new OakOAuth2Request(
    { request: original } as Context,
  );
  assertStrictEquals(wrapped.url, original.url);
  assertStrictEquals(wrapped.method, original.method);
  assertStrictEquals(wrapped.headers, original.headers);
  assertStrictEquals(Promise.resolve(wrapped.body), wrapped.body);
  assertStrictEquals(await wrapped.body, expectedBody);
});

it(requestTests, "post with sync body error", async () => {
  const original: Request = {
    url: new URL("https://example.com/token"),
    method: "POST",
    headers: new Headers({ authorization: `basic ${btoa("1:")}` }),
    body: (): BodyForm => {
      throw new Error("failed");
    },
  } as Request;
  const wrapped = new OakOAuth2Request(
    { request: original } as Context,
  );
  assertStrictEquals(wrapped.url, original.url);
  assertStrictEquals(wrapped.method, original.method);
  assertStrictEquals(wrapped.headers, original.headers);
  assertStrictEquals(Promise.resolve(wrapped.body), wrapped.body);
  assertEquals(await wrapped.body, new URLSearchParams());
});

it(requestTests, "post with async body error", async () => {
  const original: Request = {
    url: new URL("https://example.com/token"),
    method: "POST",
    headers: new Headers({ authorization: `basic ${btoa("1:")}` }),
    body: (): BodyForm => ({
      type: "form",
      value: Promise.reject(new Error("failed")),
    }),
  } as Request;
  const wrapped = new OakOAuth2Request(
    { request: original } as Context,
  );
  assertStrictEquals(wrapped.url, original.url);
  assertStrictEquals(wrapped.method, original.method);
  assertStrictEquals(wrapped.headers, original.headers);
  assertStrictEquals(Promise.resolve(wrapped.body), wrapped.body);
  await assertRejects(() => wrapped.body, Error, "failed");
});

const responseTests = describe("OakOAuth2Response");

it(responseTests, "redirect", () => {
  const original: Response = {
    redirect: (_url: string | URL) => undefined,
  } as Response;
  const redirect: Spy<Response> = spy(original, "redirect");
  const wrapped: OakOAuth2Response = new OakOAuth2Response(
    { response: original } as Context,
  );
  assertSpyCalls(redirect, 0);
  wrapped.redirect("https://example.com");
  assertSpyCall(redirect, 0, {
    self: original,
    args: ["https://example.com"],
  });
  assertSpyCalls(redirect, 1);
  const url: URL = new URL("https://example.com");
  wrapped.redirect(url);
  assertSpyCall(redirect, 1, {
    self: original,
    args: [url],
  });
  assertSpyCalls(redirect, 2);
});

it(responseTests, "without body", () => {
  const headers: Headers = new Headers({ "Content-Type": `application/json` });
  const original: Response = {
    status: 404,
    headers,
  } as Response;
  const wrapped: OakOAuth2Response = new OakOAuth2Response(
    { response: original } as Context,
  );
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
  assertStrictEquals(original.status, 200);
  assertStrictEquals(original.headers, headers);
  assertStrictEquals(original.body, undefined);
});

it(responseTests, "with sync body value", () => {
  const headers: Headers = new Headers({ "Content-Type": `application/json` });
  const original: Response = {
    status: 200,
    headers,
  } as Response;
  const wrapped: OakOAuth2Response = new OakOAuth2Response(
    { response: original } as Context,
  );
  const body = { x: 2, y: 3 };
  wrapped.body = body;
  assertStrictEquals(wrapped.status, 200);
  assertStrictEquals(wrapped.headers, headers);
  assertStrictEquals(wrapped.body, body);
  assertStrictEquals(original.status, 200);
  assertStrictEquals(original.headers, headers);
  assertStrictEquals(original.body, body);
});

it(responseTests, "with async body value", () => {
  const headers: Headers = new Headers({ "Content-Type": `application/json` });
  const original: Response = {
    status: 200,
    headers,
  } as Response;
  const wrapped: OakOAuth2Response = new OakOAuth2Response(
    { response: original } as Context,
  );
  const body = Promise.resolve({ x: 2, y: 3 });
  wrapped.body = body;
  assertStrictEquals(wrapped.status, 200);
  assertStrictEquals(wrapped.headers, headers);
  assertStrictEquals(wrapped.body, body);
  assertStrictEquals(original.status, 200);
  assertStrictEquals(original.headers, headers);
  assertStrictEquals(typeof original.body, "function");
  const result = (original.body as CallableFunction)();
  assertStrictEquals(result, body);
});

it(responseTests, "with body function", () => {
  const headers: Headers = new Headers({ "Content-Type": `application/json` });
  const original: Response = {
    status: 200,
    headers,
  } as Response;
  const wrapped: OakOAuth2Response = new OakOAuth2Response(
    { response: original } as Context,
  );
  const bodyValue = { x: 2, y: 3 };
  const body = () => bodyValue;
  wrapped.body = body;
  assertStrictEquals(wrapped.status, 200);
  assertStrictEquals(wrapped.headers, headers);
  assertStrictEquals(wrapped.body, body);
  assertStrictEquals(original.status, 200);
  assertStrictEquals(original.headers, headers);
  assertStrictEquals(original.body, body);
  const result = (original.body as CallableFunction)();
  assertStrictEquals(result, bodyValue);
});
