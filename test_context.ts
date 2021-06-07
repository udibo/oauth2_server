import { OAuth2Request, OAuth2Response } from "./context.ts";

export function fakeTokenRequest(
  body?: string | URLSearchParams | string[][] | Record<string, string>,
): OAuth2Request {
  const params: URLSearchParams | undefined = typeof body === "undefined"
    ? undefined
    : new URLSearchParams(body);
  const request: OAuth2Request = {
    url: new URL("https://example.com/token"),
    headers: new Headers(),
    method: "POST",
    hasBody: !!params,
  };
  request.headers.set("authorization", `basic ${btoa("1:")}`);
  request.headers.set("Content-Type", "application/x-www-form-urlencoded");
  if (params) request.body = Promise.resolve(params);
  return request;
}

class FakeTokenResponse implements OAuth2Response {
  headers: Headers;

  constructor() {
    this.headers = new Headers();
  }

  redirect() {}
}

export function fakeTokenResponse(): OAuth2Response {
  return new FakeTokenResponse();
}
