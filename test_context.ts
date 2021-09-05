import { OAuth2Request, OAuth2Response } from "./context.ts";
import { Scope } from "./models/scope.ts";

export function fakeTokenRequest(
  body?: string | URLSearchParams | string[][] | Record<string, string>,
): OAuth2Request<Scope> {
  const params: URLSearchParams | undefined = typeof body === "undefined"
    ? undefined
    : new URLSearchParams(body);
  const request: OAuth2Request<Scope> = {
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

export function fakeResourceRequest(
  bearerToken: string,
  body?: string | URLSearchParams | string[][] | Record<string, string>,
): OAuth2Request<Scope> {
  const params: URLSearchParams | undefined = typeof body === "undefined"
    ? undefined
    : new URLSearchParams(body);
  const request: OAuth2Request<Scope> = {
    url: new URL("https://example.com/resource/1"),
    headers: new Headers(),
    method: params ? "POST" : "GET",
    hasBody: !!params,
  };
  if (bearerToken) {
    request.headers.set("authorization", `bearer ${bearerToken}`);
  }
  if (params) {
    request.headers.set("Content-Type", "application/x-www-form-urlencoded");
    request.body = Promise.resolve(params);
  }
  return request;
}

export function fakeAuthorizeRequest(
  body?: string | URLSearchParams | string[][] | Record<string, string>,
): OAuth2Request<Scope> {
  const bodyParams: URLSearchParams | undefined = typeof body === "undefined"
    ? undefined
    : new URLSearchParams(body);

  const url = new URL(`https://example.com/authorize`);
  const { searchParams } = url;
  searchParams.set("response_type", "code");
  searchParams.set("client_id", "1");
  searchParams.set("redirect_uri", "https://client.example.com/cb");
  searchParams.set("state", "xyz");
  searchParams.set("scope", "read write");

  const request: OAuth2Request<Scope> = {
    url,
    headers: new Headers(),
    method: bodyParams ? "POST" : "GET",
    hasBody: !!bodyParams,
  };
  if (bodyParams) {
    request.headers.set("Content-Type", "application/x-www-form-urlencoded");
    request.body = Promise.resolve(bodyParams);
  }
  return request;
}

class FakeResponse implements OAuth2Response {
  headers: Headers;

  constructor() {
    this.headers = new Headers();
  }

  redirect(): Promise<void> {
    return Promise.resolve();
  }
}

export function fakeResponse(): OAuth2Response {
  return new FakeResponse();
}
