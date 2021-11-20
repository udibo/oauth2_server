import { OAuth2Request, OAuth2Response } from "./context.ts";
import { Client } from "./models/client.ts";
import { Scope } from "./models/scope.ts";
import { User } from "./models/user.ts";

export function fakeTokenRequest(
  body?: string | URLSearchParams | string[][] | Record<string, string>,
): OAuth2Request<Client, User, Scope> {
  const params: URLSearchParams | undefined = typeof body === "undefined"
    ? undefined
    : new URLSearchParams(body);
  const request: OAuth2Request<Client, User, Scope> = {
    url: new URL("https://example.com/token"),
    headers: new Headers(),
    method: "POST",
    get body() {
      return Promise.resolve(params ?? new URLSearchParams());
    },
  };
  request.headers.set("authorization", `basic ${btoa("1:")}`);
  if (params) {
    request.headers.set("Content-Type", "application/x-www-form-urlencoded");
  }
  return request;
}

export function fakeResourceRequest(
  bearerToken: string,
  body?: string | URLSearchParams | string[][] | Record<string, string>,
): OAuth2Request<Client, User, Scope> {
  const params: URLSearchParams | undefined = typeof body === "undefined"
    ? undefined
    : new URLSearchParams(body);
  const request: OAuth2Request<Client, User, Scope> = {
    url: new URL("https://example.com/resource/1"),
    headers: new Headers(),
    method: params ? "POST" : "GET",
    get body() {
      return Promise.resolve(params ?? new URLSearchParams());
    },
  };
  if (bearerToken) {
    request.headers.set("authorization", `bearer ${bearerToken}`);
  }
  if (params) {
    request.headers.set("Content-Type", "application/x-www-form-urlencoded");
  }
  return request;
}

export function fakeAuthorizeRequest(
  body?: string | URLSearchParams | string[][] | Record<string, string>,
): OAuth2Request<Client, User, Scope> {
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

  const request: OAuth2Request<Client, User, Scope> = {
    url,
    headers: new Headers(),
    method: bodyParams ? "POST" : "GET",
    get body() {
      return Promise.resolve(bodyParams ?? new URLSearchParams());
    },
  };
  if (bodyParams) {
    request.headers.set("Content-Type", "application/x-www-form-urlencoded");
  }
  return request;
}

class FakeResponse implements OAuth2Response {
  headers: Headers;

  constructor() {
    this.headers = new Headers();
  }

  async redirect(): Promise<void> {
    return await Promise.resolve();
  }
}

export function fakeResponse(): OAuth2Response {
  return new FakeResponse();
}
