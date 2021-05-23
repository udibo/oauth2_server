export interface OAuth2Request {
  url: URL;
  headers: Headers;
  method: string;
  hasBody: boolean;
  body?: Promise<URLSearchParams>;
}

export interface OAuth2Response {
  status?: number;
  headers: Headers;
  // deno-lint-ignore no-explicit-any
  body?: any | Promise<any> | (() => (any | Promise<any>));
  redirect(url: string | URL): void;
}

export interface Context {
  request: OAuth2Request;
  response: OAuth2Response;
}
