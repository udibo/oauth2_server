import { OAuth2Error } from "./errors.ts";
import { Token } from "./models/token.ts";

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

export interface OAuth2State {
  token?: Token;
  // deno-lint-ignore no-explicit-any
  [key: string]: any;
}

export interface OAuth2Context {
  request: OAuth2Request;
  response: OAuth2Response;
  state: OAuth2State;
}

export interface ErrorBody {
  error: string;
  "error_description"?: string;
  "error_uri"?: string;
}

export type ErrorHandler = (
  response: OAuth2Response,
  error: OAuth2Error,
  realm?: string,
) => void | Promise<void>;

export const errorHandler: ErrorHandler = (
  response: OAuth2Response,
  error: OAuth2Error,
  realm?: string,
) => {
  response.status = error.status ?? 500;
  if (error.status === 401) {
    response.headers.set(
      "WWW-Authenticate",
      `Basic realm="${realm ?? "Service"}"`,
    );
  }
  const body: ErrorBody = {
    error: error.code ?? "server_error",
  };
  if (error.message) body.error_description = error.message;
  if (error.uri) body.error_uri = error.uri;
  response.body = body;
};

const BEARER_TOKEN = /^ *(?:[Bb][Ee][Aa][Rr][Ee][Rr]) +([\w-.~+/]+=*) *$/;

export async function getAccessToken(
  request: OAuth2Request,
): Promise<string | null> {
  let accessToken: string | null = null;

  const authorization = request.headers.get("authorization");
  if (authorization) {
    const match = BEARER_TOKEN.exec(authorization);
    if (match) accessToken = match[1];
  }

  if (!accessToken) {
    const contentType: string | null = request.headers.get(
      "content-type",
    );
    if (
      request.method === "POST" &&
      contentType === "application/x-www-form-urlencoded"
    ) {
      const body: URLSearchParams = await request.body!;
      accessToken = body.get("access_token");
    }
  }

  return accessToken;
}

export type Authenticator = (context: OAuth2Context) => Promise<Token | null>;
