import {
  HttpError,
  HttpErrorOptions,
  isHttpError,
  optionsFromArgs,
} from "./deps.ts";

export interface OAuth2ErrorOptions extends HttpErrorOptions {
  /** An ASCII error code. */
  code?: string;
  /** A URI identifying a human readable web page with information about the error. */
  uri?: string;
}

export class OAuth2Error extends HttpError {
  /** An ASCII error code. */
  code: string;
  /** A URI identifying a human readable web page with information about the error. */
  uri?: string;

  constructor(
    status?: number,
    message?: string,
    options?: OAuth2ErrorOptions,
  );
  constructor(status?: number, options?: OAuth2ErrorOptions);
  constructor(message?: string, options?: OAuth2ErrorOptions);
  constructor(options?: OAuth2ErrorOptions);
  constructor(
    statusOrMessageOrOptions?: number | string | OAuth2ErrorOptions,
    messageOrOptions?: string | OAuth2ErrorOptions,
    options?: OAuth2ErrorOptions,
  ) {
    const init: OAuth2ErrorOptions = optionsFromArgs(
      statusOrMessageOrOptions,
      messageOrOptions,
      options,
    );
    super({ name: "OAuth2Error", ...init });
    const { code, uri } = init;
    this.code = code ?? "server_error";
    if (uri) this.uri = uri;
  }
}

export function isOAuth2Error(value: unknown): value is OAuth2Error {
  return isHttpError(value) && typeof (value as OAuth2Error).code === "string";
}

/**
 * The request is missing a required parameter, includes an unsupported parameter value,
 * repeats a parameter, includes multiple credentials, utilizes more than one mechanism
 * for authenticating the client, or is otherwise malformed.
 */
export class InvalidRequestError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "InvalidRequestError",
      code: "invalid_request",
      status: 400,
      cause: options?.cause,
    });
  }
}

/** Client authentication failed. */
export class InvalidClientError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "InvalidClientError",
      code: "invalid_client",
      status: 401,
      cause: options?.cause,
    });
  }
}

/**
 * The provided authorization grant or refresh token is invalid, expired, revoked,
 * does not match the redirection URI used in the authorization request, or was issued to another client.
 */
export class InvalidGrantError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "InvalidGrantError",
      code: "invalid_grant",
      status: 400,
      cause: options?.cause,
    });
  }
}

/** The authenticated client is not authorized to use this authorization grant type. */
export class UnauthorizedClientError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "UnauthorizedClientError",
      code: "unauthorized_client",
      status: 401,
      cause: options?.cause,
    } as OAuth2ErrorOptions);
  }
}

/** The token type is not supported by the authorization server. */
export class UnsupportedTokenTypeError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "UnsupportedTokenTypeError",
      code: "unsupported_token_type",
      status: 400,
      cause: options?.cause,
    });
  }
}

/** The authorization grant type is not supported by the authorization server. */
export class UnsupportedGrantTypeError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "UnsupportedGrantTypeError",
      code: "unsupported_grant_type",
      status: 400,
      cause: options?.cause,
    });
  }
}

/** The resource owner or authorization server denied the request. */
export class AccessDeniedError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "AccessDeniedError",
      code: "access_denied",
      status: 401,
      cause: options?.cause,
    });
  }
}

/**
 * The authorization server does not support obtaining
 * an authorization code using this method.
 */
export class UnsupportedResponseTypeError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "UnsupportedResponseTypeError",
      code: "unsupported_response_type",
      status: 400,
      cause: options?.cause,
    });
  }
}

/** The requested scope is invalid, unknown, or malformed. */
export class InvalidScopeError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "InvalidScopeError",
      code: "invalid_scope",
      status: 400,
      cause: options?.cause,
    });
  }
}

/**
 * The authorization server encountered an unexpected condition that
 * prevented it from fulfilling the request.
 */
export class ServerError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "ServerError",
      code: "server_error",
      status: 500,
      cause: options?.cause,
    });
  }
}

/**
 * The authorization server is currently unable to handle the request due to
 * a temporary overloading or maintenance of the server.
 */
export class TemporarilyUnavailableError extends OAuth2Error {
  constructor(message?: string, options?: ErrorOptions) {
    super({
      message,
      name: "TemporarilyUnavailableError",
      code: "temporarily_unavailable",
      status: 503,
      cause: options?.cause,
    });
  }
}
