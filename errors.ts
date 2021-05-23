export interface OAuth2ErrorOptions {
  /** The name of the error. */
  name?: string;
  /** An HTTP response status code. */
  status?: number;
  /** A description of the error. */
  message?: string;
  /** An ASCII error code. */
  code?: string;
  /** A URI identifying a human readable web page with information about the error. */
  uri?: string;
}

export interface MessageOrOptions {
  message?: string;
  options?: OAuth2ErrorOptions;
}

export function getMessageOrOptions(
  messageOrOptions?: string | OAuth2ErrorOptions,
): MessageOrOptions {
  let message: string | undefined;
  let options: OAuth2ErrorOptions | undefined;
  if (messageOrOptions) {
    if (typeof messageOrOptions === "string") {
      message = messageOrOptions;
    } else {
      options = messageOrOptions;
    }
  }
  return { message, options };
}

export abstract class OAuth2Error extends Error {
  /** An HTTP response status code. */
  status?: number;
  /** An ASCII error code. */
  code?: string;
  /** A URI identifying a human readable web page with information about the error. */
  uri?: string;

  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super(message ?? options?.message);
    const { name, code, status, uri }: OAuth2ErrorOptions = options ?? {};
    this.name = name ?? "OAuth2Error";
    this.status = status ?? 500;
    if (code) this.code = code;
    if (uri) this.uri = uri;
  }
}

/**
 * The request is missing a required parameter, includes an unsupported parameter value,
 * repeats a parameter, includes multiple credentials, utilizes more than one mechanism
 * for authenticating the client, or is otherwise malformed.
 */
export class InvalidRequest extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "InvalidRequest",
      code: "invalid_request",
      status: 400,
      ...options,
    });
  }
}

/** Client authentication failed. */
export class InvalidClient extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "InvalidClient",
      code: "invalid_client",
      status: 401,
      ...options,
    });
  }
}

/**
 * The provided authorization grant or refresh token is invalid, expired, revoked,
 * does not match the redirection URI used in the authorization request, or was issued to another client.
 */
export class InvalidGrant extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "InvalidGrant",
      code: "invalid_grant",
      status: 400,
      ...options,
    });
  }
}

/** The authenticated client is not authorized to use this authorization grant type. */
export class UnauthorizedClient extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "UnauthorizedClient",
      code: "unauthorized_client",
      status: 401,
      ...options,
    });
  }
}

/** The authorization grant type is not supported by the authorization server. */
export class UnsupportedGrantType extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "UnsupportedGrantType",
      code: "unsupported_grant_type",
      status: 400,
      ...options,
    });
  }
}

/** The resource owner or authorization server denied the request. */
export class AccessDenied extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "AccessDenied",
      code: "access_denied",
      status: 401,
      ...options,
    });
  }
}

/**
 * The authorization server does not support obtaining
 * an authorization code using this method.
 */
export class UnsupportedResponseType extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "UnsupportedResponseType",
      code: "unsupported_response_type",
      status: 400,
      ...options,
    });
  }
}

/** The requested scope is invalid, unknown, or malformed. */
export class InvalidScope extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "InvalidScope",
      code: "invalid_scope",
      status: 400,
      ...options,
    });
  }
}

/**
 * The authorization server encountered an unexpected condition that
 * prevented it from fulfilling the request.
 */
export class ServerError extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "ServerError",
      code: "server_error",
      status: 500,
      ...options,
    });
  }
}

/**
 * The authorization server is currently unable to handle the request due to
 * a temporary overloading or maintenance of the server.
 */
export class TemporarilyUnavailable extends OAuth2Error {
  constructor(message?: string);
  constructor(options?: OAuth2ErrorOptions);
  constructor(messageOrOptions?: string | OAuth2ErrorOptions) {
    const { message, options } = getMessageOrOptions(messageOrOptions);
    super({
      message,
      name: "TemporarilyUnavailable",
      code: "temporarily_unavailable",
      status: 503,
      ...options,
    });
  }
}
