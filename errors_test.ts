import { assertEquals, assertObjectMatch, it } from "./test_deps.ts";
import {
  AccessDeniedError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  OAuth2Error,
  ServerError,
  TemporarilyUnavailableError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
} from "./errors.ts";

it("OAuth2Error", () => {
  class CustomError extends OAuth2Error {}
  assertObjectMatch(new CustomError(), {
    name: "OAuth2Error",
    status: 500,
    code: "server_error",
    uri: undefined,
  });
  assertObjectMatch(new CustomError("failed"), {
    name: "OAuth2Error",
    message: "failed",
    status: 500,
    code: "server_error",
    uri: undefined,
  });
  assertObjectMatch(
    new CustomError({
      name: "CustomError",
      message: "failed",
      code: "custom_error",
      status: 418,
      uri: "https://example.com",
    }),
    {
      name: "CustomError",
      message: "failed",
      status: 418,
      code: "custom_error",
      uri: "https://example.com",
    },
  );
});

it("InvalidRequestError", () => {
  assertObjectMatch(new InvalidRequestError(), {
    name: "InvalidRequestError",
    status: 400,
    code: "invalid_request",
    uri: undefined,
  });
  assertObjectMatch(new InvalidRequestError("failed"), {
    name: "InvalidRequestError",
    message: "failed",
    status: 400,
    code: "invalid_request",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new InvalidRequestError("failed", { cause });
  assertObjectMatch(error, {
    name: "InvalidRequestError",
    message: "failed",
    status: 400,
    code: "invalid_request",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});

it("InvalidClientError", () => {
  assertObjectMatch(new InvalidClientError(), {
    name: "InvalidClientError",
    status: 401,
    code: "invalid_client",
    uri: undefined,
  });
  assertObjectMatch(new InvalidClientError("failed"), {
    name: "InvalidClientError",
    message: "failed",
    status: 401,
    code: "invalid_client",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new InvalidClientError("failed", { cause });
  assertObjectMatch(error, {
    name: "InvalidClientError",
    message: "failed",
    status: 401,
    code: "invalid_client",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});

it("InvalidGrantError", () => {
  assertObjectMatch(new InvalidGrantError(), {
    name: "InvalidGrantError",
    status: 400,
    code: "invalid_grant",
    uri: undefined,
  });
  assertObjectMatch(new InvalidGrantError("failed"), {
    name: "InvalidGrantError",
    message: "failed",
    status: 400,
    code: "invalid_grant",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new InvalidGrantError("failed", { cause });
  assertObjectMatch(error, {
    name: "InvalidGrantError",
    message: "failed",
    status: 400,
    code: "invalid_grant",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});

it("UnauthorizedClientError", () => {
  assertObjectMatch(new UnauthorizedClientError(), {
    name: "UnauthorizedClientError",
    status: 401,
    code: "unauthorized_client",
    uri: undefined,
  });
  assertObjectMatch(new UnauthorizedClientError("failed"), {
    name: "UnauthorizedClientError",
    message: "failed",
    status: 401,
    code: "unauthorized_client",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new UnauthorizedClientError("failed", { cause });
  assertObjectMatch(error, {
    name: "UnauthorizedClientError",
    message: "failed",
    status: 401,
    code: "unauthorized_client",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});

it("UnsupportedGrantTypeError", () => {
  assertObjectMatch(new UnsupportedGrantTypeError(), {
    name: "UnsupportedGrantTypeError",
    status: 400,
    code: "unsupported_grant_type",
    uri: undefined,
  });
  assertObjectMatch(new UnsupportedGrantTypeError("failed"), {
    name: "UnsupportedGrantTypeError",
    message: "failed",
    status: 400,
    code: "unsupported_grant_type",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new UnsupportedGrantTypeError("failed", { cause });
  assertObjectMatch(error, {
    name: "UnsupportedGrantTypeError",
    message: "failed",
    status: 400,
    code: "unsupported_grant_type",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});

it("AccessDeniedError", () => {
  assertObjectMatch(new AccessDeniedError(), {
    name: "AccessDeniedError",
    status: 401,
    code: "access_denied",
    uri: undefined,
  });
  assertObjectMatch(new AccessDeniedError("failed"), {
    name: "AccessDeniedError",
    message: "failed",
    status: 401,
    code: "access_denied",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new AccessDeniedError("failed", { cause });
  assertObjectMatch(error, {
    name: "AccessDeniedError",
    message: "failed",
    status: 401,
    code: "access_denied",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});

it("UnsupportedResponseTypeError", () => {
  assertObjectMatch(new UnsupportedResponseTypeError(), {
    name: "UnsupportedResponseTypeError",
    status: 400,
    code: "unsupported_response_type",
    uri: undefined,
  });
  assertObjectMatch(new UnsupportedResponseTypeError("failed"), {
    name: "UnsupportedResponseTypeError",
    message: "failed",
    status: 400,
    code: "unsupported_response_type",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new UnsupportedResponseTypeError("failed", { cause });
  assertObjectMatch(error, {
    name: "UnsupportedResponseTypeError",
    message: "failed",
    status: 400,
    code: "unsupported_response_type",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});

it("InvalidScopeError", () => {
  assertObjectMatch(new InvalidScopeError(), {
    name: "InvalidScopeError",
    status: 400,
    code: "invalid_scope",
    uri: undefined,
  });
  assertObjectMatch(new InvalidScopeError("failed"), {
    name: "InvalidScopeError",
    message: "failed",
    status: 400,
    code: "invalid_scope",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new InvalidScopeError("failed", { cause });
  assertObjectMatch(error, {
    name: "InvalidScopeError",
    message: "failed",
    status: 400,
    code: "invalid_scope",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});

it("ServerError", () => {
  assertObjectMatch(new ServerError(), {
    name: "ServerError",
    status: 500,
    code: "server_error",
    uri: undefined,
  });
  assertObjectMatch(new ServerError("failed"), {
    name: "ServerError",
    message: "failed",
    status: 500,
    code: "server_error",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new ServerError("failed", { cause });
  assertObjectMatch(error, {
    name: "ServerError",
    message: "failed",
    status: 500,
    code: "server_error",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});

it("TemporarilyUnavailableError", () => {
  assertObjectMatch(new TemporarilyUnavailableError(), {
    name: "TemporarilyUnavailableError",
    status: 503,
    code: "temporarily_unavailable",
    uri: undefined,
  });
  assertObjectMatch(new TemporarilyUnavailableError("failed"), {
    name: "TemporarilyUnavailableError",
    message: "failed",
    status: 503,
    code: "temporarily_unavailable",
    uri: undefined,
  });
  const cause = new Error("something went wrong");
  const error = new TemporarilyUnavailableError("failed", { cause });
  assertObjectMatch(error, {
    name: "TemporarilyUnavailableError",
    message: "failed",
    status: 503,
    code: "temporarily_unavailable",
    uri: undefined,
  });
  assertEquals(error.cause, cause);
});
