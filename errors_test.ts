import { assertObjectMatch } from "./deps/std/testing/asserts.ts";
import {
  AccessDenied,
  InvalidClient,
  InvalidGrant,
  InvalidRequest,
  InvalidScope,
  OAuth2Error,
  ServerError,
  TemporarilyUnavailable,
  UnauthorizedClient,
  UnsupportedGrantType,
  UnsupportedResponseType,
} from "./errors.ts";
import { test } from "./deps/udibo/test_suite/mod.ts";

test("OAuth2Error", () => {
  class CustomError extends OAuth2Error {}
  assertObjectMatch(new CustomError(), {
    name: "OAuth2Error",
    status: 500,
    code: undefined,
    uri: undefined,
  });
  assertObjectMatch(new CustomError("failed"), {
    name: "OAuth2Error",
    message: "failed",
    status: 500,
    code: undefined,
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

test("InvalidRequest", () => {
  assertObjectMatch(new InvalidRequest(), {
    name: "InvalidRequest",
    status: 400,
    code: "invalid_request",
    uri: undefined,
  });
  assertObjectMatch(new InvalidRequest("failed"), {
    name: "InvalidRequest",
    message: "failed",
    status: 400,
    code: "invalid_request",
    uri: undefined,
  });
  assertObjectMatch(
    new InvalidRequest({
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

test("InvalidClient", () => {
  assertObjectMatch(new InvalidClient(), {
    name: "InvalidClient",
    status: 401,
    code: "invalid_client",
    uri: undefined,
  });
  assertObjectMatch(new InvalidClient("failed"), {
    name: "InvalidClient",
    message: "failed",
    status: 401,
    code: "invalid_client",
    uri: undefined,
  });
  assertObjectMatch(
    new InvalidClient({
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

test("InvalidGrant", () => {
  assertObjectMatch(new InvalidGrant(), {
    name: "InvalidGrant",
    status: 400,
    code: "invalid_grant",
    uri: undefined,
  });
  assertObjectMatch(new InvalidGrant("failed"), {
    name: "InvalidGrant",
    message: "failed",
    status: 400,
    code: "invalid_grant",
    uri: undefined,
  });
  assertObjectMatch(
    new InvalidGrant({
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

test("UnauthorizedClient", () => {
  assertObjectMatch(new UnauthorizedClient(), {
    name: "UnauthorizedClient",
    status: 401,
    code: "unauthorized_client",
    uri: undefined,
  });
  assertObjectMatch(new UnauthorizedClient("failed"), {
    name: "UnauthorizedClient",
    message: "failed",
    status: 401,
    code: "unauthorized_client",
    uri: undefined,
  });
  assertObjectMatch(
    new UnauthorizedClient({
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

test("UnsupportedGrantType", () => {
  assertObjectMatch(new UnsupportedGrantType(), {
    name: "UnsupportedGrantType",
    status: 400,
    code: "unsupported_grant_type",
    uri: undefined,
  });
  assertObjectMatch(new UnsupportedGrantType("failed"), {
    name: "UnsupportedGrantType",
    message: "failed",
    status: 400,
    code: "unsupported_grant_type",
    uri: undefined,
  });
  assertObjectMatch(
    new UnsupportedGrantType({
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

test("AccessDenied", () => {
  assertObjectMatch(new AccessDenied(), {
    name: "AccessDenied",
    status: 401,
    code: "access_denied",
    uri: undefined,
  });
  assertObjectMatch(new AccessDenied("failed"), {
    name: "AccessDenied",
    message: "failed",
    status: 401,
    code: "access_denied",
    uri: undefined,
  });
  assertObjectMatch(
    new AccessDenied({
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

test("UnsupportedResponseType", () => {
  assertObjectMatch(new UnsupportedResponseType(), {
    name: "UnsupportedResponseType",
    status: 400,
    code: "unsupported_response_type",
    uri: undefined,
  });
  assertObjectMatch(new UnsupportedResponseType("failed"), {
    name: "UnsupportedResponseType",
    message: "failed",
    status: 400,
    code: "unsupported_response_type",
    uri: undefined,
  });
  assertObjectMatch(
    new UnsupportedResponseType({
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

test("InvalidScope", () => {
  assertObjectMatch(new InvalidScope(), {
    name: "InvalidScope",
    status: 400,
    code: "invalid_scope",
    uri: undefined,
  });
  assertObjectMatch(new InvalidScope("failed"), {
    name: "InvalidScope",
    message: "failed",
    status: 400,
    code: "invalid_scope",
    uri: undefined,
  });
  assertObjectMatch(
    new InvalidScope({
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

test("ServerError", () => {
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
  assertObjectMatch(
    new ServerError({
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

test("TemporarilyUnavailable", () => {
  assertObjectMatch(new TemporarilyUnavailable(), {
    name: "TemporarilyUnavailable",
    status: 503,
    code: "temporarily_unavailable",
    uri: undefined,
  });
  assertObjectMatch(new TemporarilyUnavailable("failed"), {
    name: "TemporarilyUnavailable",
    message: "failed",
    status: 503,
    code: "temporarily_unavailable",
    uri: undefined,
  });
  assertObjectMatch(
    new TemporarilyUnavailable({
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
