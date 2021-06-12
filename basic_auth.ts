import { InvalidClient } from "./errors.ts";

const CREDENTIALS = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([\w-.~+/]+=*) *$/;
const NAME_PASS = /^([^:]+):(.*)$/;

export interface BasicAuth {
  name: string;
  pass: string;
}

export function parseBasicAuth(authorization: string | null): BasicAuth {
  if (!authorization) {
    throw new InvalidClient("authorization header required");
  }
  let match = CREDENTIALS.exec(authorization);
  if (!match) {
    throw new InvalidClient("unsupported authorization header");
  }
  let value: string;
  try {
    value = atob(match[1]);
  } catch {
    throw new InvalidClient(
      "authorization header is not correctly encoded",
    );
  }
  match = NAME_PASS.exec(value);
  if (!match) {
    throw new InvalidClient("authorization header is malformed");
  }
  return {
    name: match[1],
    pass: match[2],
  };
}
