import { decodeBase64url } from "./deps.ts";
import { challengeMethods, generateCodeVerifier } from "./pkce.ts";
import { assertEquals, describe, it } from "./test_deps.ts";

const pkceTests = describe("PKCE");

// https://datatracker.ietf.org/doc/html/rfc7636#appendix-B
it(pkceTests, "S256 challenge method", async () => {
  const { S256 } = challengeMethods;
  assertEquals(
    await S256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  );
});

it(pkceTests, "generateCodeVerifier", () => {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(generateCodeVerifier());
  assertEquals(encoded.length, 43);
  const decoded = decodeBase64url(generateCodeVerifier());
  assertEquals(decoded.length, 32);
});
