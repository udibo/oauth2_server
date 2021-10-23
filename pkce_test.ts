import { decodeBase64url } from "./deps.ts";
import { challengeMethods, generateCodeVerifier } from "./pkce.ts";
import { assertEquals, test, TestSuite } from "./test_deps.ts";

const pkceTests: TestSuite<void> = new TestSuite({ name: "PKCE" });

// https://datatracker.ietf.org/doc/html/rfc7636#appendix-B
test(pkceTests, "S256 challenge method", async () => {
  const { S256 } = challengeMethods;
  assertEquals(
    await S256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  );
});

test(pkceTests, "generateCodeVerifier", () => {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(generateCodeVerifier());
  assertEquals(encoded.length, 43);
  const decoded = decodeBase64url(generateCodeVerifier());
  assertEquals(decoded.length, 32);
});
