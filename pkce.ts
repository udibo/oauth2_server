import { createHash, encodeBase64url } from "./deps.ts";

/**
 * A challenge method used for PKCE.
 * Transforms a verifier into a challenge.
 */
export type ChallengeMethod = (verifier: string) => string;

/** The allowed PKCE code challenge methods. */
export interface ChallengeMethods {
  [key: string]: ChallengeMethod;
}

/**
 * The default allowed PKCE code challenge methods.
 * Clients SHOULD use PKCE code challenge methods that do not expose the
 * PKCE verifier in the authorization request. Currently, "S256" is the only such method.
 * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.1
 */
export const challengeMethods: ChallengeMethods = {
  S256: (verifier: string) => {
    const hash = createHash("sha256");
    hash.update(verifier);
    const buffer: ArrayBuffer = hash.digest();
    return encodeBase64url(new Uint8Array(buffer));
  },
};

/**
 * Generates a random code verifier with a minimum of 256 bits of entropy.
 * This is done by generating a random 32-octet sequence then base64url encoding it
 * to produce a 43 octet URL safe string.
 * https://datatracker.ietf.org/doc/html/rfc7636#section-7.1
 */
export function generateCodeVerifier() {
  const sequence = new Uint8Array(32);
  crypto.getRandomValues(sequence);
  return encodeBase64url(sequence);
}
