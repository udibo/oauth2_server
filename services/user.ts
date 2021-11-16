import { encodeHex } from "../deps.ts";
import { ServerError } from "../errors.ts";

export interface UserServiceInterface<User> {
  /** Retrieves an authenticated user if the username/password combination is correct. */
  getAuthenticated(
    username: string,
    password: string,
  ): Promise<User | undefined>;
}

export abstract class AbstractUserService<User>
  implements UserServiceInterface<User> {
  /** Retrieves an authenticated user if the username/password combination is correct. Not implemented by default. */
  async getAuthenticated(
    _username: string,
    _password: string,
  ): Promise<User | undefined> {
    return await Promise.reject(
      new ServerError("userService.getAuthenticated not implemented"),
    );
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Generates random salt. The length is the number of bytes. */
export function generateSalt(length = 16): string {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return decoder.decode(encodeHex(salt));
}

/** Hashes a password with salt using the PBKDF2 algorithm with 100k SHA-256 iterations. */
export async function hashPassword(
  password: string,
  salt: string,
): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"],
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );
  const buffer = new Uint8Array(derivedBits, 0, 32);
  return decoder.decode(encodeHex(buffer));
}
