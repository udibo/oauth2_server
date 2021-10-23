import { encodeHex } from "../deps.ts";
import { ServerError } from "../errors.ts";

export interface UserServiceInterface<User> {
  /** Hashes a password with optional salt. */
  hashPassword(password: string, salt?: string): Promise<string>;
  /** Retrieves an authenticated user if the username/password combination is correct. */
  getAuthenticated(
    username: string,
    password: string,
  ): Promise<User | undefined>;
}

export abstract class AbstractUserService<User>
  implements UserServiceInterface<User> {
  /** Hashes a password with optional salt. Default implementation uses SHA-256 algorithm. */
  async hashPassword(password: string, salt?: string): Promise<string> {
    const data = (new TextEncoder()).encode(
      password + (salt ? `:${salt}` : ""),
    );
    const buffer = await crypto.subtle.digest("SHA-256", data);
    return (new TextDecoder()).decode(encodeHex(new Uint8Array(buffer)));
  }

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
