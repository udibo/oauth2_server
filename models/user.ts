import { ServerError } from "../errors.ts";

export interface User {
  // deno-lint-ignore no-explicit-any
  [key: string]: any;
}

export interface UserServiceInterface {
  /** Retrieves an authenticated user if the username/password combination is correct. */
  getAuthenticated(
    username: string,
    password: string,
  ): Promise<User | undefined>;
}

export abstract class UserService implements UserServiceInterface {
  /** Retrieves an authenticated user if the username/password combination is correct. Not implemented by default. */
  getAuthenticated(
    _username: string,
    _password: string,
  ): Promise<User | undefined> {
    return Promise.reject(
      new ServerError("userService.getAuthenticated not implemented"),
    );
  }
}
