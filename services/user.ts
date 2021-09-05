import { ServerError } from "../errors.ts";
import { User } from "../models/user.ts";

export interface UserServiceInterface {
  /** Retrieves an authenticated user if the username/password combination is correct. */
  getAuthenticated(
    username: string,
    password: string,
  ): Promise<User | undefined>;
}

export abstract class AbstractUserService implements UserServiceInterface {
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
