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
