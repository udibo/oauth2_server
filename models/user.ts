export interface User {
  // deno-lint-ignore no-explicit-any
  [key: string]: any;
}

export interface UserServiceInterface {
  /** Retrieves a user if the username/password combination is correct. */
  get(username: string, password: string): Promise<User | void>;
}

export class UserService implements UserServiceInterface {
  /** Retrieves a user if the username/password combination is correct. Not implemented by default. */
  get(_username: string, _password: string): Promise<User | void> {
    return Promise.reject(new Error("not implemented"));
  }
}
