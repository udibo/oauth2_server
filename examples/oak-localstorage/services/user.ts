import { AbstractUserService, createHash, encodeBase64 } from "../deps.ts";
import { User } from "../models/user.ts";

function generateSalt(): string {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  return encodeBase64(salt);
}

function hashPassword(password: string, salt: string): string {
  const hash = createHash("sha256");
  hash.update(`${password}:${salt}`);
  return hash.toString();
}

interface UserInternal {
  username: string;
  email?: string;
  hash?: string;
  salt?: string;
}

export class UserService extends AbstractUserService<User> {
  constructor() {
    super();
  }

  put(user: User): Promise<void> {
    const { username, password, email } = user;
    const next: UserInternal = { username, email };
    if (password) {
      next.salt = generateSalt();
      next.hash = hashPassword(password, next.salt);
    }
    localStorage.setItem(`user:${username}`, JSON.stringify(next));
    return Promise.resolve();
  }

  async patch(user: Partial<User> & Pick<User, "username">): Promise<void> {
    const { username, email, password } = user;
    const current = await this.getInternal(username);
    if (!current) throw new Error("user not found");
    const next: UserInternal = { ...current, username };
    if ("email" in user) next.email = email;
    if ("password" in user) {
      if (password) {
        next.salt = generateSalt();
        next.hash = hashPassword(password, next.salt);
      } else {
        delete next.salt;
        delete next.hash;
      }
    }
    localStorage.setItem(`user:${username}`, JSON.stringify(next));
  }

  delete(user: User | string): Promise<boolean> {
    const username = typeof user === "string" ? user : user.username;
    const userKey = `user:${username}`;
    const existed = !!localStorage.getItem(userKey);
    localStorage.removeItem(userKey);
    return Promise.resolve(existed);
  }

  private getInternal(username: string): Promise<UserInternal | undefined> {
    const internalText = localStorage.getItem(`user:${username}`);
    return Promise.resolve(internalText ? JSON.parse(internalText) : undefined);
  }

  private toExternal(internal: UserInternal): Promise<User> {
    const { username, email } = internal;
    return Promise.resolve({ username, email });
  }

  async get(username: string): Promise<User | undefined> {
    const internal = await this.getInternal(username);
    return internal ? await this.toExternal(internal) : undefined;
  }

  async getAuthenticated(
    username: string,
    password: string,
  ): Promise<User | undefined> {
    const internal = await this.getInternal(username);
    let user: User | undefined = undefined;
    if (internal) {
      const { hash, salt } = internal;
      if (hash && salt && hashPassword(password, salt) === hash) {
        user = await this.toExternal(internal);
      }
    }
    return user;
  }
}
