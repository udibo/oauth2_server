import { AbstractUserService, createHash, encodeBase64 } from "../deps.ts";
import { AppUser } from "../models/user.ts";

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

export class UserService extends AbstractUserService {
  constructor() {
    super();
  }

  async insert(user: AppUser, password: string): Promise<void> {
    if (localStorage.getItem(`user:${user.username}`)) {
      throw new Error("user already exists");
    }
    await this.update(user, password);
  }

  async update(user: AppUser, password?: string): Promise<void> {
    const { username, email } = user;
    const internal: UserInternal = { username, email };
    if (password) {
      internal.salt = generateSalt();
      internal.hash = hashPassword(password, internal.salt);
    } else {
      const current = await this.getInternal(username);
      if (current) {
        internal.salt = current.salt;
        internal.hash = current.hash;
      }
    }
    localStorage.setItem(`user:${username}`, JSON.stringify(internal));
  }

  delete(user: AppUser | string): Promise<boolean> {
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

  private toExternal(internal: UserInternal): Promise<AppUser> {
    const { username, email } = internal;
    return Promise.resolve({ username, email });
  }

  async get(username: string): Promise<AppUser | undefined> {
    const internal = await this.getInternal(username);
    return internal ? await this.toExternal(internal) : undefined;
  }

  async getAuthenticated(
    username: string,
    password: string,
  ): Promise<AppUser | undefined> {
    const internal = await this.getInternal(username);
    let user: AppUser | undefined = undefined;
    if (internal) {
      const { hash, salt } = internal;
      if (hash && salt && hashPassword(password, salt) === hash) {
        user = await this.toExternal(internal);
      }
    }
    return user;
  }
}
