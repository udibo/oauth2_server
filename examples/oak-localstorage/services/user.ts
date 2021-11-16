import { AbstractUserService, generateSalt, hashPassword } from "../deps.ts";
import { User } from "../models/user.ts";

interface UserInternal {
  id: string;
  username: string;
  email?: string;
  hash?: string;
  salt?: string;
}

export class UserService extends AbstractUserService<User> {
  constructor() {
    super();
  }

  async create(user: Omit<User, "id">): Promise<void> {
    return await this.put({ ...user, id: crypto.randomUUID() });
  }

  async put(user: User): Promise<void> {
    const { id, username, password, email } = user;
    const next: UserInternal = { id, username };

    if (email) next.email = email;
    if (password) {
      next.salt = generateSalt();
      next.hash = await hashPassword(password, next.salt);
    }

    localStorage.setItem(`username:${username}`, id);
    localStorage.setItem(`user:${id}`, JSON.stringify(next));
    return await Promise.resolve();
  }

  async patch(user: Partial<User> & Pick<User, "id">): Promise<void> {
    const { id, username, email, password } = user;
    const current = await this.getInternal(id);
    if (!current) throw new Error("user not found");
    const next: UserInternal = { ...current, id };

    if (username) next.username = username;

    if (email) next.email = email;
    else if (email === null) delete next.email;

    if (password) {
      next.salt = generateSalt();
      next.hash = await hashPassword(password, next.salt);
    } else if (password === null) {
      delete next.salt;
      delete next.hash;
    }

    localStorage.setItem(`user:${id}`, JSON.stringify(next));
  }

  async delete(user: User | string): Promise<boolean> {
    const id = typeof user === "string" ? user : user.id;
    const internal = await this.getInternal(id);
    if (internal) {
      localStorage.removeItem(`username:${internal.username}`);
      localStorage.removeItem(`user:${id}`);
    }
    return Promise.resolve(!!internal);
  }

  private async getInternal(id: string): Promise<UserInternal | undefined> {
    const internalText = localStorage.getItem(`user:${id}`);
    return await Promise.resolve(
      internalText ? JSON.parse(internalText) : undefined,
    );
  }

  private async toExternal(internal: UserInternal): Promise<User> {
    const { id, username, email } = internal;
    return await Promise.resolve({ id, username, email });
  }

  async get(id: string): Promise<User | undefined> {
    const internal = await this.getInternal(id);
    return internal ? await this.toExternal(internal) : undefined;
  }

  async getAuthenticated(
    username: string,
    password: string,
  ): Promise<User | undefined> {
    const id = localStorage.getItem(`username:${username}`);
    const internal = id && await this.getInternal(id);
    let user: User | undefined = undefined;
    if (internal) {
      const { hash, salt } = internal;
      if (hash && salt && await hashPassword(password, salt) === hash) {
        user = await this.toExternal(internal);
      }
    }
    return user;
  }
}
