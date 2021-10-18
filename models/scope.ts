import { NQCHAR } from "../common.ts";
import { InvalidScopeError } from "../errors.ts";

export const SCOPE = new RegExp(
  `^(?:(?:${NQCHAR.source}+)(?: ${NQCHAR.source}+)*)?$`,
);
export const SCOPE_TOKEN = new RegExp(`${NQCHAR.source}+`, "g");

export interface ScopeInterface {
  /** Deletes all scope tokens from this scope. */
  clear(): ScopeInterface;

  /** Adds all scope tokens in the passted in scope to this scope. */
  add(scope: ScopeInterface | string): ScopeInterface;

  /** Removes all scope tokens in the passed in scope from this scope. */
  remove(scope: ScopeInterface | string): ScopeInterface;

  /** Checks that this scope has all scope tokens in the passed in scope. */
  has(scope: ScopeInterface | string): boolean;

  /** Checks that this scope is equal to the passed in scope. */
  equals(scope: ScopeInterface | string): boolean;

  /** Converts the scope to a string representation. */
  toString(): string;

  /** Converts the scope to a JSON representation. */
  toJSON(): string;

  /** Returns an iterator for retrieving tokens from the scope in insertion order. */
  [Symbol.iterator](): IterableIterator<string>;
}

/** Constructor for scope. */
export interface ScopeConstructor<Scope extends ScopeInterface> {
  new (scope?: string): Scope;
  /** Creates a new scope with all scope tokens from both scopes. */
  from(scope: Scope | string): Scope;
  /** Creates a new scope with all scope tokens from both scopes. */
  union(a: Scope | string, b: Scope | string): Scope;
  /** Creates a new scope with all scope tokens that are present in both scopes. */
  intersection(
    a: Scope | string,
    b: Scope | string,
  ): Scope;
}

/** A basic implementation of scope. */
export class Scope implements ScopeInterface {
  private stringCache?: string;
  private tokens: Set<string>;

  constructor(scope?: string) {
    if (scope && !SCOPE.test(scope)) {
      throw new InvalidScopeError("invalid scope");
    }
    this.tokens = scope ? new Set(scope.match(SCOPE_TOKEN)) : new Set();
  }

  /** Creates a new scope from a scope. */
  static from(scope: Scope | string): Scope {
    if (typeof scope === "string") return new Scope(scope);
    const result: Scope = new Scope();
    for (const token of scope) {
      result.tokens.add(token);
    }
    return result;
  }

  /** Creates a new scope with all scope tokens from both scopes. */
  static union(a: Scope | string, b: Scope | string): Scope {
    return Scope.from(a).add(b);
  }

  /** Creates a new scope with all scope tokens that are present in both scopes. */
  static intersection(
    a: Scope | string,
    b: Scope | string,
  ): Scope {
    const result: Scope = new Scope();
    if (typeof a === "string") a = new Scope(a);
    if (typeof b === "string") b = new Scope(b);
    for (const token of a) {
      if (b.tokens.has(token)) result.add(token);
    }
    return result;
  }

  /** Deletes all scope tokens from this scope. */
  clear(): Scope {
    this.tokens = new Set<string>();
    delete this.stringCache;
    return this;
  }

  /** Adds all scope tokens in the passted in scope to this scope. */
  add(scope: Scope | string): Scope {
    if (typeof scope === "string") scope = new Scope(scope);
    for (const token of scope) {
      this.tokens.add(token);
    }
    delete this.stringCache;
    return this;
  }

  /** Removes all scope tokens in the passed in scope from this scope. */
  remove(scope: Scope | string): Scope {
    if (typeof scope === "string") scope = new Scope(scope);
    for (const token of scope) {
      this.tokens.delete(token);
    }
    delete this.stringCache;
    return this;
  }

  /** Checks that this scope has all scope tokens in the passed in scope. */
  has(scope: Scope | string): boolean {
    if (typeof scope === "string") scope = new Scope(scope);
    for (const token of scope) {
      if (!this.tokens.has(token)) return false;
    }
    return true;
  }

  /** Checks that this scope is equal to the passed in scope. */
  equals(scope: Scope | string): boolean {
    if (typeof scope === "string") scope = new Scope(scope);
    if (this.tokens.size !== scope.tokens.size) return false;
    for (const token of scope) {
      if (!this.tokens.has(token)) return false;
    }
    return true;
  }

  /** Converts the scope to a string representation. */
  toString(): string {
    if (typeof this.stringCache !== "string") {
      this.stringCache = [...this].join(" ");
    }
    return this.stringCache;
  }

  /** Converts the scope to a JSON representation. */
  toJSON(): string {
    return this.toString();
  }

  *[Symbol.iterator](): IterableIterator<string> {
    yield* this.tokens.values();
  }
}
