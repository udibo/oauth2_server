import { ClientInterface } from "./client.ts";
import { ScopeInterface } from "./scope.ts";

export interface AuthorizationCode<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  /** The authorization code. */
  code: string;
  /** The expiration time for the authorization code. */
  expiresAt: Date;
  /** The client associated with the authorization code. */
  client: Client;
  /** The user associated with the authorization code. */
  user: User;
  /** The scope granted to the authorization code. */
  scope?: Scope | null;
  /** Redirect URI for the authorization code. */
  redirectUri?: string | null;
  /** The code challenge used for PKCE. */
  challenge?: string | null;
  /** The code challenge method used for PKCE. */
  challengeMethod?: string | null;
}
