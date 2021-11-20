import {
  AbstractGrant,
  ClientCredentials,
  GrantInterface,
  GrantOptions,
  GrantServices,
} from "./grant.ts";
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  ServerError,
} from "../errors.ts";
import { Token } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { ClientInterface } from "../models/client.ts";
import { AuthorizationCode } from "../models/authorization_code.ts";
import {
  AuthorizationCodeServiceInterface,
} from "../services/authorization_code.ts";
import {
  ChallengeMethod,
  ChallengeMethods,
  challengeMethods,
} from "../pkce.ts";
import { Scope as DefaultScope, ScopeInterface } from "../models/scope.ts";

export interface AuthorizationCodeGrantServices<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends GrantServices<Client, User, Scope> {
  authorizationCodeService: AuthorizationCodeServiceInterface<
    Client,
    User,
    Scope
  >;
}

export interface AuthorizationCodeGrantOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends GrantOptions<Client, User, Scope> {
  services: AuthorizationCodeGrantServices<Client, User, Scope>;
  challengeMethods?: ChallengeMethods;
}

export interface GenerateAuthorizationCodeOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  /** The client associated with the authorization code. */
  client: Client;
  /** The user associated with the authorization code. */
  user: User;
  /** The scope granted to the authorization code. */
  scope?: Scope;
  /** Redirect URI for the authorization code. */
  redirectUri?: string | null;
  /** The code challenge used for PKCE. */
  challenge?: string | null;
  /** The code challenge method used for PKCE. */
  challengeMethod?: string | null;
}
export interface AuthorizationCodeGrantInterface<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends GrantInterface<Client, User, Scope> {
  services: AuthorizationCodeGrantServices<Client, User, Scope>;
  challengeMethods: ChallengeMethods;

  getClient(clientId: string): Promise<Client>;
  getChallengeMethod(challengeMethod?: string): ChallengeMethod | undefined;
  validateChallengeMethod(challengeMethod?: string): boolean;
  verifyCode(
    code: AuthorizationCode<Client, User, Scope>,
    verifier: string,
  ): Promise<boolean>;
}

export interface PKCEClientCredentials extends ClientCredentials {
  codeVerifier?: string;
}

/**
 * The authorization code grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.1
 * This grant supports PKCE.
 * https://datatracker.ietf.org/doc/html/rfc7636#page-9
 * Clients must use PKCE in order to detect and prevent attempts to
 * inject (replay) authorization codes in the authorization response.
 * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.1
 */
export class AuthorizationCodeGrant<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface = DefaultScope,
> extends AbstractGrant<Client, User, Scope>
  implements AuthorizationCodeGrantInterface<Client, User, Scope> {
  declare services: AuthorizationCodeGrantServices<Client, User, Scope>;
  challengeMethods: ChallengeMethods;

  constructor(options: AuthorizationCodeGrantOptions<Client, User, Scope>) {
    super(options);
    this.challengeMethods = options.challengeMethods ?? challengeMethods;
  }

  async getClientCredentials(
    request: OAuth2Request<Client, User, Scope>,
  ): Promise<PKCEClientCredentials> {
    const clientCredentials: PKCEClientCredentials = await super
      .getClientCredentials(request);
    if (request.hasBody) {
      const body: URLSearchParams = await request.body!;
      const codeVerifier: string | null = body.get("code_verifier");
      if (codeVerifier) {
        clientCredentials.codeVerifier = codeVerifier;
        delete clientCredentials.clientSecret;
      }
    }
    return clientCredentials;
  }

  async getClient(clientId: string): Promise<Client> {
    const { clientService } = this.services;
    const client: Client | void = await clientService.get(clientId);
    if (!client) throw new InvalidClientError("client not found");
    return client;
  }

  async getAuthenticatedClient(
    request: OAuth2Request<Client, User, Scope>,
  ): Promise<Client> {
    const { clientId, clientSecret, codeVerifier }: PKCEClientCredentials =
      await this
        .getClientCredentials(request);
    const { clientService } = this.services;
    const client: Client | void = codeVerifier
      ? await clientService.get(clientId)
      : clientSecret
      ? await clientService.getAuthenticated(clientId, clientSecret)
      : await clientService.getAuthenticated(clientId);
    if (!client) throw new InvalidClientError("client authentication failed");
    return client;
  }

  /** Gets the challenge method if it is allowed. */
  getChallengeMethod(
    challengeMethod?: string | null,
  ): ChallengeMethod | undefined {
    return this.challengeMethods[challengeMethod ?? "plain"];
  }

  /** Checks that the challenge method is allowed. */
  validateChallengeMethod(challengeMethod?: string | null): boolean {
    return !!this.getChallengeMethod(challengeMethod);
  }

  /**
   * Checks if the verifier matches the authorization code.
   * https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
   */
  async verifyCode(
    code: AuthorizationCode<Client, User, Scope>,
    verifier: string,
  ): Promise<boolean> {
    if (!code.challenge) return false;
    const challengeMethod = this.getChallengeMethod(code.challengeMethod);
    if (challengeMethod) {
      const challenge: string = await challengeMethod(verifier);
      if (challenge !== code.challenge) return false;
    } else {
      throw new ServerError("code_challenge_method not implemented");
    }
    return true;
  }

  /** Generates and saves an authorization code. */
  async generateAuthorizationCode(
    options: Omit<AuthorizationCode<Client, User, Scope>, "code" | "expiresAt">,
  ): Promise<AuthorizationCode<Client, User, Scope>> {
    const { client, user, scope } = options;
    const { authorizationCodeService } = this.services;
    const authorizationCode: AuthorizationCode<Client, User, Scope> = {
      code: await authorizationCodeService.generateCode(client, user, scope),
      expiresAt: await authorizationCodeService.expiresAt(client, user, scope),
      ...options,
    };
    return await authorizationCodeService.save(authorizationCode);
  }

  /** Generates and saves a token. */
  async token(
    request: OAuth2Request<Client, User, Scope>,
    client: Client,
  ): Promise<Token<Client, User, Scope>> {
    if (!request.hasBody) {
      throw new InvalidRequestError("request body required");
    }

    const body: URLSearchParams = await request.body!;
    const code: string | null = body.get("code");
    if (!code) {
      throw new InvalidRequestError("code parameter required");
    }

    const { authorizationCodeService, tokenService } = this.services;
    if (await tokenService.revokeCode(code)) {
      throw new InvalidGrantError("code already used");
    }

    const authorizationCode: AuthorizationCode<Client, User, Scope> | void =
      await authorizationCodeService.get(code);
    if (!authorizationCode || authorizationCode.expiresAt < new Date()) {
      throw new InvalidGrantError("invalid code");
    }
    await authorizationCodeService.revoke(authorizationCode);

    const codeVerifier: string | null = body.get("code_verifier");
    if (codeVerifier) {
      if (!await this.verifyCode(authorizationCode, codeVerifier)) {
        throw new InvalidClientError("client authentication failed");
      }
    } else if (authorizationCode.challenge) {
      // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.8.2
      throw new InvalidClientError("client authentication failed");
    }

    const {
      client: authorizationCodeClient,
      user,
      scope,
      redirectUri: expectedRedirectUri,
    }: AuthorizationCode<Client, User, Scope> = authorizationCode;
    if (client.id.toString() !== authorizationCodeClient.id.toString()) {
      throw new InvalidClientError("code was issued to another client");
    }

    const redirectUri: string | null = body.get("redirect_uri");
    if (expectedRedirectUri) {
      if (!redirectUri) {
        throw new InvalidGrantError("redirect_uri parameter required");
      } else if (redirectUri !== expectedRedirectUri) {
        throw new InvalidGrantError("incorrect redirect_uri");
      }
    } else if (redirectUri) {
      throw new InvalidGrantError("did not expect redirect_uri parameter");
    }

    const token = await this.generateToken(client, user, scope);
    token.code = code;
    return await tokenService.save(token);
  }
}
