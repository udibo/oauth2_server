import {
  ClientCredentials,
  Grant,
  GrantInterface,
  GrantOptions,
  GrantServices,
} from "./grant.ts";
import {
  InvalidClient,
  InvalidGrant,
  InvalidRequest,
  ServerError,
} from "../errors.ts";
import type { Token } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";
import {
  AuthorizationCode,
  AuthorizationCodeServiceInterface,
} from "../models/authorization_code.ts";
import {
  ChallengeMethod,
  ChallengeMethods,
  challengeMethods,
} from "../pkce.ts";
import { User } from "../models/user.ts";
import { ScopeInterface } from "../models/scope.ts";

export interface AuthorizationCodeGrantServices extends GrantServices {
  authorizationCodeService: AuthorizationCodeServiceInterface;
}

export interface AuthorizationCodeGrantOptions extends GrantOptions {
  services: AuthorizationCodeGrantServices;
  challengeMethods?: ChallengeMethods;
}

export interface GenerateAuthorizationCodeOptions {
  /** The client associated with the authorization code. */
  client: Client;
  /** The user associated with the authorization code. */
  user: User;
  /** The scope granted to the authorization code. */
  scope?: ScopeInterface;
  /** Redirect URI for the authorization code. */
  redirectUri?: string | null;
  /** The code challenge used for PKCE. */
  challenge?: string | null;
  /** The code challenge method used for PKCE. */
  challengeMethod?: string | null;
}
export interface AuthorizationCodeGrantInterface extends GrantInterface {
  services: AuthorizationCodeGrantServices;
  challengeMethods: ChallengeMethods;

  getClient(clientId: string): Promise<Client>;
  getChallengeMethod(challengeMethod?: string): ChallengeMethod | undefined;
  validateChallengeMethod(challengeMethod?: string): boolean;
  verifyCode(code: AuthorizationCode, verifier: string): void;
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
export class AuthorizationCodeGrant extends Grant
  implements AuthorizationCodeGrantInterface {
  declare services: AuthorizationCodeGrantServices;
  challengeMethods: ChallengeMethods;

  constructor(options: AuthorizationCodeGrantOptions) {
    super(options);
    this.challengeMethods = options.challengeMethods ?? challengeMethods;
  }

  async getClientCredentials(
    request: OAuth2Request,
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
    const { clientService }: GrantServices = this.services;
    const client: Client | void = await clientService.get(clientId);
    if (!client) throw new InvalidClient("client not found");
    return client;
  }

  async getAuthenticatedClient(request: OAuth2Request): Promise<Client> {
    const { clientId, clientSecret, codeVerifier }: PKCEClientCredentials =
      await this
        .getClientCredentials(request);
    const { clientService }: GrantServices = this.services;
    const client: Client | void = codeVerifier
      ? await clientService.get(clientId)
      : clientSecret
      ? await clientService.getAuthenticated(clientId, clientSecret)
      : await clientService.getAuthenticated(clientId);
    if (!client) throw new InvalidClient("client authentication failed");
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
  verifyCode(code: AuthorizationCode, verifier: string): boolean {
    if (!code.challenge) return false;
    const challengeMethod = this.getChallengeMethod(code.challengeMethod);
    if (challengeMethod) {
      const challenge: string = challengeMethod(verifier);
      if (challenge !== code.challenge) return false;
    } else {
      throw new ServerError("code_challenge_method not implemented");
    }
    return true;
  }

  /** Generates and saves an authorization code. */
  async generateAuthorizationCode(
    options: Omit<AuthorizationCode, "code" | "expiresAt">,
  ): Promise<AuthorizationCode> {
    const { client, user, scope } = options;
    const { authorizationCodeService }: AuthorizationCodeGrantServices =
      this.services;
    const authorizationCode: AuthorizationCode = {
      code: await authorizationCodeService.generateCode(client, user, scope),
      expiresAt: await authorizationCodeService.expiresAt(client, user, scope),
      ...options,
    };
    return await authorizationCodeService.save(authorizationCode);
  }

  /** Generates and saves a token. */
  async token(request: OAuth2Request, client: Client): Promise<Token> {
    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const code: string | null = body.get("code");
    if (!code) {
      throw new InvalidRequest("code parameter required");
    }

    const { authorizationCodeService, tokenService }:
      AuthorizationCodeGrantServices = this.services;
    if (await tokenService.revokeCode(code)) {
      throw new InvalidGrant("code already used");
    }

    const authorizationCode: AuthorizationCode | void =
      await authorizationCodeService.get(code);
    if (!authorizationCode || authorizationCode.expiresAt < new Date()) {
      throw new InvalidGrant("invalid code");
    }
    await authorizationCodeService.revoke(authorizationCode);

    const codeVerifier: string | null = body.get("code_verifier");
    if (codeVerifier) {
      if (!this.verifyCode(authorizationCode, codeVerifier)) {
        throw new InvalidClient("client authentication failed");
      }
    } else if (authorizationCode.challenge) {
      // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.8.2
      throw new InvalidClient("client authentication failed");
    }

    const {
      client: authorizationCodeClient,
      user,
      scope,
      redirectUri: expectedRedirectUri,
    }: AuthorizationCode = authorizationCode;
    if (client.id !== authorizationCodeClient.id) {
      throw new InvalidClient("code was issued to another client");
    }

    const redirectUri: string | null = body.get("redirect_uri");
    if (expectedRedirectUri) {
      if (!redirectUri) {
        throw new InvalidGrant("redirect_uri parameter required");
      } else if (redirectUri !== expectedRedirectUri) {
        throw new InvalidGrant("incorrect redirect_uri");
      }
    } else if (redirectUri) {
      throw new InvalidGrant("did not expect redirect_uri parameter");
    }

    const token: Token = await this.generateToken(client, user, scope);
    token.code = code;
    return await tokenService.save(token);
  }
}
