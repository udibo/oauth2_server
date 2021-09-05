import { AccessToken, RefreshToken, Scope, Token } from "../deps.ts";
import { AppClient } from "./client.ts";
import { AppUser } from "./user.ts";

export interface AppAccessToken extends AccessToken<Scope> {
  client: AppClient;
  user: AppUser;
}

export interface AppToken extends Token<Scope> {
  client: AppClient;
  user: AppUser;
}

export interface AppRefreshToken extends RefreshToken<Scope> {
  client: AppClient;
  user: AppUser;
}
