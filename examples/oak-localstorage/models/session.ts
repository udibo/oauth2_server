import { AppUser } from "./user.ts";

export interface Session {
  id: string;
  user?: AppUser;
  state?: string;
  redirectUri?: string;
  codeVerifier?: string;
  accessToken?: string;
  refreshToken?: string;
  accessTokenExpiresAt?: number;
  csrf?: string;
}
