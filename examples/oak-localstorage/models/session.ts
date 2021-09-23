import { User } from "./user.ts";

export interface Session {
  id: string;
  csrf: string;
  user?: User;
  state?: string;
  redirectUri?: string;
  codeVerifier?: string;
  accessToken?: string;
  refreshToken?: string;
  accessTokenExpiresAt?: Date;
}
