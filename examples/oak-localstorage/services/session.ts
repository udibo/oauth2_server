import { Session } from "../models/session.ts";
import { UserService } from "./user.ts";

interface SessionInternal {
  csrf: string;
  username?: string;
  authorizedScope?: string;
  state?: string;
  redirectUri?: string;
  codeVerifier?: string;
  accessToken?: string;
  refreshToken?: string;
  accessTokenExpiresAt?: number;
}

export function saveSession(sessionId: string, session: Session): void {
  localStorage.setItem(`session:${sessionId}`, JSON.stringify(session));
}

export class SessionService {
  private userService: UserService;

  constructor(userService: UserService) {
    this.userService = userService;
  }

  async insert(session: Session): Promise<void> {
    if (localStorage.getItem(`session:${session.id}`)) {
      throw new Error("session already exists");
    }
    await this.update(session);
  }

  update(session: Session): Promise<void> {
    const {
      user,
      state,
      redirectUri,
      codeVerifier,
      accessToken,
      refreshToken,
      accessTokenExpiresAt,
      csrf,
    } = session;
    localStorage.setItem(
      `session:${session.id}`,
      JSON.stringify({
        state,
        redirectUri,
        codeVerifier,
        accessToken,
        refreshToken,
        accessTokenExpiresAt,
        csrf,
        username: user?.username,
      } as SessionInternal),
    );
    return Promise.resolve();
  }

  delete(session: Session | string): Promise<boolean> {
    const sessionId = typeof session === "string" ? session : session.id;
    const sessionKey = `session:${sessionId}`;
    const existed = !!localStorage.getItem(sessionKey);
    localStorage.removeItem(sessionKey);
    return Promise.resolve(existed);
  }

  async get(id: string): Promise<Session | undefined> {
    const internalText = localStorage.getItem(`session:${id}`);
    let session: Session | undefined = undefined;
    if (internalText) {
      const internal: SessionInternal = JSON.parse(internalText);
      const {
        username,
        state,
        redirectUri,
        codeVerifier,
        accessToken,
        refreshToken,
        accessTokenExpiresAt,
        csrf,
      } = internal;
      session = {
        id,
        state,
        redirectUri,
        codeVerifier,
        accessToken,
        refreshToken,
        accessTokenExpiresAt,
        csrf,
      };
      if (username) session.user = await this.userService.get(username);
    }
    return session;
  }

  async start(id?: string): Promise<Session> {
    let session: Session | undefined = id ? await this.get(id) : undefined;
    if (!session) {
      session = {
        id: crypto.randomUUID(),
        csrf: crypto.randomUUID(),
      };
      await this.insert(session);
    }
    return session;
  }
}
