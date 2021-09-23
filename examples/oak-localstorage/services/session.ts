import { Session } from "../models/session.ts";
import { UserService } from "./user.ts";

interface SessionInternal {
  id: string;
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

  put(session: Session): Promise<void> {
    const {
      id,
      user,
      state,
      redirectUri,
      codeVerifier,
      accessToken,
      refreshToken,
      accessTokenExpiresAt,
      csrf,
    } = session;
    const next: SessionInternal = {
      id,
      state,
      redirectUri,
      codeVerifier,
      accessToken,
      refreshToken,
      csrf,
      username: user?.username,
    };
    if (accessTokenExpiresAt) {
      next.accessTokenExpiresAt = accessTokenExpiresAt?.valueOf();
    }
    localStorage.setItem(`session:${id}`, JSON.stringify(next));
    return Promise.resolve();
  }

  async patch(session: Partial<Session> & Pick<Session, "id">): Promise<void> {
    const {
      id,
      user,
      state,
      redirectUri,
      codeVerifier,
      accessToken,
      refreshToken,
      accessTokenExpiresAt,
      csrf,
    } = session;
    const { username } = user ?? {};
    const current = await this.getInternal(id);
    if (!current) throw new Error("session not found");
    const next: SessionInternal = { ...current };
    if ("user" in session) next.username = username;
    if ("state" in session) next.state = state;
    if ("redirectUri" in session) next.redirectUri = redirectUri;
    if ("codeVerifier" in session) next.codeVerifier = codeVerifier;
    if ("accessToken" in session) next.accessToken = accessToken;
    if ("refreshToken" in session) next.refreshToken = refreshToken;
    if ("accessTokenExpiresAt" in session) {
      next.accessTokenExpiresAt = accessTokenExpiresAt?.valueOf();
    }
    if ("csrf" in session) next.csrf = csrf ?? crypto.randomUUID();
    localStorage.setItem(`session:${id}`, JSON.stringify(next));
    await Promise.resolve();
  }

  delete(session: Session | string): Promise<boolean> {
    const sessionId = typeof session === "string" ? session : session.id;
    const sessionKey = `session:${sessionId}`;
    const existed = !!localStorage.getItem(sessionKey);
    localStorage.removeItem(sessionKey);
    return Promise.resolve(existed);
  }

  private getInternal(id: string): Promise<SessionInternal | undefined> {
    const internalText = localStorage.getItem(`session:${id}`);
    return Promise.resolve(internalText ? JSON.parse(internalText) : undefined);
  }

  private async toExternal(internal: SessionInternal): Promise<Session> {
    const {
      id,
      state,
      redirectUri,
      codeVerifier,
      accessToken,
      refreshToken,
      accessTokenExpiresAt,
      csrf,
      username,
    } = internal;
    const external: Session = {
      id,
      state,
      redirectUri,
      codeVerifier,
      accessToken,
      refreshToken,
      csrf,
    };
    if (accessTokenExpiresAt) {
      external.accessTokenExpiresAt = new Date(accessTokenExpiresAt);
    }
    if (username) external.user = await this.userService.get(username);
    return external;
  }

  async get(id: string): Promise<Session | undefined> {
    const internal = await this.getInternal(id);
    return internal ? await this.toExternal(internal) : undefined;
  }

  async start(id?: string): Promise<Session> {
    let session: Session | undefined = id ? await this.get(id) : undefined;
    if (!session) {
      session = {
        id: crypto.randomUUID(),
        csrf: crypto.randomUUID(),
      };
      await this.put(session);
    }
    return session;
  }
}
