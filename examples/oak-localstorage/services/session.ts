import { Session } from "../models/session.ts";
import { UserService } from "./user.ts";

interface SessionInternal {
  id: string;
  csrf: string;
  userId?: string;
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
    const next: SessionInternal = { id, csrf };
    if (state) next.state = state;
    if (redirectUri) next.redirectUri = redirectUri;
    if (codeVerifier) next.codeVerifier = codeVerifier;
    if (accessToken) next.accessToken = accessToken;
    if (accessTokenExpiresAt) {
      next.accessTokenExpiresAt = accessTokenExpiresAt?.valueOf();
    }
    if (refreshToken) next.refreshToken = refreshToken;
    if (user) next.userId = user.id;
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
    const current = await this.getInternal(id);
    if (!current) throw new Error("session not found");
    const next: SessionInternal = { ...current, id };

    if (user) next.userId = user.id;
    else if (user === null) delete next.userId;

    if (state) next.state = state;
    else if (state === null) delete next.state;

    if (redirectUri) next.redirectUri = redirectUri;
    else if (redirectUri === null) delete next.redirectUri;

    if (codeVerifier) next.codeVerifier = codeVerifier;
    else if (codeVerifier === null) delete next.codeVerifier;

    if (accessToken) next.accessToken = accessToken;
    else if (accessToken === null) delete next.accessToken;

    if (accessTokenExpiresAt) {
      next.accessTokenExpiresAt = accessTokenExpiresAt?.valueOf();
    } else if (accessTokenExpiresAt === null) delete next.accessTokenExpiresAt;

    if (refreshToken) next.refreshToken = refreshToken;
    else if (refreshToken === null) delete next.refreshToken;

    if (csrf) next.csrf = csrf;

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
      userId,
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
    if (userId) external.user = await this.userService.get(userId);
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
