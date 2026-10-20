import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, apiFetch, setCsrfToken, setUnauthorizedHandler } from "../api/client";

interface SessionInfo {
  csrf_token: string;
  expires_at: string;
  role: string;
  email?: string;
}

interface AuthState {
  isAuthenticated: boolean;
  loading: boolean;
  // True after the server ended a signed-in session (idle timeout or absolute limit); the login page explains it.
  signedOutByTimeout: boolean;
  role: string | null;
  email: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [role, setRole] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [signedOutByTimeout, setSignedOutByTimeout] = useState(false);
  const authedRef = useRef(false);

  useEffect(() => {
    authedRef.current = isAuthenticated;
  }, [isAuthenticated]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      if (!authedRef.current) return;
      authedRef.current = false;
      setCsrfToken(null);
      setRole(null);
      setEmail(null);
      setSignedOutByTimeout(true);
      setIsAuthenticated(false);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  useEffect(() => {
    // GET /api/auth/me on load: is there already a valid session cookie
    // (e.g. from a previous visit), and if so, what's its CSRF token/role.
    apiFetch<SessionInfo>("/api/auth/me")
      .then((session) => {
        setCsrfToken(session.csrf_token);
        setRole(session.role);
        setEmail(session.email || null);
        setIsAuthenticated(true);
      })
      .catch(() => {
        setCsrfToken(null);
        setRole(null);
        setEmail(null);
        setIsAuthenticated(false);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const session = await apiFetch<SessionInfo>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setCsrfToken(session.csrf_token);
    setRole(session.role);
        setEmail(session.email || null);
    setSignedOutByTimeout(false);
    setIsAuthenticated(true);
  }, []);

  const logout = useCallback(async () => {
    const result = await apiFetch<{ redirect?: string | null }>("/api/auth/logout", { method: "POST" }).catch(
      () => undefined,
    );
    setCsrfToken(null);
    setRole(null);
        setEmail(null);
    setSignedOutByTimeout(false);
    setIsAuthenticated(false);
    // A plugin may ask for a page to visit after sign-out, such as an identity provider's.
    if (result?.redirect) window.location.assign(result.redirect);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, loading, signedOutByTimeout, role, email, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}

export { ApiError };
