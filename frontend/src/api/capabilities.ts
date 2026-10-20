import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "./client";
import type { MethodologyInfo } from "../methodology";

export interface AuthProviderInfo {
  id: string;
  label: string;
  login_url: string;
  /** False when the server refuses passwords for most users (the form is tucked behind an owner link). */
  password_login?: boolean;
}

export interface Capabilities {
  plugins: { name: string; version: string; features: string[] }[];
  features: string[];
  auth_providers: AuthProviderInfo[];
  /** Instance-level state of the experimental AI assist. Whether a user has a key is a separate call. */
  ai: { enabled: boolean; experimental: boolean };
  /** The threat-modelling methodologies this installation can generate for (STRIDE, plus a plugin's). */
  methodologies?: MethodologyInfo[];
}

export function fetchCapabilities(): Promise<Capabilities> {
  return apiFetch<Capabilities>("/api/capabilities");
}

/** Reads `/api/capabilities` once, with `refresh` for after something changes it (e.g. the AI switch). */
export function useCapabilities(): {
  capabilities: Capabilities | null;
  refresh: () => Promise<void>;
} {
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const refresh = useCallback(async () => {
    try {
      setCapabilities(await fetchCapabilities());
    } catch {
      setCapabilities(null);
    }
  }, []);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  return { capabilities, refresh };
}
