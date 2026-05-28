import { invoke } from "@tauri-apps/api/core";
import { create } from "zustand";
import { setLastWslDistro } from "@/modules/settings/store";

export type WorkspaceEnv =
  | { kind: "local" }
  | { kind: "wsl"; distro: string }
  | { kind: "ssh"; conn: string };

export type WslDistro = {
  name: string;
  default: boolean;
  running: boolean;
};

/** Mirrors the Rust `SshAuth` (serde tag = "method"). */
export type SshAuth =
  | { method: "agent" }
  | { method: "password"; password: string }
  | { method: "key"; path: string; passphrase?: string };

/** Mirrors the Rust `SshConnectRequest`. */
export type SshConnectRequest = {
  host: string;
  port?: number;
  user: string;
  auth: SshAuth;
  label?: string;
};

/** Mirrors the Rust `ConnectionInfo` returned by `ssh_connect`. */
export type SshConnectionInfo = {
  id: string;
  label: string;
  host: string;
  port: number;
  user: string;
  home: string;
};

type State = {
  env: WorkspaceEnv;
  distros: WslDistro[];
  sshConns: SshConnectionInfo[];
  loading: boolean;
  error: string | null;
  setEnv: (env: WorkspaceEnv) => void;
  refreshDistros: () => Promise<WslDistro[]>;
  refreshSshConns: () => Promise<SshConnectionInfo[]>;
  connectSsh: (req: SshConnectRequest) => Promise<SshConnectionInfo>;
  disconnectSsh: (id: string) => Promise<void>;
};

export const LOCAL_WORKSPACE: WorkspaceEnv = { kind: "local" };

export const useWorkspaceEnvStore = create<State>((set) => ({
  env: LOCAL_WORKSPACE,
  distros: [],
  sshConns: [],
  loading: false,
  error: null,
  setEnv: (env) => {
    set({ env });
    if (env.kind === "wsl") void setLastWslDistro(env.distro);
  },
  refreshDistros: async () => {
    set({ loading: true, error: null });
    try {
      const distros = await invoke<WslDistro[]>("wsl_list_distros");
      set({ distros, loading: false });
      return distros;
    } catch (e) {
      set({ distros: [], loading: false, error: String(e) });
      return [];
    }
  },
  refreshSshConns: async () => {
    try {
      const sshConns = await invoke<SshConnectionInfo[]>(
        "ssh_list_connections",
      );
      set({ sshConns });
      return sshConns;
    } catch (e) {
      set({ error: String(e) });
      return [];
    }
  },
  connectSsh: async (req) => {
    const info = await invoke<SshConnectionInfo>("ssh_connect", { req });
    set((s) => ({
      sshConns: [...s.sshConns.filter((c) => c.id !== info.id), info],
    }));
    return info;
  },
  disconnectSsh: async (id) => {
    await invoke("ssh_disconnect", { conn: id });
    set((s) => {
      const next: Partial<State> = {
        sshConns: s.sshConns.filter((c) => c.id !== id),
      };
      // If we were sitting in the connection we just dropped, fall back to
      // local so the explorer doesn't keep hammering a dead session.
      if (s.env.kind === "ssh" && s.env.conn === id) {
        next.env = LOCAL_WORKSPACE;
      }
      return next;
    });
  },
}));

export function currentWorkspaceEnv(): WorkspaceEnv {
  return useWorkspaceEnvStore.getState().env;
}

export function workspaceScopeKey(env: WorkspaceEnv): string {
  if (env.kind === "wsl") return `wsl:${env.distro}`;
  if (env.kind === "ssh") return `ssh:${env.conn}`;
  return "local";
}

export function currentWorkspaceScopeKey(): string {
  return workspaceScopeKey(currentWorkspaceEnv());
}

export async function getWslHome(distro: string): Promise<string> {
  return invoke<string>("wsl_home", { distro });
}

export async function getSshHome(conn: string): Promise<string> {
  return invoke<string>("ssh_home", { conn });
}
