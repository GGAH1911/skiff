import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useState } from "react";
import {
  useWorkspaceEnvStore,
  type SshAuth,
  type SshConnectionInfo,
} from "./env";

type AuthMethod = "agent" | "key" | "password";

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Fired after a successful connect with the established connection. */
  onConnected: (info: SshConnectionInfo) => void;
};

// Last-used form values (never secrets) so reconnecting doesn't mean retyping.
const PROFILE_KEY = "terax.ssh.lastProfile";

type SavedProfile = {
  host: string;
  port: string;
  user: string;
  method: AuthMethod;
  keyPath: string;
  label: string;
};

function loadProfile(): SavedProfile | null {
  try {
    const raw = localStorage.getItem(PROFILE_KEY);
    return raw ? (JSON.parse(raw) as SavedProfile) : null;
  } catch {
    return null;
  }
}

function saveProfile(p: SavedProfile) {
  try {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(p));
  } catch {
    // localStorage may be unavailable; non-fatal.
  }
}

export function SshConnectDialog({ open, onOpenChange, onConnected }: Props) {
  const connectSsh = useWorkspaceEnvStore((s) => s.connectSsh);
  const saved = loadProfile();

  const [host, setHost] = useState(saved?.host ?? "");
  const [port, setPort] = useState(saved?.port ?? "22");
  const [user, setUser] = useState(saved?.user ?? "");
  const [method, setMethod] = useState<AuthMethod>(saved?.method ?? "agent");
  const [keyPath, setKeyPath] = useState(saved?.keyPath ?? "~/.ssh/id_ed25519");
  const [passphrase, setPassphrase] = useState("");
  const [password, setPassword] = useState("");
  const [label, setLabel] = useState(saved?.label ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canConnect = host.trim() !== "" && user.trim() !== "" && !busy;

  const submit = async () => {
    if (!canConnect) return;
    setBusy(true);
    setError(null);

    let auth: SshAuth;
    if (method === "password") auth = { method: "password", password };
    else if (method === "key")
      auth = {
        method: "key",
        path: keyPath.trim(),
        passphrase: passphrase ? passphrase : undefined,
      };
    else auth = { method: "agent" };

    const parsedPort = Number.parseInt(port, 10);
    try {
      const info = await connectSsh({
        host: host.trim(),
        port: Number.isFinite(parsedPort) ? parsedPort : 22,
        user: user.trim(),
        auth,
        label: label.trim() || undefined,
      });
      saveProfile({
        host: host.trim(),
        port,
        user: user.trim(),
        method,
        keyPath: keyPath.trim(),
        label: label.trim(),
      });
      // Clear secrets from component state immediately after use.
      setPassword("");
      setPassphrase("");
      onOpenChange(false);
      onConnected(info);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Connect to SSH host</DialogTitle>
          <DialogDescription>
            Browse and edit files on a remote machine over SFTP.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-3 py-1">
          <div className="grid grid-cols-[1fr_84px] gap-2">
            <div className="grid gap-1.5">
              <Label htmlFor="ssh-host">Host</Label>
              <Input
                id="ssh-host"
                value={host}
                placeholder="example.com or 10.0.0.5"
                autoFocus
                onChange={(e) => setHost(e.target.value)}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ssh-port">Port</Label>
              <Input
                id="ssh-port"
                value={port}
                inputMode="numeric"
                onChange={(e) => setPort(e.target.value)}
              />
            </div>
          </div>

          <div className="grid gap-1.5">
            <Label htmlFor="ssh-user">User</Label>
            <Input
              id="ssh-user"
              value={user}
              placeholder="root"
              onChange={(e) => setUser(e.target.value)}
            />
          </div>

          <div className="grid gap-1.5">
            <Label>Authentication</Label>
            <Select
              value={method}
              onValueChange={(v) => setMethod(v as AuthMethod)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="agent">SSH agent</SelectItem>
                <SelectItem value="key">Private key file</SelectItem>
                <SelectItem value="password">Password</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {method === "key" ? (
            <>
              <div className="grid gap-1.5">
                <Label htmlFor="ssh-key">Private key path</Label>
                <Input
                  id="ssh-key"
                  value={keyPath}
                  placeholder="~/.ssh/id_ed25519"
                  onChange={(e) => setKeyPath(e.target.value)}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="ssh-passphrase">Passphrase (optional)</Label>
                <Input
                  id="ssh-passphrase"
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                />
              </div>
            </>
          ) : null}

          {method === "password" ? (
            <div className="grid gap-1.5">
              <Label htmlFor="ssh-password">Password</Label>
              <Input
                id="ssh-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          ) : null}

          <div className="grid gap-1.5">
            <Label htmlFor="ssh-label">Label (optional)</Label>
            <Input
              id="ssh-label"
              value={label}
              placeholder="prod-web"
              onChange={(e) => setLabel(e.target.value)}
            />
          </div>

          {error ? (
            <div className="rounded-sm bg-destructive/10 px-2 py-1.5 text-xs text-destructive">
              {error}
            </div>
          ) : null}
        </div>

        <DialogFooter>
          <Button
            variant="ghost"
            onClick={() => onOpenChange(false)}
            disabled={busy}
          >
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={!canConnect}>
            {busy ? "Connecting…" : "Connect"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
