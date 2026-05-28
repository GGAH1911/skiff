import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { IS_WINDOWS } from "@/lib/platform";
import {
  LOCAL_WORKSPACE,
  SshConnectDialog,
  useWorkspaceEnvStore,
  type WorkspaceEnv,
} from "@/modules/workspace";
import {
  Cancel01Icon,
  PlusSignIcon,
  Refresh01Icon,
  ServerStack03Icon,
} from "@hugeicons/core-free-icons";
import { HugeiconsIcon } from "@hugeicons/react";
import { useState } from "react";

type Props = {
  onSelect: (env: WorkspaceEnv) => void;
};

export function WorkspaceEnvSelector({ onSelect }: Props) {
  const env = useWorkspaceEnvStore((s) => s.env);
  const distros = useWorkspaceEnvStore((s) => s.distros);
  const sshConns = useWorkspaceEnvStore((s) => s.sshConns);
  const loading = useWorkspaceEnvStore((s) => s.loading);
  const error = useWorkspaceEnvStore((s) => s.error);
  const refreshDistros = useWorkspaceEnvStore((s) => s.refreshDistros);
  const refreshSshConns = useWorkspaceEnvStore((s) => s.refreshSshConns);
  const disconnectSsh = useWorkspaceEnvStore((s) => s.disconnectSsh);

  const [dialogOpen, setDialogOpen] = useState(false);

  const handleOpenChange = (open: boolean) => {
    if (!open) return;
    void refreshSshConns();
    if (IS_WINDOWS && distros.length === 0 && !loading) {
      void refreshDistros();
    }
  };

  const localLabel = IS_WINDOWS ? "Windows" : "Local";
  let label = localLabel;
  if (env.kind === "wsl") label = `WSL: ${env.distro}`;
  else if (env.kind === "ssh") {
    const active = sshConns.find((c) => c.id === env.conn);
    label = active ? active.label : env.conn;
  }

  return (
    <>
      <DropdownMenu onOpenChange={handleOpenChange}>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            className="flex h-6 shrink-0 items-center gap-1 rounded-sm px-1.5 text-[11px] text-muted-foreground outline-none hover:bg-accent hover:text-foreground focus:outline-none focus-visible:outline-none focus-visible:ring-0 data-[state=open]:bg-accent data-[state=open]:text-foreground"
            title="Workspace environment"
          >
            <HugeiconsIcon
              icon={ServerStack03Icon}
              size={13}
              strokeWidth={1.75}
            />
            <span className="max-w-28 truncate">{label}</span>
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="min-w-52">
          <DropdownMenuItem onSelect={() => onSelect(LOCAL_WORKSPACE)}>
            {IS_WINDOWS ? "Windows Local" : "Local"}
          </DropdownMenuItem>

          {IS_WINDOWS ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuLabel className="text-[10px] uppercase tracking-wide text-muted-foreground">
                WSL
              </DropdownMenuLabel>
              {distros.length === 0 ? (
                <DropdownMenuItem disabled>
                  {loading
                    ? "Loading WSL distros..."
                    : error
                      ? "WSL unavailable"
                      : "No WSL distros found"}
                </DropdownMenuItem>
              ) : (
                distros.map((distro) => (
                  <DropdownMenuItem
                    key={distro.name}
                    onSelect={() =>
                      onSelect({ kind: "wsl", distro: distro.name })
                    }
                  >
                    WSL: {distro.name}
                  </DropdownMenuItem>
                ))
              )}
              <DropdownMenuItem onSelect={() => void refreshDistros()}>
                <HugeiconsIcon
                  icon={Refresh01Icon}
                  size={13}
                  strokeWidth={1.75}
                />
                Refresh WSL
              </DropdownMenuItem>
            </>
          ) : null}

          <DropdownMenuSeparator />
          <DropdownMenuLabel className="text-[10px] uppercase tracking-wide text-muted-foreground">
            SSH
          </DropdownMenuLabel>
          {sshConns.map((conn) => (
            <DropdownMenuItem
              key={conn.id}
              className="flex items-center justify-between gap-2"
              onSelect={() => onSelect({ kind: "ssh", conn: conn.id })}
            >
              <span className="truncate">{conn.label}</span>
              <button
                type="button"
                title="Disconnect"
                className="shrink-0 rounded-sm p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  void disconnectSsh(conn.id);
                }}
              >
                <HugeiconsIcon icon={Cancel01Icon} size={12} strokeWidth={2} />
              </button>
            </DropdownMenuItem>
          ))}
          <DropdownMenuItem onSelect={() => setDialogOpen(true)}>
            <HugeiconsIcon icon={PlusSignIcon} size={13} strokeWidth={1.75} />
            Connect to SSH…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <SshConnectDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        onConnected={(info) => onSelect({ kind: "ssh", conn: info.id })}
      />
    </>
  );
}
