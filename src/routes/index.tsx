import { createFileRoute } from "@tanstack/react-router";
import { VaultConsole } from "@/components/vault-console";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  return <VaultConsole />;
}
