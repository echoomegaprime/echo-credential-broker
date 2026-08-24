import { useEffect, useState } from "react";
import { Check, Copy, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const APPS = [
  {
    id: "grok",
    name: "Grok",
    caller: "grok",
    blurb: "GitHub app for the repo, then HTTP MCP in Grok connectors.",
    github: "https://github.com/apps/grok-by-xai/installations/new",
  },
  {
    id: "gpt",
    name: "GPT / Codex",
    caller: "chatgpt",
    blurb: "Codex GitHub app, then Custom GPT Action or Developer Mode MCP.",
    github: "https://github.com/apps/chatgpt-codex-connector/installations/new",
  },
  {
    id: "claude",
    name: "Claude",
    caller: "claude",
    blurb: "Claude GitHub app, then Desktop stdio or Claude Code .mcp.json.",
    github: "https://github.com/apps/claude/installations/new",
  },
] as const;

function CopyBlock({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="grid gap-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs uppercase tracking-wide text-muted">{label}</p>
        <Button
          type="button"
          variant="ghost"
          className="h-8 px-2 text-xs"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1400);
            } catch {
              /* clipboard blocked */
            }
          }}
        >
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <pre className="max-h-64 overflow-auto rounded-md bg-bg p-3 font-mono text-[11px] leading-relaxed text-fg shadow-[0_0_0_1px_var(--color-border)]">
        {value}
      </pre>
    </div>
  );
}

export function InstallPanel() {
  const [origin, setOrigin] = useState("https://YOUR-HOST");
  useEffect(() => {
    setOrigin(window.location.origin);
  }, []);

  const grokHttp = JSON.stringify(
    {
      mcpServers: {
        "echo-credential-broker": {
          type: "http",
          url: `${origin}/api/mcp`,
          headers: { "x-echo-agent": "grok" },
        },
      },
    },
    null,
    2,
  );

  const gptAction = `Import OpenAPI: ${origin}/install/chatgpt.openapi.json
Server: ${origin}
Header: x-echo-agent = chatgpt
MCP URL: ${origin}/api/mcp`;

  const claudeDesktop = JSON.stringify(
    {
      mcpServers: {
        "echo-credential-broker": {
          command: "node",
          args: ["--experimental-strip-types", "scripts/mcp-stdio.ts"],
          cwd: "/ABSOLUTE/PATH/TO/echo-credential-broker",
          env: { ECHO_AGENT: "claude" },
        },
      },
    },
    null,
    2,
  );

  const clone = `git clone https://github.com/echoomegaprime/echo-credential-broker.git
cd echo-credential-broker
npm install
cp .env.example .env
npm run mcp`;

  return (
    <div className="grid gap-4">
      <Card className="p-5">
        <CardHeader>
          <CardTitle>Clone once — three clients</CardTitle>
          <CardDescription>
            Same broker. Secrets stay in env. Chat only ever sees vault:// handles.
          </CardDescription>
        </CardHeader>
        <CopyBlock label="Repo" value={clone} />
        <p className="mt-3 text-sm text-muted">
          Source:{" "}
          <a
            className="text-fg underline-offset-2 hover:underline"
            href="https://github.com/echoomegaprime/echo-credential-broker"
            target="_blank"
            rel="noreferrer"
          >
            echoomegaprime/echo-credential-broker
          </a>
        </p>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        {APPS.map((app) => (
          <Card key={app.id} className="flex flex-col gap-3 p-5">
            <CardHeader>
              <CardTitle>{app.name}</CardTitle>
              <CardDescription>{app.blurb}</CardDescription>
            </CardHeader>
            <a
              href={app.github}
              target="_blank"
              rel="noreferrer"
              className="inline-flex min-h-11 items-center justify-center gap-2 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground"
            >
              Install GitHub app
              <ExternalLink className="size-3.5" />
            </a>
            <p className="font-mono text-[11px] text-subtle">x-echo-agent: {app.caller}</p>
          </Card>
        ))}
      </div>

      <Card className="p-5">
        <CardHeader>
          <CardTitle>Grok MCP</CardTitle>
          <CardDescription>
            Settings → Connectors → add MCP. Header is required.
          </CardDescription>
        </CardHeader>
        <CopyBlock label="HTTP connector" value={grokHttp} />
      </Card>

      <Card className="p-5">
        <CardHeader>
          <CardTitle>GPT Action / MCP</CardTitle>
          <CardDescription>
            Custom GPT Actions import the OpenAPI. Developer Mode uses the MCP URL.
          </CardDescription>
        </CardHeader>
        <CopyBlock label="ChatGPT" value={gptAction} />
      </Card>

      <Card className="p-5">
        <CardHeader>
          <CardTitle>Claude Desktop / Code</CardTitle>
          <CardDescription>
            Merge into claude_desktop_config.json, then restart. Claude Code reads
            .mcp.json in the repo.
          </CardDescription>
        </CardHeader>
        <CopyBlock label="claude_desktop_config.json" value={claudeDesktop} />
        <div className="mt-3">
          <CopyBlock
            label="Claude Code"
            value="claude mcp add echo-credential-broker --env ECHO_AGENT=claude -- node --experimental-strip-types scripts/mcp-stdio.ts"
          />
        </div>
      </Card>
    </div>
  );
}
