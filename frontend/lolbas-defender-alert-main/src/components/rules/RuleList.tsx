import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, ChevronRight } from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/common/EmptyState";
import { Panel } from "@/components/common/Panel";
import { SeverityBadge } from "@/components/alerts/AlertBadges";
import { api, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { DetectionRule } from "@/types";

const RuleRow = ({ rule }: { rule: DetectionRule }) => {
  const [open, setOpen] = useState(false);

  return (
    <Collapsible open={open} onOpenChange={setOpen} asChild>
      <li className="border-b last:border-0">
        <CollapsibleTrigger className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-accent/40">
          <ChevronRight className={cn("h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />
          <span className="w-40 shrink-0 font-mono text-[13px]">{rule.binary}</span>
          <span className="hidden flex-1 truncate text-xs text-muted-foreground sm:block">{rule.description}</span>
          <span className="ml-auto flex shrink-0 items-center gap-3">
            <span className="font-mono text-2xs text-muted-foreground">{rule.command_patterns.length} patterns</span>
            <SeverityBadge severity={rule.severity} />
          </span>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="space-y-3 px-4 pb-4 pl-11">
            <p className="text-[13px] text-muted-foreground sm:hidden">{rule.description}</p>
            <div>
              <div className="label-caps mb-1.5">Command patterns</div>
              <div className="flex flex-wrap gap-1.5">
                {rule.command_patterns.map((pattern) => (
                  <code key={pattern} className="rounded border bg-background px-1.5 py-0.5 font-mono text-2xs">{pattern}</code>
                ))}
              </div>
            </div>
            {rule.parent_process_hints.length > 0 && (
              <div>
                <div className="label-caps mb-1.5">Typically launched from</div>
                <div className="flex flex-wrap gap-1.5">
                  {rule.parent_process_hints.map((hint) => (
                    <code key={hint} className="rounded border bg-background px-1.5 py-0.5 font-mono text-2xs text-muted-foreground">{hint}</code>
                  ))}
                </div>
              </div>
            )}
            {rule.mitre_attack_id && (
              <a
                href={rule.mitre_link ?? "#"}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
              >
                <span className="font-mono">{rule.mitre_attack_id}</span> on attack.mitre.org
                <ArrowUpRight className="h-3 w-3" />
              </a>
            )}
          </div>
        </CollapsibleContent>
      </li>
    </Collapsible>
  );
};

const RuleList = () => {
  const { data: rules, isLoading, isError, error } = useQuery({
    queryKey: ["rules"],
    queryFn: api.getRules,
    retry: false,
  });

  return (
    <Panel
      flush
      title="Detection rules"
      description={rules ? `${rules.length} LOLBin${rules.length === 1 ? "" : "s"} monitored` : "LOLBins monitored"}
    >
      {isLoading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 6 }).map((_, index) => <Skeleton key={index} className="h-8 w-full" />)}
        </div>
      ) : isError ? (
        <EmptyState title="Could not load rules" description={errorMessage(error, "The backend is unreachable.")} />
      ) : !rules || rules.length === 0 ? (
        <EmptyState title="No rules configured" />
      ) : (
        <ul>
          {rules.map((rule) => <RuleRow key={rule.binary} rule={rule} />)}
        </ul>
      )}
    </Panel>
  );
};

export default RuleList;
