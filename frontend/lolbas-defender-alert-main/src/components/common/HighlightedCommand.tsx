import { useMemo } from "react";
import { highlightParts } from "@/lib/highlight";
import { cn } from "@/lib/utils";
import { CopyButton } from "./CopyButton";

interface HighlightedCommandProps {
  command: string;
  patterns?: string[];
  className?: string;
}

/** Command line in a code block with the suspicious patterns marked */
export const HighlightedCommand = ({ command, patterns = [], className }: HighlightedCommandProps) => {
  const parts = useMemo(() => highlightParts(command, patterns), [command, patterns]);

  return (
    <div className={cn("group relative", className)}>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/40 p-3 pr-10 font-mono text-xs leading-relaxed">
        {parts.map((part, index) =>
          part.match ? (
            <mark key={index} className="rounded-[2px] bg-sev-high/20 px-0.5 text-sev-high">
              {part.text}
            </mark>
          ) : (
            <span key={index}>{part.text}</span>
          )
        )}
      </pre>
      <CopyButton value={command} label="Copy command" className="absolute right-1.5 top-1.5 opacity-60 group-hover:opacity-100" />
    </div>
  );
};
