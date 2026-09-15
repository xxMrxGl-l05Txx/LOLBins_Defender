import { cn } from "@/lib/utils";

/** Terminal-prompt mark: a command line being watched */
export const LogoMark = ({ className }: { className?: string }) => (
  <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
    <rect x="2.75" y="2.75" width="18.5" height="18.5" rx="4" stroke="currentColor" strokeWidth="1.5" />
    <path d="M7.5 9l3 3-3 3" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M12.5 15.25h4" stroke="hsl(var(--brand))" strokeWidth="1.75" strokeLinecap="round" />
  </svg>
);

export const Wordmark = ({ className }: { className?: string }) => (
  <div className={cn("flex items-center gap-2.5", className)}>
    <LogoMark className="h-6 w-6 text-foreground" />
    <div className="leading-none">
      <div className="text-[13px] font-semibold tracking-tight">LOLBins Defender</div>
      <div className="mt-1 font-mono text-[10px] text-muted-foreground">endpoint console</div>
    </div>
  </div>
);
