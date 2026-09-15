import { cn } from "@/lib/utils";

interface MeterProps {
  value: number | null | undefined;
  className?: string;
  /** Override the automatic usage color */
  toneClassName?: string;
}

export const Meter = ({ value, className, toneClassName }: MeterProps) => {
  const percent = Math.max(0, Math.min(100, value ?? 0));
  const tone = toneClassName ?? (percent >= 90 ? "bg-sev-critical" : percent >= 75 ? "bg-sev-medium" : "bg-ok");

  return (
    <div
      className={cn("h-1 w-full overflow-hidden rounded-full bg-muted", className)}
      role="meter"
      aria-valuenow={Math.round(percent)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div className={cn("h-full rounded-full transition-[width] duration-500", tone)} style={{ width: `${percent}%` }} />
    </div>
  );
};
