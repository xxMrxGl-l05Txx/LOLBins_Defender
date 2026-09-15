import React from "react";
import { cn } from "@/lib/utils";

interface EmptyStateProps {
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}

export const EmptyState = ({ title, description, action, className }: EmptyStateProps) => (
  <div className={cn("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
    <div className="mb-3 flex h-8 w-8 items-center justify-center rounded-md border border-dashed">
      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/60" />
    </div>
    <p className="text-[13px] font-medium">{title}</p>
    {description && <p className="mt-1 max-w-sm text-xs text-muted-foreground">{description}</p>}
    {action && <div className="mt-4">{action}</div>}
  </div>
);
