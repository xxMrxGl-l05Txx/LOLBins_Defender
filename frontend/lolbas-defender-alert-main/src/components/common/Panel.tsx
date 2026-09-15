import React from "react";
import { cn } from "@/lib/utils";

interface PanelProps extends Omit<React.HTMLAttributes<HTMLElement>, "title"> {
  title?: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  bodyClassName?: string;
  /** Remove body padding, e.g. for tables and lists that run edge to edge */
  flush?: boolean;
}

export const Panel = ({ title, description, actions, className, bodyClassName, flush, children, ...props }: PanelProps) => (
  <section className={cn("rounded-lg border bg-card", className)} {...props}>
    {(title || actions) && (
      <header className="flex items-start justify-between gap-3 border-b px-4 py-3">
        <div className="min-w-0">
          {title && <h2 className="text-[13px] font-medium leading-5">{title}</h2>}
          {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </header>
    )}
    <div className={cn(!flush && "p-4", bodyClassName)}>{children}</div>
  </section>
);
