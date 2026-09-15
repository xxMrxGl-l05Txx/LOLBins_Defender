import React from "react";
import { cn } from "@/lib/utils";

export const Kbd = ({ className, ...props }: React.HTMLAttributes<HTMLElement>) => (
  <kbd
    className={cn(
      "pointer-events-none inline-flex h-5 select-none items-center rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground",
      className
    )}
    {...props}
  />
);
