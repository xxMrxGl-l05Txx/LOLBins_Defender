import React from "react";

interface PageHeaderProps {
  eyebrow?: React.ReactNode;
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}

export const PageHeader = ({ eyebrow, title, description, actions }: PageHeaderProps) => (
  <div className="flex flex-wrap items-end justify-between gap-4 pb-6">
    <div className="min-w-0">
      {eyebrow && <div className="label-caps mb-1.5 font-mono normal-case tracking-normal">{eyebrow}</div>}
      <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
      {description && <p className="mt-1 max-w-2xl text-[13px] text-muted-foreground">{description}</p>}
    </div>
    {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
  </div>
);
