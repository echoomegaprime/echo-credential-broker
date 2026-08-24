import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium tracking-wide",
  {
    variants: {
      tone: {
        default: "bg-bg-subtle text-muted shadow-[0_0_0_1px_var(--color-border)]",
        healthy: "bg-healthy/15 text-healthy",
        warn: "bg-warn/15 text-warn",
        danger: "bg-danger/15 text-danger",
        accent: "bg-accent/15 text-accent",
      },
    },
    defaultVariants: { tone: "default" },
  },
);

export function Badge({
  className,
  tone,
  ...props
}: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
