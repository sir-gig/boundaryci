import { useState } from "react";

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1_800);
  }

  return (
    <button className="button button-secondary button-small" type="button" onClick={() => void copy()}>
      {copied ? "Copied" : label}
    </button>
  );
}
