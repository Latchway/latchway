import type { RefObject } from "react";

/** Reads and clears a password input in one step. */
export function takePassword(inputRef: RefObject<HTMLInputElement | null>): string {
  const value = inputRef.current?.value ?? "";
  if (inputRef.current) inputRef.current.value = "";
  return value;
}
