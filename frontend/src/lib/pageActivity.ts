/**
 * pageActivity.ts
 * ===============
 * Tracks whether the current browser tab is actively being viewed.
 *
 * Live connections (Socket.io, SSE) keep the backend replay ticker running and
 * consume hosting bandwidth. A tab that has been hidden for longer than the
 * grace period is treated as inactive so those connections can be dropped,
 * and re-established as soon as the user returns.
 */

/** How long a tab may stay hidden before it is considered inactive. */
export const INACTIVE_GRACE_MS = 30_000;

export function isPageVisible(): boolean {
  return typeof document === "undefined" || document.visibilityState !== "hidden";
}

/**
 * Subscribe to active/inactive transitions of the current tab.
 * - `onInactive` fires once the tab has been hidden for `graceMs`.
 * - `onActive` fires when the tab becomes visible again after going inactive.
 * Returns an unsubscribe function.
 */
export function onPageActivityChange(
  onActive: () => void,
  onInactive: () => void,
  graceMs: number = INACTIVE_GRACE_MS,
): () => void {
  if (typeof document === "undefined") return () => {};

  let inactive = false;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const clearTimer = () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };

  const handleVisibility = () => {
    if (document.visibilityState === "hidden") {
      clearTimer();
      timer = setTimeout(() => {
        timer = null;
        inactive = true;
        onInactive();
      }, graceMs);
    } else {
      clearTimer();
      if (inactive) {
        inactive = false;
        onActive();
      }
    }
  };

  document.addEventListener("visibilitychange", handleVisibility);
  // Handle the case where subscription starts while the tab is already hidden
  if (document.visibilityState === "hidden") handleVisibility();

  return () => {
    clearTimer();
    document.removeEventListener("visibilitychange", handleVisibility);
  };
}
