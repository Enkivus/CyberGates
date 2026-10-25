import { useEffect, useRef } from "react";
import { AlertTriangle } from "lucide-react";

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Continue",
  cancelLabel = "Cancel",
  destructive = false,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const onCancelRef = useRef(onCancel);

  useEffect(() => {
    onCancelRef.current = onCancel;
  }, [onCancel]);

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    cancelRef.current?.focus();

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancelRef.current();
      } else if (event.key === "Tab") {
        const cancel = cancelRef.current;
        const confirm = confirmRef.current;
        if (event.shiftKey && document.activeElement === cancel) {
          event.preventDefault();
          confirm?.focus();
        } else if (!event.shiftKey && document.activeElement === confirm) {
          event.preventDefault();
          cancel?.focus();
        }
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      previouslyFocused?.focus();
    };
  }, [open]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[70] grid place-items-center bg-[var(--modal)] p-4"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <section
        className="w-full max-w-md rounded-2xl border border-line bg-surface p-5 shadow-2xl"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-description"
      >
        <div className="mb-4 flex items-start gap-3">
          <div className={`grid h-9 w-9 shrink-0 place-items-center rounded-xl ${destructive ? "bg-danger-soft text-danger" : "bg-warn-soft text-warn"}`}>
            <AlertTriangle className="h-4 w-4" aria-hidden />
          </div>
          <div>
            <h2 id="confirm-dialog-title" className="text-sm font-semibold text-ink">
              {title}
            </h2>
            <p id="confirm-dialog-description" className="mt-1 text-xs leading-relaxed text-muted">
              {description}
            </p>
          </div>
        </div>
        <div className="flex justify-end gap-2">
          <button ref={cancelRef} type="button" className="btn btn-sm" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            ref={confirmRef}
            type="button"
            className={`btn btn-sm ${destructive ? "btn-danger" : "btn-primary"}`}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}
