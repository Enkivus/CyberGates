import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";

type ToastTone = "success" | "error" | "info" | "warning";
type ToastMessage = { id: number; message: string; tone: ToastTone };
type ToastContextValue = { showToast: (message: string, tone?: ToastTone) => void };

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const nextId = useRef(1);

  const dismissToast = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const showToast = useCallback((message: string, tone: ToastTone = "info") => {
    const id = nextId.current++;
    setToasts((current) => [...current.slice(-3), { id, message, tone }]);
  }, []);

  const contextValue = useMemo(() => ({ showToast }), [showToast]);

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <div
        className="pointer-events-none fixed right-4 top-4 z-[100] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2"
        aria-label="Notifications"
      >
        {toasts.map((toast) => (
          <Toast key={toast.id} toast={toast} onDismiss={dismissToast} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

function Toast({
  toast,
  onDismiss,
}: {
  toast: ToastMessage;
  onDismiss: (id: number) => void;
}) {
  const Icon =
    toast.tone === "success"
      ? CheckCircle2
      : toast.tone === "error"
        ? XCircle
        : toast.tone === "warning"
          ? AlertTriangle
          : Info;
  const color =
    toast.tone === "success"
      ? "text-ok"
      : toast.tone === "error"
        ? "text-danger"
        : toast.tone === "warning"
          ? "text-warn"
          : "text-info";

  return (
    <div
      className="pointer-events-auto flex items-start gap-3 rounded-xl border border-line bg-surface px-4 py-3 shadow-xl"
      role={toast.tone === "error" ? "alert" : "status"}
      aria-live={toast.tone === "error" ? "assertive" : "polite"}
    >
      <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${color}`} aria-hidden />
      <p className="min-w-0 flex-1 break-words text-xs leading-relaxed text-ink">
        {toast.message}
      </p>
      <button
        type="button"
        className="rounded p-0.5 text-faint hover:bg-surface-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-accent"
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss notification"
      >
        <X className="h-3.5 w-3.5" aria-hidden />
      </button>
      <ToastExpiry id={toast.id} onDismiss={onDismiss} />
    </div>
  );
}

function ToastExpiry({ id, onDismiss }: { id: number; onDismiss: (id: number) => void }) {
  useEffect(() => {
    const timeout = window.setTimeout(() => onDismiss(id), 5000);
    return () => window.clearTimeout(timeout);
  }, [id, onDismiss]);
  return null;
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used within ToastProvider");
  return context;
}
