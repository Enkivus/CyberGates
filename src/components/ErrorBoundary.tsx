import { Component, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

type ErrorBoundaryProps = { children: ReactNode };
type ErrorBoundaryState = { hasError: boolean };

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <main className="grid h-full place-items-center bg-canvas p-6 text-ink">
          <section
            className="w-full max-w-lg rounded-2xl border border-danger/30 bg-surface p-6 shadow-xl"
            role="alert"
          >
            <div className="mb-4 grid h-10 w-10 place-items-center rounded-xl bg-danger-soft text-danger">
              <AlertTriangle className="h-5 w-5" aria-hidden />
            </div>
            <h1 className="text-lg font-semibold">This view could not load</h1>
            <p className="mt-2 text-sm leading-relaxed text-muted">
              CyberGates encountered an unexpected display error. Try loading the view
              again. Your saved local data has not been changed by this error screen.
            </p>
            <button
              type="button"
              className="btn btn-primary mt-5"
              onClick={() => this.setState({ hasError: false })}
            >
              <RefreshCw className="h-4 w-4" aria-hidden />
              Try again
            </button>
          </section>
        </main>
      );
    }

    return this.props.children;
  }
}
