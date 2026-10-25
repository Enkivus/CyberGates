import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search } from "lucide-react";
import { searchNavItems } from "./navigation";

export function CommandPalette() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const results = useMemo(() => searchNavItems(query), [query]);

  useEffect(() => {
    function handleGlobalKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen(true);
      }
    }

    window.addEventListener("keydown", handleGlobalKeyDown);
    return () => window.removeEventListener("keydown", handleGlobalKeyDown);
  }, []);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setActiveIndex(0);
    inputRef.current?.focus();
  }, [open]);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  function close() {
    setOpen(false);
    triggerRef.current?.focus();
  }

  function select(path: string) {
    navigate(path);
    close();
  }

  function handleInputKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
    } else if (event.key === "ArrowDown" && results.length > 0) {
      event.preventDefault();
      setActiveIndex((index) => (index + 1) % results.length);
    } else if (event.key === "ArrowUp" && results.length > 0) {
      event.preventDefault();
      setActiveIndex((index) => (index - 1 + results.length) % results.length);
    } else if (event.key === "Enter" && results[activeIndex]) {
      event.preventDefault();
      select(results[activeIndex].to);
    }
  }

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className="btn btn-sm min-w-[190px] justify-between text-muted"
        onClick={() => setOpen(true)}
        aria-haspopup="dialog"
        aria-label="Search sections"
      >
        <span className="flex items-center gap-2">
          <Search className="h-4 w-4" aria-hidden />
          <span>Search sections</span>
        </span>
        <kbd className="rounded border border-line px-1.5 py-0.5 text-[10px] text-faint">
          ⌘ / Ctrl K
        </kbd>
      </button>

      {open ? (
        <div
          className="fixed inset-0 z-[60] flex items-start justify-center bg-[var(--modal)] px-4 pt-[14vh]"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) close();
          }}
        >
          <section
            className="w-full max-w-xl overflow-hidden rounded-xl border border-line bg-surface shadow-2xl"
            role="dialog"
            aria-modal="true"
            aria-labelledby="command-palette-title"
          >
            <h2 id="command-palette-title" className="sr-only">
              Search sections
            </h2>
            <div className="flex items-center gap-3 border-b border-line px-4">
              <Search className="h-4 w-4 shrink-0 text-muted" aria-hidden />
              <input
                ref={inputRef}
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={handleInputKeyDown}
                placeholder="Search sections..."
                className="h-14 min-w-0 flex-1 bg-transparent text-sm text-ink outline-none placeholder:text-faint"
                role="combobox"
                aria-label="Search sections"
                aria-autocomplete="list"
                aria-expanded="true"
                aria-controls="command-palette-results"
                aria-activedescendant={results[activeIndex] ? `command-result-${activeIndex}` : undefined}
              />
              <kbd className="hidden text-[10px] text-faint sm:block">
                Enter to open
              </kbd>
            </div>
            <ul
              id="command-palette-results"
              role="listbox"
              aria-label="Sections"
              className="max-h-[min(55vh,420px)] overflow-y-auto p-2"
            >
              {results.length ? (
                results.map((item, index) => {
                  const Icon = item.icon;
                  return (
                    <li
                      key={item.to}
                      id={`command-result-${index}`}
                      role="option"
                      aria-selected={index === activeIndex}
                      className={`flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2.5 text-sm ${
                        index === activeIndex
                          ? "bg-accent-soft text-accent-strong"
                          : "text-ink hover:bg-surface-2"
                      }`}
                      onMouseEnter={() => setActiveIndex(index)}
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={() => select(item.to)}
                    >
                      <Icon className="h-4 w-4 shrink-0" aria-hidden />
                      <span className="flex-1">{item.label}</span>
                      <span className="text-xs text-faint">{item.group}</span>
                    </li>
                  );
                })
              ) : (
                <li className="px-3 py-8 text-center text-sm text-muted" role="status">
                  No sections match “{query}”.
                </li>
              )}
            </ul>
            <div className="flex justify-between border-t border-line px-4 py-2 text-[10px] text-faint">
              <span>Navigate to a section</span>
              <span>↑ ↓ to move · Esc to close</span>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}
