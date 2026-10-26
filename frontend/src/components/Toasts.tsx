import { createContext, ReactNode, useCallback, useContext, useMemo, useState } from "react";
import { Toast, ToastContainer } from "react-bootstrap";

interface ToastMessage {
  id: string;
  message: string;
  type: "success" | "error";
}

interface ToastContextValue {
  success: (message: string) => void;
  error: (message: string) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const addToast = useCallback((message: string, type: "success" | "error") => {
    const id = Math.random().toString(36).slice(2);
    const newToast: ToastMessage = { id, message, type };
    setToasts((prev) => [...prev, newToast].slice(-3)); // Keep max 3 toasts

    // Auto-hide based on type
    const delay = type === "success" ? 4000 : 8000;
    const timer = setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, delay);

    return () => clearTimeout(timer);
  }, []);

  const value: ToastContextValue = useMemo(
    () => ({
      success: (message: string) => addToast(message, "success"),
      error: (message: string) => addToast(message, "error"),
    }),
    [addToast],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastContainer position="bottom-end" className="p-3">
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            show
            bg={toast.type === "success" ? "success" : "danger"}
            role="status"
            aria-live="polite"
          >
            <Toast.Body className={toast.type === "success" ? "text-white" : "text-white"}>{toast.message}</Toast.Body>
          </Toast>
        ))}
      </ToastContainer>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) {
    // Return no-op object when used outside provider (e.g., in tests)
    return {
      success: () => {},
      error: () => {},
    };
  }
  return context;
}
