import { useCallback, useRef, useState } from "react";

// Undo/redo for DFD edit mode. Every DFD edit is already a persisted API
// call against Application-scoped overlay data, so history is a stack of
// commands whose undo/redo issue the *inverse API call* -- never a rewind
// of local React state, which would desync from what's persisted.
export interface HistoryCommand {
  label: string;
  undo: () => Promise<void>;
  redo: () => Promise<void>;
}

interface Options {
  onError: (message: string) => void;
  // Called after every undo/redo attempt, success or failure, so the diagram
  // is re-fetched from the server and reflects what is actually persisted.
  onSettled: () => Promise<unknown> | void;
}

export function useEditHistory({ onError, onSettled }: Options) {
  const undoStack = useRef<HistoryCommand[]>([]);
  const redoStack = useRef<HistoryCommand[]>([]);
  // Undo/redo mutate server state; overlapping runs (a held-down Ctrl-Z)
  // would interleave inverse calls out of order.
  const busy = useRef(false);
  const [, setVersion] = useState(0);
  const bump = () => setVersion((v) => v + 1);

  // Call only after the edit itself succeeded. A new edit invalidates redo.
  const record = useCallback((command: HistoryCommand) => {
    undoStack.current.push(command);
    redoStack.current = [];
    bump();
  }, []);

  const run = useCallback(
    async (from: HistoryCommand[], to: HistoryCommand[], direction: "undo" | "redo") => {
      if (busy.current || from.length === 0) return;
      busy.current = true;
      const command = from.pop() as HistoryCommand;
      try {
        await command[direction]();
        to.push(command);
      } catch (err) {
        // The command is dropped rather than retried: its inverse no longer
        // applies cleanly (e.g. the row was already changed elsewhere).
        onError(err instanceof Error ? err.message : `Could not ${direction} "${command.label}".`);
      } finally {
        busy.current = false;
        bump();
        await onSettled();
      }
    },
    [onError, onSettled],
  );

  const undo = useCallback(() => run(undoStack.current, redoStack.current, "undo"), [run]);
  const redo = useCallback(() => run(redoStack.current, undoStack.current, "redo"), [run]);

  const clear = useCallback(() => {
    undoStack.current = [];
    redoStack.current = [];
    bump();
  }, []);

  return {
    record,
    undo,
    redo,
    clear,
    canUndo: undoStack.current.length > 0,
    canRedo: redoStack.current.length > 0,
    undoLabel: undoStack.current.at(-1)?.label ?? null,
    redoLabel: redoStack.current.at(-1)?.label ?? null,
  };
}

// True when a keystroke is headed to a text field, where the browser's own
// undo must win over DFD undo.
export function isTextEntryTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}
