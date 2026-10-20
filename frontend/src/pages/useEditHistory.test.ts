import { renderHook, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, type Mock } from "vitest";
import { useEditHistory, isTextEntryTarget, type HistoryCommand } from "./useEditHistory";

describe("useEditHistory", () => {
  let onError: Mock<(message: string) => void>;
  let onSettled: Mock<() => void>;
  let commandA: HistoryCommand;
  let commandB: HistoryCommand;

  beforeEach(() => {
    onError = vi.fn();
    onSettled = vi.fn().mockResolvedValue(undefined);
    commandA = { label: "A", undo: vi.fn().mockResolvedValue(undefined), redo: vi.fn().mockResolvedValue(undefined) };
    commandB = { label: "B", undo: vi.fn().mockResolvedValue(undefined), redo: vi.fn().mockResolvedValue(undefined) };
  });

  it("records then undos calls command.undo once, canUndo false, canRedo true, onSettled called", async () => {
    const { result } = renderHook(() => useEditHistory({ onError, onSettled }));
    act(() => {
      result.current.record(commandA);
    });
    expect(result.current.canUndo).toBe(true);
    expect(result.current.canRedo).toBe(false);

    await act(async () => {
      await result.current.undo();
    });

    expect(commandA.undo).toHaveBeenCalledTimes(1);
    expect(result.current.canUndo).toBe(false);
    expect(result.current.canRedo).toBe(true);
    expect(onSettled).toHaveBeenCalledTimes(1);
  });

  it("undo then redo calls command.redo, canUndo true again", async () => {
    const { result } = renderHook(() => useEditHistory({ onError, onSettled }));
    act(() => {
      result.current.record(commandA);
    });
    await act(async () => {
      await result.current.undo();
    });
    expect(commandA.undo).toHaveBeenCalledTimes(1);

    await act(async () => {
      await result.current.redo();
    });

    expect(commandA.redo).toHaveBeenCalledTimes(1);
    expect(result.current.canUndo).toBe(true);
    expect(result.current.canRedo).toBe(false);
  });

  it("recording a new command after an undo clears the redo stack (canRedo false)", async () => {
    const { result } = renderHook(() => useEditHistory({ onError, onSettled }));
    act(() => {
      result.current.record(commandA);
    });
    await act(async () => {
      await result.current.undo();
    });
    expect(result.current.canRedo).toBe(true);

    act(() => {
      result.current.record(commandB);
    });

    expect(result.current.canRedo).toBe(false);
  });

  it("undo/redo with empty stacks do nothing and do not call onSettled", async () => {
    const { result } = renderHook(() => useEditHistory({ onError, onSettled }));

    await act(async () => {
      await result.current.undo();
    });
    expect(onSettled).not.toHaveBeenCalled();

    await act(async () => {
      await result.current.redo();
    });
    expect(onSettled).not.toHaveBeenCalled();
  });

  it("commands undo in LIFO order (record a, b; undo twice; check call order via a shared array)", async () => {
    const calls: string[] = [];
    commandA.undo = vi.fn().mockImplementation(() => {
      calls.push("A");
      return Promise.resolve();
    });
    commandB.undo = vi.fn().mockImplementation(() => {
      calls.push("B");
      return Promise.resolve();
    });

    const { result } = renderHook(() => useEditHistory({ onError, onSettled }));
    act(() => {
      result.current.record(commandA);
      result.current.record(commandB);
    });
    expect(result.current.canUndo).toBe(true);

    await act(async () => {
      await result.current.undo();
    });
    await act(async () => {
      await result.current.undo();
    });

    expect(calls).toEqual(["B", "A"]);
  });

  it("if command.undo rejects with Error('boom'): onError called with 'boom', command is dropped (canUndo false AND canRedo false), onSettled still called", async () => {
    commandA.undo = vi.fn().mockRejectedValue(new Error("boom"));
    const { result } = renderHook(() => useEditHistory({ onError, onSettled }));
    act(() => {
      result.current.record(commandA);
    });

    await act(async () => {
      await result.current.undo();
    });

    expect(onError).toHaveBeenCalledWith("boom");
    expect(result.current.canUndo).toBe(false);
    expect(result.current.canRedo).toBe(false);
    expect(onSettled).toHaveBeenCalledTimes(1);
  });

  it("ignores an undo issued while another undo is still in flight", async () => {
    // Undo is LIFO, so B (recorded last) runs first; hold its promise open.
    let finishB: () => void = () => {};
    commandB.undo = vi.fn(() => new Promise<void>((resolve) => (finishB = resolve)));
    const { result } = renderHook(() => useEditHistory({ onError, onSettled }));
    act(() => {
      result.current.record(commandA);
      result.current.record(commandB);
    });

    let first!: Promise<void>;
    let second!: Promise<void>;
    await act(async () => {
      first = result.current.undo();
      second = result.current.undo();
      await second;
    });
    expect(commandB.undo).toHaveBeenCalledTimes(1);
    expect(commandA.undo).not.toHaveBeenCalled();

    await act(async () => {
      finishB();
      await first;
    });
    await act(async () => {
      await result.current.undo();
    });
    expect(commandA.undo).toHaveBeenCalledTimes(1);
  });

  it("clear() empties both stacks", async () => {
    const { result } = renderHook(() => useEditHistory({ onError, onSettled }));
    act(() => {
      result.current.record(commandA);
    });
    await act(async () => {
      await result.current.undo();
    });
    expect(result.current.canUndo).toBe(false);
    expect(result.current.canRedo).toBe(true);

    act(() => {
      result.current.clear();
    });

    expect(result.current.canUndo).toBe(false);
    expect(result.current.canRedo).toBe(false);
  });

  it("undoLabel/redoLabel reflect the top of each stack", async () => {
    const { result } = renderHook(() => useEditHistory({ onError, onSettled }));
    act(() => {
      result.current.record(commandA);
    });
    expect(result.current.undoLabel).toBe("A");
    expect(result.current.redoLabel).toBeNull();

    await act(async () => {
      await result.current.undo();
    });
    expect(result.current.undoLabel).toBeNull();
    expect(result.current.redoLabel).toBe("A");

    await act(async () => {
      await result.current.redo();
    });
    expect(result.current.undoLabel).toBe("A");
    expect(result.current.redoLabel).toBeNull();
  });

  it("isTextEntryTarget: true for an input, textarea, select element, false for a div and for null, and true for a div with contentEditable set", () => {
    const input = document.createElement("input");
    const textarea = document.createElement("textarea");
    const select = document.createElement("select");
    const div = document.createElement("div");
    const divContentEditable = document.createElement("div");

    Object.defineProperty(divContentEditable, "isContentEditable", { value: true });

    expect(isTextEntryTarget(input)).toBe(true);
    expect(isTextEntryTarget(textarea)).toBe(true);
    expect(isTextEntryTarget(select)).toBe(true);
    expect(isTextEntryTarget(div)).toBe(false);
    expect(isTextEntryTarget(null)).toBe(false);
    expect(isTextEntryTarget(divContentEditable)).toBe(true);
  });
});
