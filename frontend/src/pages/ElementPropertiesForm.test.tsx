import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ElementPropertiesForm, type PropertySpec } from "./ElementPropertiesForm";

const SPECS: PropertySpec[] = [
  { key: "is_encrypted", label: "Encrypted at rest", kind: "bool", help: "" },
  { key: "stores_credentials", label: "Stores credentials", kind: "bool", help: "Passwords, keys or tokens." },
  { key: "out_of_scope_reason", label: "Reason out of scope", kind: "text", help: "" },
];

describe("ElementPropertiesForm", () => {
  it("shows a tri-state control per boolean, starting from what is stated", () => {
    render(<ElementPropertiesForm specs={SPECS} value={{ is_encrypted: false }} onSave={vi.fn()} />);

    expect(screen.getByLabelText("Encrypted at rest")).toHaveValue("no");
    expect(screen.getByLabelText("Stores credentials")).toHaveValue("");
    expect(screen.getByText("Passwords, keys or tokens.")).toBeInTheDocument();
  });

  it("saves only what was stated: Unknown removes the key, Yes/No set it, empty text is dropped", async () => {
    const onSave = vi.fn();
    render(<ElementPropertiesForm specs={SPECS} value={{ is_encrypted: false }} onSave={onSave} />);

    fireEvent.change(screen.getByLabelText("Encrypted at rest"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Stores credentials"), { target: { value: "yes" } });
    fireEvent.change(screen.getByLabelText("Reason out of scope"), { target: { value: "Owned elsewhere" } });
    fireEvent.click(screen.getByRole("button", { name: "Save properties" }));

    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(1));
    expect(onSave).toHaveBeenCalledWith({ stores_credentials: true, out_of_scope_reason: "Owned elsewhere" });

    fireEvent.change(screen.getByLabelText("Reason out of scope"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save properties" }));
    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(2));
    expect(onSave).toHaveBeenLastCalledWith({ stores_credentials: true });
  });

  it("resets its draft when the stated properties change underneath it", () => {
    const { rerender } = render(<ElementPropertiesForm specs={SPECS} value={{}} onSave={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Encrypted at rest"), { target: { value: "yes" } });

    rerender(<ElementPropertiesForm specs={SPECS} value={{ is_encrypted: false }} onSave={vi.fn()} />);

    expect(screen.getByLabelText("Encrypted at rest")).toHaveValue("no");
  });

  it("read-only mode lists only the stated properties, and nothing when none are stated", () => {
    const { rerender, container } = render(
      <ElementPropertiesForm
        specs={SPECS}
        value={{ is_encrypted: true, out_of_scope_reason: "Vendor" }}
        readOnly
        onSave={vi.fn()}
      />,
    );

    expect(screen.getByText("Encrypted at rest: Yes")).toBeInTheDocument();
    expect(screen.getByText("Reason out of scope: Vendor")).toBeInTheDocument();
    expect(screen.queryByText(/Stores credentials/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save properties" })).not.toBeInTheDocument();

    rerender(<ElementPropertiesForm specs={SPECS} value={{}} readOnly onSave={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for an element type with no specs", () => {
    const { container } = render(<ElementPropertiesForm specs={[]} value={{}} onSave={vi.fn()} />);

    expect(container).toBeEmptyDOMElement();
  });
});
