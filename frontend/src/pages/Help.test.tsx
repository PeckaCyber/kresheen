import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { HelpPage } from "./Help";

function open(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/help/:topic?" element={<HelpPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("HelpPage", () => {
  it("opens the first topic by default and lists every section in the sidebar", () => {
    open("/help");
    expect(screen.getByRole("heading", { name: "What this tool does" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Editing the diagram" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Audit log" })).toBeInTheDocument();
  });

  it("shows the requested topic with previous and next links", () => {
    open("/help/diagram");
    expect(screen.getByRole("heading", { name: "Editing the diagram" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^← The Dashboard/ })).toHaveAttribute("href", "/help/dashboard");
    expect(screen.getByRole("link", { name: /^Reading the results →/ })).toHaveAttribute("href", "/help/results");
  });

  it("falls back to the first topic for an unknown one", () => {
    open("/help/nope");
    expect(screen.getByRole("heading", { name: "What this tool does" })).toBeInTheDocument();
  });
});
