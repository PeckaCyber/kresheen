import { useEffect, useRef, useState } from "react";
import { Modal, Form } from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import { apiFetch } from "../api/client";

interface PaletteItem {
  id: string;
  label: string;
  path: string;
  group: string;
}

interface Application {
  id: string;
  name: string;
}

// Help topic IDs and titles extracted from Help.tsx SECTIONS (read-only, not exported)
const HELP_TOPICS: Array<{ id: string; title: string }> = [
  { id: "overview", title: "What this tool does" },
  { id: "first-model", title: "Create your first threat model" },
  { id: "dashboard", title: "The Dashboard" },
  { id: "diagram", title: "Editing the diagram" },
  { id: "results", title: "Reading the results" },
  { id: "triage", title: "Triaging threats" },
  { id: "exports", title: "Exporting" },
  { id: "data-sources", title: "Data sources" },
  { id: "settings", title: "Settings" },
  { id: "audit-log", title: "Audit log" },
  { id: "teams", title: "Groups and access" },
  { id: "threat-kb", title: "Threat library" },
];

export function CommandPalette() {
  const [isOpen, setIsOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [items, setItems] = useState<PaletteItem[]>([]);
  const [filteredItems, setFilteredItems] = useState<PaletteItem[]>([]);
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const [loaded, setLoaded] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  // Initialize items
  useEffect(() => {
    const pages: PaletteItem[] = [
      { id: "dashboard", label: "Home", path: "/dashboard", group: "Pages" },
      { id: "applications", label: "Threat models", path: "/applications", group: "Pages" },
      { id: "threat-kb", label: "Threat library", path: "/threat-kb", group: "Pages" },
      { id: "settings", label: "Settings", path: "/settings", group: "Pages" },
      { id: "help", label: "Help", path: "/help", group: "Pages" },
    ];

    // Create help topic items from hard-coded topics
    const helpTopics: PaletteItem[] = HELP_TOPICS.map((topic) => ({
      id: `help-${topic.id}`,
      label: topic.title,
      path: `/help/${topic.id}`,
      group: "Help",
    }));

    setItems([...pages, ...helpTopics]);
  }, []);

  // Load threat models on first open
  useEffect(() => {
    if (isOpen && !loaded) {
      setLoaded(true);
      // The plain list, not /api/dashboard: that one derives every model's
      // threats and records trend snapshots, too heavy for a search box.
      // /models/:id opens the latest run.
      apiFetch<Application[]>("/api/applications")
        .then((data) => {
          const threatModels: PaletteItem[] = data.map((app) => ({
            id: `model-${app.id}`,
            label: app.name,
            path: `/models/${app.id}`,
            group: "Threat models",
          }));
          setItems((prev) => [...prev, ...threatModels]);
        })
        .catch(() => {
          // Fail silently on API error
        });
    }
  }, [isOpen, loaded]);

  // Filter items based on search
  useEffect(() => {
    const lowerSearch = search.toLowerCase();
    const filtered = items.filter(
      (item) => item.label.toLowerCase().includes(lowerSearch) || item.path.toLowerCase().includes(lowerSearch),
    );
    setFilteredItems(filtered);
    setHighlightedIndex(0);
  }, [search, items]);

  // Handle Ctrl-K / Meta-K
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setIsOpen(true);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Handle modal key events
  function handleInputKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Escape") {
      setIsOpen(false);
      setSearch("");
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlightedIndex((i) => (i < filteredItems.length - 1 ? i + 1 : i));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlightedIndex((i) => (i > 0 ? i - 1 : 0));
    } else if (e.key === "Enter" && filteredItems.length > 0) {
      e.preventDefault();
      const item = filteredItems[highlightedIndex];
      navigate(item.path);
      setIsOpen(false);
      setSearch("");
    }
  }

  function handleItemClick(item: PaletteItem) {
    navigate(item.path);
    setIsOpen(false);
    setSearch("");
  }

  // Group filtered items
  const groupedItems = new Map<string, PaletteItem[]>();
  filteredItems.forEach((item) => {
    if (!groupedItems.has(item.group)) {
      groupedItems.set(item.group, []);
    }
    groupedItems.get(item.group)!.push(item);
  });

  return (
    <Modal show={isOpen} onHide={() => setIsOpen(false)} centered size="lg">
      <Modal.Header closeButton>
        <Form.Control
          ref={inputRef}
          type="text"
          placeholder="Search pages, threats, help..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={handleInputKeyDown}
          autoFocus
          aria-label="Search"
        />
      </Modal.Header>
      <Modal.Body className="p-0" style={{ maxHeight: "400px", overflowY: "auto" }}>
        {filteredItems.length === 0 ? (
          <div className="p-3 text-muted text-center">No results found</div>
        ) : (
          Array.from(groupedItems.entries()).map(([group, groupItems]) => (
            <div key={group}>
              <div className="p-2 px-3 small text-muted fw-semibold bg-body-tertiary">{group}</div>
              {groupItems.map((item) => {
                const itemIndex = filteredItems.indexOf(item);
                return (
                  <button
                    key={item.id}
                    type="button"
                    className={`w-100 text-start p-2 px-3 border-0 bg-transparent ${
                      itemIndex === highlightedIndex ? "bg-primary-subtle" : "hover:bg-body-tertiary"
                    }`}
                    style={{ cursor: "pointer" }}
                    onClick={() => handleItemClick(item)}
                  >
                    {item.label}
                  </button>
                );
              })}
            </div>
          ))
        )}
      </Modal.Body>
    </Modal>
  );
}
