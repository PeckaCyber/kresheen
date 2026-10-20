import { apiFetch } from "../api/client";

export interface DiagramElementLayoutOut {
  id: string;
  diagram_id: string;
  element_key: string;
  hidden: boolean;
  position_x: number | null;
  position_y: number | null;
}

export function dfdEditApi(applicationId: string, diagramId: string) {
  const base = `/api/applications/${encodeURIComponent(applicationId)}`;
  const layoutBase = `${base}/diagrams/${encodeURIComponent(diagramId)}/layout`;

  async function createManualAsset(spec: {id?: string; name: string; type: string; trust_boundary?: string | null; position_x?: number | null; position_y?: number | null}): Promise<{id: string}> {
    return apiFetch<{id: string}>(`${base}/manual-assets`, {
      method: 'POST',
      body: JSON.stringify(spec)
    });
  }

  async function deleteManualAsset(id: string): Promise<void> {
    await apiFetch<void>(`${base}/manual-assets/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    });
  }

  async function renameManualAsset(id: string, name: string): Promise<void> {
    await apiFetch<void>(`${base}/manual-assets/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({name})
    });
  }

  async function updateManualFlowLabel(id: string, label: string): Promise<void> {
    await apiFetch<void>(`${base}/manual-flows/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({label})
    });
  }

  async function createManualFlow(spec: {id?: string; source_ref: string; target_ref: string; label?: string | null}): Promise<{id: string}> {
    return apiFetch<{id: string}>(`${base}/manual-flows`, {
      method: 'POST',
      body: JSON.stringify(spec)
    });
  }

  async function deleteManualFlow(id: string): Promise<void> {
    await apiFetch<void>(`${base}/manual-flows/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    });
  }

  async function setBoundary(componentName: string, label: string): Promise<void> {
    await apiFetch<void>(`${base}/trust-boundaries`, {
      method: 'PUT',
      body: JSON.stringify({component_name: componentName, trust_boundary: label})
    });
  }

  async function clearBoundary(componentName: string): Promise<void> {
    await apiFetch<void>(`${base}/trust-boundaries?component_name=${encodeURIComponent(componentName)}`, {
      method: 'DELETE'
    });
  }

  async function restoreBoundary(componentName: string, label: string | null): Promise<void> {
    if (label === null) {
      await clearBoundary(componentName);
    } else {
      await setBoundary(componentName, label);
    }
  }

  // Diagram-scoped visual state (position + hidden), one row per
  // (diagram, element_key). `element_key` is `<type>:<name>` for a
  // component, `flow:<source>-><target>` for a flow, `boundary:<name>` for
  // a trust-boundary group -- see models/diagram_layout.py.
  async function saveElementLayout(
    elementKey: string,
    patch: { hidden?: boolean; position_x?: number; position_y?: number },
  ): Promise<DiagramElementLayoutOut> {
    return apiFetch<DiagramElementLayoutOut>(`${layoutBase}?element_key=${encodeURIComponent(elementKey)}`, {
      method: 'PUT',
      body: JSON.stringify(patch),
    });
  }

  async function clearElementLayout(elementKey: string): Promise<void> {
    await apiFetch<void>(`${layoutBase}?element_key=${encodeURIComponent(elementKey)}`, {
      method: 'DELETE',
    });
  }

  async function moveElement(elementKey: string, x: number, y: number): Promise<void> {
    await saveElementLayout(elementKey, { position_x: x, position_y: y });
  }

  async function restoreElementPosition(
    elementKey: string,
    pos: { x: number; y: number } | null,
  ): Promise<void> {
    if (pos === null) {
      await clearElementLayout(elementKey);
    } else {
      await moveElement(elementKey, pos.x, pos.y);
    }
  }

  async function setHidden(elementKey: string, hidden: boolean): Promise<void> {
    await saveElementLayout(elementKey, { hidden });
  }

  async function listHiddenLayout(): Promise<DiagramElementLayoutOut[]> {
    const rows = await apiFetch<DiagramElementLayoutOut[]>(layoutBase);
    return rows.filter((row) => row.hidden);
  }

  return {
    createManualAsset,
    deleteManualAsset,
    renameManualAsset,
    updateManualFlowLabel,
    createManualFlow,
    deleteManualFlow,
    setBoundary,
    clearBoundary,
    restoreBoundary,
    saveElementLayout,
    clearElementLayout,
    moveElement,
    restoreElementPosition,
    setHidden,
    listHiddenLayout,
  };
}
