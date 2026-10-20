// The core build resolves `@kresheen/pro` to this empty stub. A build with a plugin frontend sets
// KRESHEEN_PRO_FRONTEND=<path> (see vite.config.ts) and the alias points at that entry file instead.
import type { FrontendExtension } from "../extensions";

const extension: FrontendExtension = {};
export default extension;
