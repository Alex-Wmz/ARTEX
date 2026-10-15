import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";

// Set before starting Next, including when invoked directly through npm on
// Windows. No shell-specific environment assignment or extra package needed.
const require = createRequire(import.meta.url);
const args = process.argv.slice(2);
const isStatic = args.includes("--static");
const result = spawnSync(process.execPath, [require.resolve("next/dist/bin/next"), ...args.filter((arg) => arg !== "--static")], {
  stdio: "inherit",
  env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1", ...(isStatic ? { NEXT_EXPORT: "1" } : {}) },
});
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);
