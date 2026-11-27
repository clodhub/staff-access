// Renders a settings template the way clod does at install, for tests: every {{name}} needs a value.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const TOKEN = /\{\{([A-Za-z][A-Za-z0-9_.-]*)\}\}/g;

export function placeholders(template: URL): string[] {
  return [...readFileSync(template, "utf8").matchAll(TOKEN)].map((match) => match[1]);
}

export function render(template: URL, values: Record<string, unknown>): string {
  return readFileSync(template, "utf8").replace(TOKEN, (_, name: string) => {
    if (!(name in values)) throw new Error(`${name} has no value`);
    return String(values[name]);
  });
}

// Writes the rendered template to a temporary folder and imports it.
export async function importRendered<T>(template: URL, values: Record<string, unknown>): Promise<T> {
  const folder = mkdtempSync(join(tmpdir(), "rendered-"));
  const file = join(folder, "settings.ts");
  writeFileSync(file, render(template, values));
  return import(pathToFileURL(file).href) as Promise<T>;
}
