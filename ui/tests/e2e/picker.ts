// REQ: UI-901 (T24.34) — drive the searchable picker the way a person does.
import type { Locator, Page } from '@playwright/test';

/** Opens the picker named `name` inside `scope`, picks each option by its (partial) name, and closes it. */
export async function pick(scope: Locator | Page, name: string, ...options: Array<string | RegExp>): Promise<void> {
  const group = scope.getByRole('group', { name, exact: true });
  const box = group.getByRole('combobox');
  await box.click();
  for (const o of options) await group.getByRole('option', { name: o, exact: typeof o === 'string' }).click();
  await box.press('Escape');
}
