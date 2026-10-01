import { copyFile, mkdir, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const output = join(root, 'dist');
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
for (const file of ['index.html', 'privacy.html', 'style.css', 'favicon.svg', '_headers']) {
  await copyFile(join(root, file), join(output, file));
}
await copyFile(join(root, 'design/brand/tentative-logo.svg'), join(output, 'logo.svg'));
