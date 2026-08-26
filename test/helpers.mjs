import { readFile } from 'node:fs/promises'
export const json = value => `${JSON.stringify(value, null, 2)}\n`
export const fixture = async () => JSON.parse(await readFile(new URL('../examples/promoted.json', import.meta.url), 'utf8'))
export const clone = value => structuredClone(value)
