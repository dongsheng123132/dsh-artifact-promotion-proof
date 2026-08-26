import assert from 'node:assert/strict'
import { createDefinitions } from '../index.js'
const definitions = createDefinitions({}, { workspaceRoot: process.cwd() })
assert.deepEqual(definitions.map(row => row.name), ['dsh_artifact_promotion_inspect', 'dsh_artifact_promotion_verify'])
const inspected = await definitions[0].execute({ manifestJson: await (await import('node:fs/promises')).readFile(new URL('../examples/promoted.json', import.meta.url), 'utf8') })
assert.equal(inspected.declaredStageCount, 3)
process.stdout.write('plugin smoke passed: 2 tools\n')
