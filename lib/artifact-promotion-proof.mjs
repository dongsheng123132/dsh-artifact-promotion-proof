import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 4 * 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/
const SECRET_VALUE = /(?:bearer\s+[a-z0-9._-]{12,}|(?:sk|ghp|github_pat)_[a-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i
const stable = value => JSON.stringify(value, (_, child) => child && typeof child === 'object' && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a.localeCompare(b))) : child)
export const sha256 = value => createHash('sha256').update(value).digest('hex')
const fail = (code, message) => Object.assign(new Error(message), { code })
const hash = (value, label) => { if (typeof value !== 'string' || !HEX.test(value)) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const boundedId = (value, label) => { if (typeof value !== 'string' || !ID.test(value)) throw fail('INVALID_MANIFEST', `${label} must be a bounded public id`) }
const timestamp = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw fail('INVALID_TIME', `${label} must be an ISO timestamp`); return parsed }

function rejectSecrets(value, path = '$') {
  if (typeof value === 'string' && SECRET_VALUE.test(value)) throw fail('SECRET_MATERIAL', `secret-shaped value rejected at ${path}`)
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (/(?:secret|password|credential|api[_-]?key|private[_-]?key|authorization|cookie|raw|body|content|log|prompt|chat)$/i.test(key) && (typeof child === 'string' || typeof child === 'number')) throw fail('SECRET_MATERIAL', `sensitive field rejected at ${path}.${key}`)
    rejectSecrets(child, `${path}.${key}`)
  }
}

function uniqueIds(values, label, min = 1) {
  if (!Array.isArray(values) || values.length < min || values.length > 32) throw fail('INVALID_MANIFEST', `${label} invalid`)
  const set = new Set()
  for (const value of values) { boundedId(value, label); if (set.has(value)) throw fail('INVALID_MANIFEST', `duplicate ${label}`); set.add(value) }
  return set
}

function parseManifest(input) {
  let manifest
  try { manifest = typeof input === 'string' ? JSON.parse(input) : structuredClone(input) } catch { throw fail('INVALID_MANIFEST', 'manifest must be JSON') }
  if (!manifest || manifest.schemaVersion !== 1) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required')
  rejectSecrets(manifest)
  boundedId(manifest.proofId, 'proofId')
  const evaluationMs = timestamp(manifest.evaluationTime, 'evaluationTime')
  const artifact = manifest.artifact || {}
  for (const key of ['artifactSha256', 'buildRevisionSha256', 'buildReceiptSha256', 'provenanceSha256']) hash(artifact[key], `artifact.${key}`)
  const policy = manifest.policy || {}
  if (!Number.isInteger(policy.maxEvidenceAgeMs) || policy.maxEvidenceAgeMs < 1000 || policy.maxEvidenceAgeMs > 365 * 86400000) throw fail('INVALID_MANIFEST', 'maxEvidenceAgeMs invalid')
  if (!Array.isArray(policy.stages) || policy.stages.length < 2 || policy.stages.length > 16) throw fail('INVALID_MANIFEST', 'policy.stages invalid')
  const stageIds = new Set()
  const stages = policy.stages.map((stage, index) => {
    hash(stage?.stageIdHash, `policy.stages[${index}].stageIdHash`)
    hash(stage.environmentHash, `policy.stages[${index}].environmentHash`)
    if (stageIds.has(stage.stageIdHash)) throw fail('INVALID_MANIFEST', 'duplicate policy stage')
    stageIds.add(stage.stageIdHash)
    const requiredGateTypes = uniqueIds(stage.requiredGateTypes, `policy.stages[${index}].requiredGateTypes`)
    if (!Number.isInteger(stage.minDistinctAuthorities) || stage.minDistinctAuthorities < 1 || stage.minDistinctAuthorities > requiredGateTypes.size) throw fail('INVALID_MANIFEST', 'minDistinctAuthorities invalid')
    return { ...stage, requiredGateTypes }
  })
  if (!Array.isArray(manifest.records) || !manifest.records.length || manifest.records.length > 16) throw fail('INVALID_MANIFEST', 'records invalid')
  const recordIds = new Set(); const receipts = new Set(); const gateIds = new Set()
  const records = manifest.records.map((record, index) => {
    if (!Number.isInteger(record?.sequence) || record.sequence < 1) throw fail('INVALID_MANIFEST', 'record sequence invalid')
    for (const key of ['recordIdHash', 'stageIdHash', 'environmentHash', 'artifactSha256', 'deploymentReceiptSha256']) hash(record[key], `records[${index}].${key}`)
    if (record.previousDeploymentReceiptSha256 !== null) hash(record.previousDeploymentReceiptSha256, `records[${index}].previousDeploymentReceiptSha256`)
    if (recordIds.has(record.recordIdHash) || receipts.has(record.deploymentReceiptSha256)) throw fail('INVALID_MANIFEST', 'duplicate promotion record or receipt')
    recordIds.add(record.recordIdHash); receipts.add(record.deploymentReceiptSha256)
    if (record.status !== 'promoted') throw fail('INVALID_MANIFEST', 'record status must be promoted')
    const promotedMs = timestamp(record.promotedAt, `records[${index}].promotedAt`)
    if (!Array.isArray(record.gates) || !record.gates.length || record.gates.length > 32) throw fail('INVALID_MANIFEST', 'record gates invalid')
    const gates = record.gates.map((gate, gateIndex) => {
      boundedId(gate?.type, `records[${index}].gates[${gateIndex}].type`)
      for (const key of ['gateIdHash', 'authorityHash', 'artifactSha256']) hash(gate[key], `records[${index}].gates[${gateIndex}].${key}`)
      if (gateIds.has(gate.gateIdHash)) throw fail('INVALID_MANIFEST', 'duplicate gate receipt')
      gateIds.add(gate.gateIdHash)
      if (gate.status !== 'passed') throw fail('INVALID_MANIFEST', 'gate status must be passed')
      return { ...gate, observedMs: timestamp(gate.observedAt, `records[${index}].gates[${gateIndex}].observedAt`) }
    })
    return { ...record, promotedMs, gates }
  }).sort((a, b) => a.sequence - b.sequence)
  return { manifest, evaluationMs, artifact, policy, stages, records }
}

export function inspectArtifactPromotionManifestJson(manifestJson) {
  const { manifest, artifact, stages, records } = parseManifest(manifestJson)
  return { schemaVersion: 1, proofIdHash: sha256(manifest.proofId), artifactSha256: artifact.artifactSha256, buildRevisionSha256: artifact.buildRevisionSha256, declaredStageCount: stages.length, recordedStageCount: records.length, gateReceiptCount: records.reduce((sum, record) => sum + record.gates.length, 0), executesDeployment: false, authenticatesReceipts: false }
}

export function evaluateArtifactPromotionManifest(manifestJson) {
  const { manifest, evaluationMs, artifact, policy, stages, records } = parseManifest(manifestJson)
  const exactStageCount = records.length === stages.length
  const sequenceContiguous = records.every((record, index) => record.sequence === index + 1)
  const stageOrderMatched = exactStageCount && records.every((record, index) => record.stageIdHash === stages[index].stageIdHash)
  const environmentMatched = exactStageCount && records.every((record, index) => record.environmentHash === stages[index].environmentHash)
  const artifactDigestContinuous = records.every(record => record.artifactSha256 === artifact.artifactSha256 && record.gates.every(gate => gate.artifactSha256 === artifact.artifactSha256))
  const receiptChainValid = records.every((record, index) => index === 0 ? record.previousDeploymentReceiptSha256 === null : record.previousDeploymentReceiptSha256 === records[index - 1].deploymentReceiptSha256)
  const chronologyValid = records.every((record, index) => record.promotedMs <= evaluationMs && (index === 0 || record.promotedMs > records[index - 1].promotedMs) && record.gates.every(gate => gate.observedMs <= record.promotedMs && gate.observedMs <= evaluationMs))
  const evidenceFresh = records.every(record => evaluationMs - record.promotedMs >= 0 && evaluationMs - record.promotedMs <= policy.maxEvidenceAgeMs && record.gates.every(gate => evaluationMs - gate.observedMs >= 0 && evaluationMs - gate.observedMs <= policy.maxEvidenceAgeMs))
  const stageResults = records.map((record, index) => {
    const stage = stages[index]
    if (!stage) return { sequence: record.sequence, stageIdHash: record.stageIdHash, gatesComplete: false, authoritiesDistinct: false, unexpectedGateTypes: true }
    const typeCounts = new Map(); const authorities = new Set()
    for (const gate of record.gates) { typeCounts.set(gate.type, (typeCounts.get(gate.type) || 0) + 1); authorities.add(gate.authorityHash) }
    const gatesComplete = [...stage.requiredGateTypes].every(type => typeCounts.get(type) === 1)
    const unexpectedGateTypes = [...typeCounts].some(([type, count]) => !stage.requiredGateTypes.has(type) || count !== 1)
    return { sequence: record.sequence, stageIdHash: record.stageIdHash, environmentHash: record.environmentHash, deploymentReceiptSha256: record.deploymentReceiptSha256, gatesComplete, authoritiesDistinct: authorities.size >= stage.minDistinctAuthorities, unexpectedGateTypes }
  })
  const requiredGatesPassed = exactStageCount && stageResults.every(row => row.gatesComplete && row.authoritiesDistinct && !row.unexpectedGateTypes)
  const promoted = exactStageCount && sequenceContiguous && stageOrderMatched && environmentMatched && artifactDigestContinuous && receiptChainValid && chronologyValid && evidenceFresh && requiredGatesPassed
  return { schemaVersion: 1, verdict: promoted ? 'promoted' : 'not-promoted', proofIdHash: sha256(manifest.proofId), artifactSha256: artifact.artifactSha256, buildRevisionSha256: artifact.buildRevisionSha256, buildReceiptSha256: artifact.buildReceiptSha256, provenanceSha256: artifact.provenanceSha256, checks: { exactStageCount, sequenceContiguous, stageOrderMatched, environmentMatched, artifactDigestContinuous, receiptChainValid, chronologyValid, evidenceFresh, requiredGatesPassed }, disclosures: { declaredStageCount: stages.length, recordedStageCount: records.length, gateReceiptCount: records.reduce((sum, record) => sum + record.gates.length, 0) }, stages: stageResults, executesDeployment: false, grantsApproval: false, authenticatesReceipts: false, verifiesBuildProvenanceSignature: false, provesRuntimeHealth: false, destructiveActions: false }
}

async function safeManifest(root, manifestPath) {
  if (typeof manifestPath !== 'string' || !manifestPath || manifestPath.length > 512 || isAbsolute(manifestPath)) throw fail('PATH_ESCAPE', 'manifestPath must be workspace-relative')
  const absolute = resolve(root, manifestPath); const rel = relative(root, absolute)
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'manifestPath escapes workspaceRoot')
  let cursor = root; let stat; const parts = rel.split(/[\\/]/)
  for (const [index, part] of parts.entries()) { cursor = resolve(cursor, part); stat = await lstat(cursor).catch(() => { throw fail('MISSING_MANIFEST', 'manifest missing') }); if (stat.isSymbolicLink()) throw fail('UNSAFE_MANIFEST', 'manifest path contains symlink'); if (index < parts.length - 1 && !stat.isDirectory()) throw fail('UNSAFE_MANIFEST', 'manifest parent invalid') }
  if (!stat.isFile() || stat.size > MAX_FILE) throw fail('UNSAFE_MANIFEST', 'manifest must be a regular file no larger than 4 MiB')
  const rootReal = await realpath(root); const fileReal = await realpath(absolute); const realRel = relative(rootReal, fileReal)
  if (realRel.startsWith('..') || isAbsolute(realRel)) throw fail('PATH_ESCAPE', 'real manifest escapes workspaceRoot')
  return readFile(fileReal, 'utf8')
}

async function safeArtifactDir(root, artifactDir) {
  if (typeof artifactDir !== 'string' || !artifactDir || artifactDir.length > 512 || isAbsolute(artifactDir)) throw fail('PATH_ESCAPE', 'artifactDir must be workspace-relative')
  const dir = resolve(root, artifactDir); const rel = relative(root, dir)
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  let cursor = root
  for (const part of rel.split(/[\\/]/)) { cursor = resolve(cursor, part); try { const stat = await lstat(cursor); if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('UNSAFE_ARTIFACT_DIR', 'artifactDir components must be real directories') } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(cursor) } }
  return dir
}

export async function verifyArtifactPromotionManifest({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot); const report = evaluateArtifactPromotionManifest(await safeManifest(root, manifestPath)); const bytes = Buffer.from(`${stable(report)}\n`); const digest = sha256(bytes); const dir = await safeArtifactDir(root, artifactDir); const output = resolve(dir, `artifact-promotion-proof-${digest}.json`)
  try { await writeFile(output, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; if (!(await readFile(output)).equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(output)
  if (sha256(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back failed')
  return { ...report, artifact: { path: relative(root, output).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}
