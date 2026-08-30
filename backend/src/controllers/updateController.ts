import { Request, Response } from 'express'
import path from 'path'
import fs from 'fs'
import crypto from 'crypto'
import multer, { FileFilterCallback } from 'multer'
import { AuthenticatedRequest } from '../types'
import { audit } from '../services/auditService'
import { logger } from '../utils/logger'

// ──────────────────── storage paths ────────────────────

const UPLOAD_DIR   = process.env.UPDATE_UPLOAD_DIR || path.join(process.cwd(), 'uploads', 'updates')
const VERSION_FILE = path.join(UPLOAD_DIR, 'version.json')

fs.mkdirSync(UPLOAD_DIR, { recursive: true })

// ──────────────────── version.json schema ────────────────────
// {
//   "live": "2.1.0",
//   "versions": [
//     { "version": "2.1.0", "sha256": "...", "file": "CheatDLL_2.1.0.dll",
//       "uploadedAt": "2026-08-30T00:00:00Z", "uploadedBy": "admin", "live": true }
//   ]
// }

interface VersionEntry {
  version:    string
  sha256:     string
  file:       string
  uploadedAt: string
  uploadedBy: string
  live:       boolean
  sizeBytes:  number
}

interface VersionManifest {
  live:     string
  versions: VersionEntry[]
}

function readManifest(): VersionManifest {
  try {
    return JSON.parse(fs.readFileSync(VERSION_FILE, 'utf8'))
  } catch {
    return { live: '', versions: [] }
  }
}

function writeManifest(m: VersionManifest) {
  fs.writeFileSync(VERSION_FILE, JSON.stringify(m, null, 2), 'utf8')
}

function sha256File(filePath: string): string {
  const h = crypto.createHash('sha256')
  h.update(fs.readFileSync(filePath))
  return h.digest('hex')
}

// ──────────────────── multer setup ────────────────────
// Only .dll files up to 64 MB.
export const dllUpload = multer({
  storage: multer.diskStorage({
    destination: (_req: Request, _file: Express.Multer.File, cb: (error: Error | null, destination: string) => void) =>
      cb(null, UPLOAD_DIR),
    filename: (_req: Request, file: Express.Multer.File, cb: (error: Error | null, filename: string) => void) => {
      const safe = file.originalname.replace(/[^a-zA-Z0-9._\-]/g, '_')
      const ts   = new Date().toISOString().replace(/[:.]/g, '-')
      cb(null, `${ts}_${safe}`)
    },
  }),
  limits: { fileSize: 64 * 1024 * 1024 },
  fileFilter: (_req: Request, file: Express.Multer.File, cb: FileFilterCallback) => {
    if (!file.originalname.toLowerCase().endsWith('.dll')) {
      cb(new Error('Only .dll files are accepted'))
      return
    }
    cb(null, true)
  },
})

// ──────────────────── handlers ────────────────────

// POST /api/admin/update/upload
// multipart: file (DLL), version (semver string)
export async function handleUpload(req: Request, res: Response) {
  const file = (req as Request & { file?: Express.Multer.File }).file
  if (!file) {
    res.status(400).json({ error: 'No file uploaded' })
    return
  }

  const version = (req.body.version as string | undefined)?.trim()
  if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
    fs.unlinkSync(file.path)
    res.status(400).json({ error: 'version must be semver (e.g. 2.1.0)' })
    return
  }

  const manifest = readManifest()
  if (manifest.versions.some(v => v.version === version)) {
    fs.unlinkSync(file.path)
    res.status(409).json({ error: `Version ${version} already exists` })
    return
  }

  const sha256 = sha256File(file.path)
  const actor  = (req as AuthenticatedRequest).user

  const entry: VersionEntry = {
    version,
    sha256,
    file:       path.basename(file.path),
    uploadedAt: new Date().toISOString(),
    uploadedBy: actor?.sub ?? 'unknown',
    live:       false,
    sizeBytes:  file.size,
  }

  manifest.versions.unshift(entry)
  writeManifest(manifest)

  await audit({
    eventType: 'UPDATE_UPLOADED',
    result:    'SUCCESS',
    userId:    actor?.sub ?? 'unknown',
    metadata:  { version, sha256, file: entry.file },
  })

  logger.info('Update uploaded', { version, sha256 })
  res.status(201).json({ version, sha256, file: entry.file })
}

// POST /api/admin/update/set-live/:version
export async function handleSetLive(req: Request, res: Response) {
  const { version } = req.params
  const manifest    = readManifest()
  const entry       = manifest.versions.find(v => v.version === version)

  if (!entry) {
    res.status(404).json({ error: `Version ${version} not found` })
    return
  }

  manifest.versions.forEach(v => { v.live = false })
  entry.live   = true
  manifest.live = version
  writeManifest(manifest)

  const actor = (req as AuthenticatedRequest).user
  await audit({
    eventType: 'UPDATE_SET_LIVE',
    result:    'SUCCESS',
    userId:    actor?.sub ?? 'unknown',
    metadata:  { version },
  })

  logger.info('Live version set', { version })
  res.json({ live: version })
}

// DELETE /api/admin/update/versions/:version
export async function handleDeleteVersion(req: Request, res: Response) {
  const { version } = req.params
  const manifest    = readManifest()
  const idx         = manifest.versions.findIndex(v => v.version === version)

  if (idx === -1) {
    res.status(404).json({ error: `Version ${version} not found` })
    return
  }

  const entry = manifest.versions[idx]
  if (entry.live) {
    res.status(409).json({ error: 'Cannot delete the live version — set another version live first' })
    return
  }

  const filePath = path.join(UPLOAD_DIR, entry.file)
  try { fs.unlinkSync(filePath) } catch {}

  manifest.versions.splice(idx, 1)
  writeManifest(manifest)

  res.json({ deleted: version })
}

// GET /api/admin/update/versions
export function handleListVersions(_req: Request, res: Response) {
  const manifest = readManifest()
  res.json({ live: manifest.live, versions: manifest.versions })
}

// ──────────────────── client-facing (loader) ────────────────────

// GET /api/update/check
// Query: currentVersion (semver)
export function handleCheck(req: Request, res: Response) {
  const current  = (req.query.currentVersion as string | undefined) ?? '0.0.0'
  const manifest = readManifest()

  if (!manifest.live) {
    res.json({ available: false })
    return
  }

  const entry = manifest.versions.find(v => v.version === manifest.live)
  if (!entry) {
    res.json({ available: false })
    return
  }

  const isNewer = semverGt(manifest.live, current)
  res.json({
    available:   isNewer,
    version:     manifest.live,
    sha256:      entry.sha256,
    downloadUrl: `/api/update/download/${manifest.live}`,
  })
}

// GET /api/update/download/:version
// Auth required — loader sends Bearer token.
export function handleDownload(req: Request, res: Response) {
  const { version } = req.params
  const manifest    = readManifest()
  const entry       = manifest.versions.find(v => v.version === version)

  if (!entry) {
    res.status(404).json({ error: 'Version not found' })
    return
  }

  const filePath = path.join(UPLOAD_DIR, entry.file)
  if (!fs.existsSync(filePath)) {
    res.status(404).json({ error: 'File not found on server' })
    return
  }

  res.setHeader('X-SHA256',              entry.sha256)
  res.setHeader('Content-Disposition',   `attachment; filename="CheatDLL_${version}.dll"`)
  res.setHeader('Content-Type',          'application/octet-stream')
  res.setHeader('Content-Length',        entry.sizeBytes.toString())
  res.sendFile(filePath)
}

// ──────────────────── semver helper ────────────────────

function parseSemver(v: string): [number, number, number] {
  const parts = v.split('.').map(Number)
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0]
}

function semverGt(a: string, b: string): boolean {
  const [aMaj, aMin, aPat] = parseSemver(a)
  const [bMaj, bMin, bPat] = parseSemver(b)
  if (aMaj !== bMaj) return aMaj > bMaj
  if (aMin !== bMin) return aMin > bMin
  return aPat > bPat
}
