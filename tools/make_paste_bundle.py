#!/usr/bin/env python3
"""Build dist/Rebuild-Hashslinger.ps1: one paste-able PowerShell file that recreates the core
Hashslinger files and then verifies each one (byte length, line count, SHA-256).

Usage (from the repo root):  python3 tools/make_paste_bundle.py [--out dist/Rebuild-Hashslinger.ps1]

Only files tracked by git are bundled, as committed. Lab diagnostics (they change AD) and CI files are
left out; edit EXCLUDE to change that.
"""
import argparse
import datetime
import hashlib
import os
import subprocess
import sys

EXCLUDE_PREFIXES = ("diagnostics/", ".github/", "tools/")
EXCLUDE_FILES = {".gitignore"}


def git(*args):
    return subprocess.check_output(("git",) + args, text=True).strip()


def core_files():
    files = []
    for p in git("ls-files").splitlines():
        if p in EXCLUDE_FILES or p.startswith(EXCLUDE_PREFIXES):
            continue
        files.append(p)
    return sorted(files)


def check_pasteable(path, data):
    """The bundle embeds each file in a single-quoted here-string, so these must hold."""
    problems = []
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        problems.append("non-ASCII bytes (would be mangled by ANSI/UTF-8 save differences)")
        return problems
    if "\r" in text:
        problems.append("carriage returns (bundle normalizes to LF)")
    for n, line in enumerate(text.split("\n"), 1):
        if line.startswith("'@"):
            problems.append("line %d starts with '@ (would end the here-string)" % n)
    if "'" in path:
        problems.append("apostrophe in path")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join("dist", "Rebuild-Hashslinger.ps1"))
    args = ap.parse_args()

    commit = git("rev-parse", "--short", "HEAD")
    dirty = git("status", "--porcelain", "--untracked-files=no")
    entries = []
    bad = []
    for p in core_files():
        data = subprocess.check_output(["git", "show", "HEAD:" + p])  # committed bytes, not the work tree
        bad += ["%s: %s" % (p, m) for m in check_pasteable(p, data)]
        entries.append((p, data))
    if bad:
        sys.exit("cannot bundle:\n  " + "\n  ".join(bad))

    manifest = []
    for p, data in entries:
        manifest.append((p, len(data), data.count(b"\n"), hashlib.sha256(data).hexdigest().upper()))
    fingerprint = hashlib.sha256(
        "".join("%s\n%s\n" % (p, h) for p, _, _, h in manifest).encode("ascii")).hexdigest().upper()
    total = sum(m[1] for m in manifest)

    out = []
    w = out.append
    w("<#")
    w(".SYNOPSIS")
    w("  Recreates the core Hashslinger files from this one script, then checks every file's byte length,")
    w("  line count and SHA-256 against the originals.")
    w(".DESCRIPTION")
    w("  1. Paste this whole file into Notepad and save it as Rebuild-Hashslinger.ps1 (any encoding is fine).")
    w("  2. Run:  powershell -NoProfile -ExecutionPolicy Bypass -File .\\Rebuild-Hashslinger.ps1 -Destination C:\\Hashslinger-src")
    w("  3. Read the RESULT line at the end. Every row must say PASS.")
    w("  It only writes files under -Destination. It runs nothing it creates, makes no network calls and")
    w("  does not touch Active Directory. Files are written as committed in git: ASCII, LF line endings.")
    w("  -VerifyOnly re-checks an existing folder without writing anything.")
    w("  Everything below param() is one block, so a paste that was cut short fails with a")
    w("  'Missing closing' parse error and nothing is written.")
    w("  Source commit %s%s, generated %s UTC." % (
        commit, " (work tree had uncommitted changes; bundle uses the commit)" if dirty else "",
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")))
    w("  %d files, %d bytes. Bundle fingerprint: %s" % (len(manifest), total, fingerprint))
    w("#>")
    w("param(")
    w("  [string]$Destination = (Join-Path (Get-Location).Path 'Hashslinger'),")
    w("  [switch]$VerifyOnly,")
    w("  [switch]$Force")
    w(")")
    w(". {   # one block: a truncated paste is a parse error, never a partial run")
    w("$ErrorActionPreference = 'Stop'")
    w("$ExpectedFingerprint = '%s'" % fingerprint)
    w("")
    w("# ---- manifest: what each file must look like once written")
    w("$Manifest = @(")
    for i, (p, b, l, h) in enumerate(manifest):
        w("  [pscustomobject]@{ Path = '%s'; Bytes = %d; Lines = %d; Sha256 = '%s' }%s" % (
            p, b, l, h, "," if i < len(manifest) - 1 else ""))
    w(")")
    w("")
    w("# ---- file contents (each between @' and '@ exactly as committed)")
    w("$Files = [ordered]@{}")
    for p, data in entries:
        w("")
        w("$Files['%s'] = @'" % p)
        w(data.decode("ascii") + "\n'@")
    w("")
    w(MAIN.strip("\n"))
    w("}   # end of bundle")
    text = "\n".join(out) + "\n"

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="ascii", newline="\n") as f:
        f.write(text)
    print("wrote %s: %d files, %d content bytes, %d bundle bytes, fingerprint %s" % (
        args.out, len(manifest), total, len(text), fingerprint))


MAIN = r"""
# ---- write
$dest = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
Write-Host "Hashslinger rebuild: $($Manifest.Count) files -> $dest"
$missingFromBundle = @($Manifest | Where-Object { -not $Files.Contains($_.Path) })
if (-not $VerifyOnly) {
  if ((Test-Path -LiteralPath $dest) -and (Get-ChildItem -LiteralPath $dest -Force | Select-Object -First 1) -and -not $Force) {
    throw "$dest already has files in it. Pick an empty folder, or add -Force to overwrite."
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  foreach ($m in $Manifest) {
    if (-not $Files.Contains($m.Path)) { continue }
    $full = Join-Path $dest ($m.Path -replace '/', '\')
    $dir = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $text = $Files[$m.Path] -replace "`r`n", "`n"     # Notepad saves CRLF; the originals are LF
    [IO.File]::WriteAllBytes($full, $enc.GetBytes($text))
  }
}

# ---- verify
$sha = [Security.Cryptography.SHA256]::Create()
$fpText = New-Object System.Text.StringBuilder
$rows = foreach ($m in $Manifest) {
  $full = Join-Path $dest ($m.Path -replace '/', '\')
  if (-not (Test-Path -LiteralPath $full)) {
    $why = if (-not $Files.Contains($m.Path)) { 'not in the pasted bundle (paste cut short?)' } else { 'file not found' }
    [void]$fpText.Append("$($m.Path)`nMISSING`n")
    [pscustomobject]@{ Status = 'FAIL'; File = $m.Path; Bytes = "0 / $($m.Bytes)"; Lines = "0 / $($m.Lines)"; Problem = $why }
    continue
  }
  $bytes = [IO.File]::ReadAllBytes($full)
  $lines = 0; foreach ($b in $bytes) { if ($b -eq 10) { $lines++ } }
  $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '')
  [void]$fpText.Append("$($m.Path)`n$hash`n")
  $problems = @()
  if ($bytes.Length -ne $m.Bytes) { $problems += "length off by $($bytes.Length - $m.Bytes) bytes" }
  if ($lines -ne $m.Lines) { $problems += "line count off by $($lines - $m.Lines)" }
  if ($hash -ne $m.Sha256) { $problems += $(if ($problems.Count) { 'content differs' } else { 'same length but content differs' }) }
  [pscustomobject]@{
    Status = $(if ($problems.Count) { 'FAIL' } else { 'PASS' }); File = $m.Path
    Bytes = "$($bytes.Length) / $($m.Bytes)"; Lines = "$lines / $($m.Lines)"; Problem = ($problems -join '; ')
  }
}
$fingerprint = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($fpText.ToString()))).Replace('-', '')

Write-Host ''
Write-Host 'Bytes and Lines are shown as actual / expected.'
$rows | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
$failed = @($rows | Where-Object Status -eq 'FAIL')
foreach ($r in $failed) { Write-Host ("FAIL  {0}: {1}" -f $r.File, $r.Problem) -ForegroundColor Red }
Write-Host ("Fingerprint: {0}" -f $fingerprint)
Write-Host ("Expected:    {0}" -f $ExpectedFingerprint)
if ($failed.Count -eq 0 -and $missingFromBundle.Count -eq 0 -and $fingerprint -eq $ExpectedFingerprint) {
  Write-Host ("RESULT: PASS. All {0} files match in length, line count and SHA-256." -f $Manifest.Count) -ForegroundColor Green
  exit 0
}
Write-Host ("RESULT: FAIL. {0} of {1} files do not match. Re-copy the bundle and run it again." -f $failed.Count, $Manifest.Count) -ForegroundColor Red
exit 1
"""

if __name__ == "__main__":
    main()
