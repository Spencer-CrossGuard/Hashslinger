<#
.SYNOPSIS
  Report viewer for the Running Tool: opens the newest scan report (or any CSV) in a window where analysts can
  look through it, search, sort, edit, save, and copy everything to the clipboard.
.DESCRIPTION
  The scan server has no spreadsheet program, so this is a small built-in one. Dot-source this file and call
  Show-HsCsvViewer -Path <csv> -Folder <report folder>. It needs HashslingerTheme.ps1 to be loaded first.
  It reads and writes only the files the person picks. It never touches Active Directory, hashes or settings.
  Saving writes UTF-8 (no BOM) with CRLF line ends and quotes only where needed, the same layout the scanner writes.
#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic

function Read-HsCsvTable([string]$Path) {
  $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
  if ($fi.Length -gt 100MB) { throw ('This file is {0:N0} MB, too big for the viewer. Use "Open in app" instead.' -f ($fi.Length / 1MB)) }
  $table = New-Object Data.DataTable
  $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($Path, (New-Object Text.UTF8Encoding($false)), $true)
  try {
    $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
    $parser.SetDelimiters(@(','))
    $parser.HasFieldsEnclosedInQuotes = $true
    $parser.TrimWhiteSpace = $false
    $header = $null
    while (-not $parser.EndOfData) {
      $fields = $parser.ReadFields()
      if ($null -eq $header) {
        $header = @($fields)
        $seen = @{}
        for ($i = 0; $i -lt $header.Count; $i++) {
          $n = [string]$header[$i]
          if ($i -eq 0) { $n = $n.TrimStart([char]0xFEFF) }   # a byte-order mark from a file saved by another program
          if (-not $n.Trim()) { $n = 'Column ' + ($i + 1) }
          $base = $n; $k = 2
          while ($seen.ContainsKey($n.ToLowerInvariant())) { $n = $base + ' (' + $k + ')'; $k++ }
          $seen[$n.ToLowerInvariant()] = $true
          $col = New-Object Data.DataColumn($n, [string]); $col.DefaultValue = ''
          [void]$table.Columns.Add($col)
        }
        $table.BeginLoadData()
        continue
      }
      $row = $table.NewRow()
      for ($i = 0; $i -lt $table.Columns.Count -and $i -lt $fields.Count; $i++) { $row[$i] = [string]$fields[$i] }
      [void]$table.Rows.Add($row)
    }
    if ($null -eq $header) { throw 'The file is empty.' }
    $table.EndLoadData()
  } finally { $parser.Close() }
  $table.AcceptChanges()
  return , $table
}

function ConvertTo-HsCsvCell([string]$v) {
  if ($v.IndexOfAny([char[]]@(',', '"', "`r", "`n")) -ge 0) { return '"' + $v.Replace('"', '""') + '"' }
  return $v
}

function Get-HsTableText([Data.DataTable]$Table, [string]$Mode) {
  # Mode 'csv' = a CSV file's text. Mode 'tsv' = tab separated, which pastes into Excel, Outlook or Word as a table.
  $sb = New-Object Text.StringBuilder
  $cols = @($Table.Columns | ForEach-Object { $_.ColumnName })
  $clean = { param($t) ($t -replace "[\t\r\n]+", ' ') }
  if ($Mode -eq 'csv') { [void]$sb.Append((($cols | ForEach-Object { ConvertTo-HsCsvCell $_ }) -join ',') + "`r`n") }
  else { [void]$sb.Append((($cols | ForEach-Object { & $clean $_ }) -join "`t") + "`r`n") }
  foreach ($r in $Table.Rows) {
    if ($r.RowState -eq 'Deleted') { continue }
    $cells = New-Object 'System.Collections.Generic.List[string]'
    foreach ($c in $Table.Columns) {
      $val = [string]$r[$c]
      if ($Mode -eq 'csv') { $cells.Add((ConvertTo-HsCsvCell $val)) } else { $cells.Add((& $clean $val)) }
    }
    [void]$sb.Append(($cells -join $(if ($Mode -eq 'csv') { ',' } else { "`t" })) + "`r`n")
  }
  return $sb.ToString()
}

function Write-HsCsvFile([Data.DataTable]$Table, [string]$Path) {
  $text = Get-HsTableText $Table 'csv'
  $tmp = $Path + '.tmp' + [guid]::NewGuid().ToString('N').Substring(0, 6)
  try {
    [IO.File]::WriteAllText($tmp, $text, (New-Object Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($tmp, $Path, [NullString]::Value) } else { [IO.File]::Move($tmp, $Path) }
  } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
}

function Set-HsClipboardText([string]$Text) {
  for ($i = 0; $i -lt 5; $i++) {
    try { [Windows.Forms.Clipboard]::SetText($Text); return $true } catch { Start-Sleep -Milliseconds 120 }
  }
  try { $Text | & "$env:SystemRoot\System32\clip.exe"; return $true } catch { return $false }
}

function Show-HsCsvViewer {
  param([string]$Path = '', [string]$Folder = '')
  $C = $script:HsC
  $V = @{ Path = $Path; Folder = $Folder; Table = $null; Dirty = $false; Loading = $false }

  # pick the newest report when no file is given
  if (-not $V.Path -and $V.Folder) {
    try { $f = Get-ChildItem -LiteralPath $V.Folder -Filter 'report_*.csv' -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { $V.Path = $f.FullName } } catch { }
  }

  $wa = [Windows.Forms.Screen]::PrimaryScreen.WorkingArea
  $f = New-Object Windows.Forms.Form -Property @{
    Text = 'Hashslinger report viewer'; Width = [Math]::Min(1180, $wa.Width - 20); Height = [Math]::Min(720, $wa.Height - 20)
    StartPosition = 'CenterParent'; MinimumSize = New-Object Drawing.Size(860, 480); KeyPreview = $true
  }
  $hdr = Add-HsHeader $f 'Report viewer' 'Look through, search, edit and copy a scan report' 76 $false

  # toolbar row 1: file + search
  $btnOpen = New-Object Windows.Forms.Button -Property @{ Text = 'Open file...'; Left = 12; Top = 86; Width = 100; Height = 30 }
  $btnLatest = New-Object Windows.Forms.Button -Property @{ Text = 'Newest report'; Left = 118; Top = 86; Width = 110; Height = 30 }
  $btnReload = New-Object Windows.Forms.Button -Property @{ Text = 'Reload'; Left = 234; Top = 86; Width = 80; Height = 30 }
  $lblFind = New-Object Windows.Forms.Label -Property @{ Text = 'Search'; Left = 336; Top = 92; Width = 50; Height = 20; ForeColor = $C.Muted }
  $txtFind = New-Object Windows.Forms.TextBox -Property @{ Left = 388; Top = 89; Width = 260; Anchor = 'Top,Left' }
  $btnClear = New-Object Windows.Forms.Button -Property @{ Text = 'Clear'; Left = 654; Top = 86; Width = 64; Height = 30 }

  # toolbar row 2: edit + save + copy
  $btnCopyAll = New-Object Windows.Forms.Button -Property @{ Text = 'Copy everything'; Left = 12; Top = 122; Width = 130; Height = 30; Tag = 'primary' }
  $btnCopySel = New-Object Windows.Forms.Button -Property @{ Text = 'Copy selected'; Left = 148; Top = 122; Width = 110; Height = 30 }
  $btnCopyCsv = New-Object Windows.Forms.Button -Property @{ Text = 'Copy as CSV text'; Left = 264; Top = 122; Width = 120; Height = 30 }
  $btnAdd = New-Object Windows.Forms.Button -Property @{ Text = 'Add row'; Left = 410; Top = 122; Width = 80; Height = 30 }
  $btnDel = New-Object Windows.Forms.Button -Property @{ Text = 'Delete selected'; Left = 496; Top = 122; Width = 110; Height = 30 }
  $btnSave = New-Object Windows.Forms.Button -Property @{ Text = 'Save'; Left = 632; Top = 122; Width = 80; Height = 30; Tag = 'primary' }
  $btnSaveAs = New-Object Windows.Forms.Button -Property @{ Text = 'Save as...'; Left = 718; Top = 122; Width = 90; Height = 30 }

  $grid = New-Object Windows.Forms.DataGridView -Property @{
    Left = 12; Top = 160; Width = $f.ClientSize.Width - 24; Height = $f.ClientSize.Height - 160 - 40; Anchor = 'Top,Bottom,Left,Right'
    AllowUserToAddRows = $false; AllowUserToDeleteRows = $true; AllowUserToOrderColumns = $true
    SelectionMode = 'FullRowSelect'; MultiSelect = $true; RowHeadersWidth = 28
    AutoSizeColumnsMode = 'None'; ClipboardCopyMode = 'EnableAlwaysIncludeHeaderText'
    BackgroundColor = [Drawing.Color]::White; BorderStyle = 'FixedSingle'; CellBorderStyle = 'SingleHorizontal'
    ColumnHeadersHeight = 34; ColumnHeadersHeightSizeMode = 'DisableResizing'; EnableHeadersVisualStyles = $false
    GridColor = $C.Line; RowTemplate = (New-Object Windows.Forms.DataGridViewRow -Property @{ Height = 24 })
  }
  Set-HsDoubleBuffer $grid
  $grid.ColumnHeadersDefaultCellStyle.BackColor = $C.Indigo
  $grid.ColumnHeadersDefaultCellStyle.ForeColor = [Drawing.Color]::White
  $grid.ColumnHeadersDefaultCellStyle.Font = New-HsFont 9 'Bold'
  $grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $C.Indigo
  $grid.DefaultCellStyle.Font = New-HsFont 9
  $grid.DefaultCellStyle.SelectionBackColor = $C.Light
  $grid.DefaultCellStyle.SelectionForeColor = $C.Text
  $grid.AlternatingRowsDefaultCellStyle.BackColor = $C.Soft

  $lblStatus = New-Object Windows.Forms.Label -Property @{ Left = 12; Top = $f.ClientSize.Height - 30; Width = $f.ClientSize.Width - 24; Height = 22; Anchor = 'Bottom,Left,Right'; ForeColor = $C.Muted }
  $f.Controls.AddRange(@($btnOpen, $btnLatest, $btnReload, $lblFind, $txtFind, $btnClear, $btnCopyAll, $btnCopySel, $btnCopyCsv, $btnAdd, $btnDel, $btnSave, $btnSaveAs, $grid, $lblStatus))
  Set-HsTheme $f
  $f.BackColor = $C.Bg

  # ---- helpers (script-block variables, so the event handlers can reach them)
  $updateStatus = {
    $name = if ($V.Path) { [IO.Path]::GetFileName($V.Path) } else { '(no file)' }
    $f.Text = 'Hashslinger report viewer: ' + $name + $(if ($V.Dirty) { ' *' } else { '' })
    if ($V.Table) {
      $total = $V.Table.Rows.Count; $shown = $grid.Rows.Count
      $lblStatus.Text = ('{0:N0} rows' -f $total) + $(if ($shown -ne $total) { (', {0:N0} shown by the search' -f $shown) } else { '' }) + '   |   ' + $(if ($V.Dirty) { 'UNSAVED CHANGES' } else { 'no changes' }) + '   |   ' + $V.Path
    } else { $lblStatus.Text = 'Open a CSV file to begin.' }
    $lblStatus.ForeColor = $(if ($V.Dirty) { $C.Red } else { $C.Muted })
  }
  $applyFilter = {
    if (-not $V.Table) { return }
    $q = $txtFind.Text.Trim()
    if (-not $q) { $V.Table.DefaultView.RowFilter = ''; & $updateStatus; return }
    $like = $q.Replace("'", "''")
    $like = [regex]::Replace($like, '([\[\]\*%])', '[$1]')
    $parts = foreach ($c in $V.Table.Columns) { '[' + $c.ColumnName.Replace(']', '\]') + "] LIKE '%" + $like + "%'" }
    try { $V.Table.DefaultView.RowFilter = ($parts -join ' OR ') } catch { $V.Table.DefaultView.RowFilter = '' }
    & $updateStatus
  }
  $loadFile = {
    param([string]$p)
    try {
      $t = Read-HsCsvTable $p
    } catch {
      [void][Windows.Forms.MessageBox]::Show('Cannot open the file:' + "`r`n" + $p + "`r`n`r`n" + $_.Exception.Message, 'Hashslinger')
      return
    }
    $V.Loading = $true
    $V.Table = $t; $V.Path = $p; $V.Dirty = $false
    $t.Add_ColumnChanged({ if (-not $V.Loading) { $V.Dirty = $true; & $updateStatus } })
    $t.Add_RowDeleted({ if (-not $V.Loading) { $V.Dirty = $true; & $updateStatus } })
    $t.Add_TableNewRow({ if (-not $V.Loading) { $V.Dirty = $true; & $updateStatus } })
    $txtFind.Text = ''
    $grid.DataSource = $null
    $grid.DataSource = $t.DefaultView
    foreach ($col in $grid.Columns) { $col.SortMode = 'Automatic'; $col.MinimumWidth = 60 }
    try { $grid.AutoResizeColumns('DisplayedCells') } catch { }
    foreach ($col in $grid.Columns) { if ($col.Width -gt 420) { $col.Width = 420 } }
    # the widest column (Flag Reason in a report) soaks up any extra room, so the list grows and shrinks with the window
    try {
      $wide = $null
      foreach ($col in $grid.Columns) { if (-not $wide -or $col.Width -gt $wide.Width) { $wide = $col } }
      if ($wide) { $mw = $wide.Width; $wide.AutoSizeMode = 'Fill'; $wide.MinimumWidth = [Math]::Max(60, $mw); $wide.FillWeight = 100 }
    } catch { }
    $V.Loading = $false
    & $updateStatus
  }
  $confirmDiscard = {
    if (-not $V.Dirty) { return $true }
    $r = [Windows.Forms.MessageBox]::Show('You have unsaved changes. Throw them away?', 'Hashslinger', 'YesNo', 'Warning')
    return ($r -eq 'Yes')
  }
  $saveTo = {
    param([string]$p)
    try { $grid.EndEdit() | Out-Null; $null = $grid.CurrentCell = $null } catch { }
    try {
      Write-HsCsvFile $V.Table $p
      $V.Path = $p; $V.Dirty = $false
      $V.Table.AcceptChanges()
      & $updateStatus
      return $true
    } catch {
      [void][Windows.Forms.MessageBox]::Show('Could not save:' + "`r`n" + $_.Exception.Message + "`r`n`r`nTry Save as... and pick a folder you can write to.", 'Hashslinger')
      return $false
    }
  }
  $copy = {
    param([string]$text, [string]$what)
    if (Set-HsClipboardText $text) { $lblStatus.ForeColor = $C.Green; $lblStatus.Text = 'Copied ' + $what + ' to the clipboard. Paste it into Excel, Outlook, Teams or Notepad.' }
    else { [void][Windows.Forms.MessageBox]::Show('Could not reach the clipboard. Try again, or use Save as... instead.', 'Hashslinger') }
  }

  # ---- events
  $txtFind.Add_TextChanged({ & $applyFilter })
  $btnClear.Add_Click({ $txtFind.Text = '' })
  $btnOpen.Add_Click({
    if (-not (& $confirmDiscard)) { return }
    $d = New-Object Windows.Forms.OpenFileDialog -Property @{ Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'; Title = 'Open a CSV file' }
    try { $start = if ($V.Folder -and (Test-Path -LiteralPath $V.Folder)) { $V.Folder } elseif ($V.Path) { Split-Path -Parent $V.Path } else { '' }; if ($start) { $d.InitialDirectory = $start } } catch { }
    if ($d.ShowDialog($f) -eq 'OK') { & $loadFile $d.FileName }
  })
  $btnLatest.Add_Click({
    if (-not (& $confirmDiscard)) { return }
    try {
      $n = Get-ChildItem -LiteralPath $V.Folder -Filter 'report_*.csv' -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 1
      if ($n) { & $loadFile $n.FullName } else { [void][Windows.Forms.MessageBox]::Show('There is no report yet.', 'Hashslinger') }
    } catch { [void][Windows.Forms.MessageBox]::Show('Cannot read the reports folder: ' + $_.Exception.Message, 'Hashslinger') }
  })
  $btnReload.Add_Click({ if ($V.Path -and (& $confirmDiscard)) { & $loadFile $V.Path } })
  $btnCopyAll.Add_Click({ if ($V.Table) { & $copy (Get-HsTableText $V.Table 'tsv') ('all {0:N0} rows' -f $V.Table.Rows.Count) } })
  $btnCopyCsv.Add_Click({ if ($V.Table) { & $copy (Get-HsTableText $V.Table 'csv') ('all {0:N0} rows as CSV text' -f $V.Table.Rows.Count) } })
  $btnCopySel.Add_Click({
    try {
      if ($grid.SelectedRows.Count -eq 0) { [void][Windows.Forms.MessageBox]::Show('Click a row first (Ctrl or Shift to pick several).', 'Hashslinger'); return }
      $d = $grid.GetClipboardContent()
      if ($d) { [Windows.Forms.Clipboard]::SetDataObject($d, $true); $lblStatus.ForeColor = $C.Green; $lblStatus.Text = ('Copied {0} selected rows to the clipboard.' -f $grid.SelectedRows.Count) }
    } catch { [void][Windows.Forms.MessageBox]::Show('Could not copy: ' + $_.Exception.Message, 'Hashslinger') }
  })
  $btnAdd.Add_Click({
    if (-not $V.Table) { return }
    try { $r = $V.Table.NewRow(); $V.Table.Rows.Add($r); $V.Dirty = $true; & $updateStatus
      $grid.ClearSelection(); $last = $grid.Rows.Count - 1; if ($last -ge 0) { $grid.Rows[$last].Selected = $true; $grid.FirstDisplayedScrollingRowIndex = $last } } catch { }
  })
  $btnDel.Add_Click({
    if (-not $V.Table -or $grid.SelectedRows.Count -eq 0) { [void][Windows.Forms.MessageBox]::Show('Click the row(s) to delete first.', 'Hashslinger'); return }
    $n = $grid.SelectedRows.Count
    if ([Windows.Forms.MessageBox]::Show("Delete $n selected row(s)? This only changes the file when you click Save.", 'Hashslinger', 'YesNo', 'Question') -ne 'Yes') { return }
    $rows = @($grid.SelectedRows | ForEach-Object { $_.DataBoundItem.Row })
    foreach ($r in $rows) { try { $r.Delete() } catch { } }
    & $updateStatus
  })
  $btnSave.Add_Click({
    if (-not $V.Table -or -not $V.Path) { return }
    $m = 'Save over this file?' + "`r`n`r`n" + $V.Path + "`r`n`r`nChoose No to keep the original and save a copy instead."
    $a = [Windows.Forms.MessageBox]::Show($m, 'Hashslinger', 'YesNoCancel', 'Question')
    if ($a -eq 'Yes') { [void](& $saveTo $V.Path) } elseif ($a -eq 'No') { $btnSaveAs.PerformClick() }
  })
  $btnSaveAs.Add_Click({
    if (-not $V.Table) { return }
    $d = New-Object Windows.Forms.SaveFileDialog -Property @{ Filter = 'CSV files (*.csv)|*.csv'; Title = 'Save a copy'; DefaultExt = 'csv'; OverwritePrompt = $true }
    try { if ($V.Path) { $d.FileName = [IO.Path]::GetFileNameWithoutExtension($V.Path) + '_edited.csv'; $d.InitialDirectory = (Split-Path -Parent $V.Path) } } catch { }
    if ($d.ShowDialog($f) -eq 'OK') { [void](& $saveTo $d.FileName) }
  })
  $f.Add_KeyDown({
    param($s, $e)
    if ($e.Control -and $e.KeyCode -eq 'S') { $e.SuppressKeyPress = $true; $btnSave.PerformClick() }
    elseif ($e.Control -and $e.KeyCode -eq 'F') { $e.SuppressKeyPress = $true; $txtFind.Focus(); $txtFind.SelectAll() }
  })
  $f.Add_FormClosing({
    param($s, $e)
    if ($V.Dirty) {
      $r = [Windows.Forms.MessageBox]::Show('You have unsaved changes. Close without saving?', 'Hashslinger', 'YesNo', 'Warning')
      if ($r -ne 'Yes') { $e.Cancel = $true }
    }
  })
  $grid.Add_DataError({ param($s, $e) $e.ThrowException = $false })

  $f.Add_Shown({
    if ($V.Path) { & $loadFile $V.Path } else { & $updateStatus }
  })
  [void]$f.ShowDialog()
}
