<#
.SYNOPSIS
  Analyst wrapper: OU dropdown (from config), output folder picker, Run Scan.
.DESCRIPTION
  The analyst must enter an EDIPI and a reason; both are stored in the request file and written to
  the audit log by the GMSA task (which also validates them). The request folder lets analysts create
  files but not list or read them.
  Runs as the analyst. It never touches AD or hashes. It writes a request file
  (OU + output folder) and starts the on-demand scheduled task, which runs under the
  GMSA and re-validates the request against config. No free-text input anywhere.
#>
param([string]$ConfigPath = 'D:\Hashslinger\config\hashslinger.json')
Add-Type -AssemblyName System.Windows.Forms
$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$taskName = 'Hashslinger-OnDemand'

$form = New-Object Windows.Forms.Form -Property @{ Text = 'Hashslinger'; Width = 520; Height = 350; FormBorderStyle = 'FixedDialog'; MaximizeBox = $false }
$ouLbl = New-Object Windows.Forms.Label -Property @{ Text = 'Organizational Unit'; Left = 15; Top = 15; Width = 200 }
$ou = New-Object Windows.Forms.ComboBox -Property @{ Left = 15; Top = 38; Width = 470; DropDownStyle = 'DropDownList' }
$cfg.target_ous | ForEach-Object { [void]$ou.Items.Add($_) }
if ($ou.Items.Count) { $ou.SelectedIndex = 0 }
$outLbl = New-Object Windows.Forms.Label -Property @{ Text = 'Output folder'; Left = 15; Top = 70; Width = 200 }
$out = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 93; Width = 380; ReadOnly = $true }
$browse = New-Object Windows.Forms.Button -Property @{ Text = 'Browse...'; Left = 405; Top = 91; Width = 80 }
$edLbl = New-Object Windows.Forms.Label -Property @{ Text = 'EDIPI (10 digits)'; Left = 15; Top = 125; Width = 200 }
$ed = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 146; Width = 150; MaxLength = 10 }
$rsLbl = New-Object Windows.Forms.Label -Property @{ Text = 'Reason for this run (ticket / justification)'; Left = 15; Top = 178; Width = 300 }
$rs = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 199; Width = 470; MaxLength = 500 }
$run = New-Object Windows.Forms.Button -Property @{ Text = 'Run Scan'; Left = 15; Top = 240; Width = 120; Enabled = $false }
$prog = New-Object Windows.Forms.Button -Property @{ Text = 'View progress'; Left = 15; Top = 275; Width = 120 }
$prog.Add_Click({ Start-Process powershell.exe -ArgumentList '-NoProfile', '-File', (Join-Path $PSScriptRoot 'Show-HashslingerProgress.ps1'), '-StatusPath', $cfg.status_path })
$status = New-Object Windows.Forms.Label -Property @{ Left = 150; Top = 245; Width = 340; Text = '' }

function Check { $run.Enabled = ($out.Text -ne '' -and $ed.Text -match '^\d{10}$' -and $rs.Text.Trim().Length -ge 10) }
$ed.Add_TextChanged({ Check }); $rs.Add_TextChanged({ Check })
$browse.Add_Click({
  $d = New-Object Windows.Forms.FolderBrowserDialog
  if ($cfg.allowed_output_roots.Count) { $d.SelectedPath = $cfg.allowed_output_roots[0] }
  if ($d.ShowDialog() -eq 'OK') { $out.Text = $d.SelectedPath; Check }
})
$run.Add_Click({
  $run.Enabled = $false
  $req = @{ ou = [string]$ou.SelectedItem; output_dir = $out.Text; edipi = $ed.Text; reason = $rs.Text.Trim(); requested_by = "$env:USERDOMAIN\$env:USERNAME" }
  $file = Join-Path $cfg.request_dir ("req_{0}.json" -f [guid]::NewGuid())
  $req | ConvertTo-Json | Set-Content -Path $file -Encoding UTF8
  try {
    Start-ScheduledTask -TaskName $taskName
    $status.Text = 'Scan requested. Check the output folder and audit log for results.'
  } catch {
    $status.Text = 'Could not start the scan. Contact the DCO lead.'
  }
})
$form.Controls.AddRange(@($ouLbl, $ou, $outLbl, $out, $browse, $edLbl, $ed, $rsLbl, $rs, $run, $prog, $status))
[void]$form.ShowDialog()
