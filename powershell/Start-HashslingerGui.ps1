<#
.SYNOPSIS
  Analyst wrapper: OU dropdown (from config), output folder picker, Run Scan.
.DESCRIPTION
  Runs as the analyst. It never touches AD or hashes. It writes a request file
  (OU + output folder) and starts the on-demand scheduled task, which runs under the
  GMSA and re-validates the request against config. No free-text input anywhere.
#>
param([string]$ConfigPath = 'D:\Hashslinger\config\hashslinger.json')
Add-Type -AssemblyName System.Windows.Forms
$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$taskName = 'Hashslinger-OnDemand'

$form = New-Object Windows.Forms.Form -Property @{ Text = 'Hashslinger'; Width = 520; Height = 230; FormBorderStyle = 'FixedDialog'; MaximizeBox = $false }
$ouLbl = New-Object Windows.Forms.Label -Property @{ Text = 'Organizational Unit'; Left = 15; Top = 15; Width = 200 }
$ou = New-Object Windows.Forms.ComboBox -Property @{ Left = 15; Top = 38; Width = 470; DropDownStyle = 'DropDownList' }
$cfg.target_ous | ForEach-Object { [void]$ou.Items.Add($_) }
if ($ou.Items.Count) { $ou.SelectedIndex = 0 }
$outLbl = New-Object Windows.Forms.Label -Property @{ Text = 'Output folder'; Left = 15; Top = 70; Width = 200 }
$out = New-Object Windows.Forms.TextBox -Property @{ Left = 15; Top = 93; Width = 380; ReadOnly = $true }
$browse = New-Object Windows.Forms.Button -Property @{ Text = 'Browse...'; Left = 405; Top = 91; Width = 80 }
$run = New-Object Windows.Forms.Button -Property @{ Text = 'Run Scan'; Left = 15; Top = 135; Width = 120; Enabled = $false }
$status = New-Object Windows.Forms.Label -Property @{ Left = 150; Top = 140; Width = 340; Text = '' }

$browse.Add_Click({
  $d = New-Object Windows.Forms.FolderBrowserDialog
  if ($cfg.allowed_output_roots.Count) { $d.SelectedPath = $cfg.allowed_output_roots[0] }
  if ($d.ShowDialog() -eq 'OK') { $out.Text = $d.SelectedPath; $run.Enabled = $true }
})
$run.Add_Click({
  $run.Enabled = $false
  $req = @{ ou = [string]$ou.SelectedItem; output_dir = $out.Text; requested_by = "$env:USERDOMAIN\$env:USERNAME" }
  $file = Join-Path $cfg.request_dir ("req_{0}.json" -f [guid]::NewGuid())
  $req | ConvertTo-Json | Set-Content -Path $file -Encoding UTF8
  try {
    Start-ScheduledTask -TaskName $taskName
    $status.Text = 'Scan requested. Check the output folder and audit log for results.'
  } catch {
    $status.Text = 'Could not start the scan. Contact the DCO lead.'
  }
})
$form.Controls.AddRange(@($ouLbl, $ou, $outLbl, $out, $browse, $run, $status))
[void]$form.ShowDialog()
