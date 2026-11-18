<#
.SYNOPSIS
  Shared helpers for the Setup wizard and the Admin tool (dot-source this file).
.DESCRIPTION
  * ONE config file (<root>\config\hashslinger.json): read with defaults filled in, written with a backup.
    The exe reads the same file and ignores keys it does not use, so setup-only settings live there too.
  * Read-only AD scope list (domain, containers, OUs, DCs). Nothing here writes to AD.
  * Nested OU picker: a real tree (like AD), search that keeps parents visible, a list of what is selected.
#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ================================================================ config
function Get-HsDefaultConfig([string]$Root) {
  [ordered]@{
    install_root = $Root
    mode = 'live'
    replication = 'bulk'
    per_account_threshold = 5000
    workers = 4
    target_server = ''
    target_ous = @()
    account_types = @('User', 'Service')
    uac = [ordered]@{ require_flags = @(); exclude_flags = @('SMARTCARD_REQUIRED') }
    ntds_path = ''
    system_hive_path = ''
    check_duplicates = $false
    cadence = 'Weekly'
    schedule_day = 'Sunday'
    schedule_time = '02:00'
    retention_days = 90
    engine_timeout_seconds = 86400
    hash_store_path = "$Root\data\store\master.ntlm"
    staging_path = "$Root\data\staging"
    log_path = "$Root\logs\audit.jsonl"
    output_path = "$Root\reports"
    allowed_output_roots = @("$Root\reports")
    request_dir = "$Root\requests"
    status_path = "$Root\status\status.json"
    pattern_rules_path = "$Root\config\pattern_rules.json"
    engine_script = "$Root\app\powershell\Get-AccountHashes.ps1"
    require_encrypted_volume = $false
    authorized_edipis = @()
    gmsa_name = 'svc-hashslinger'
    run_server = $env:COMPUTERNAME
    analyst_group = ''
    wordlists = [ordered]@{ hibp = ''; rockyou = ''; custom = '' }
    dsinternals_offline_path = ''
    min_free_space_gb = [ordered]@{ store = 60; output = 5 }
  }
}

# PSCustomObject (from ConvertFrom-Json) -> ordered hashtable. The leading comma keeps arrays from being unrolled,
# so one-element and empty arrays survive the round trip (the exe needs real JSON arrays).
function ConvertTo-HsHashtable($o) {
  if ($null -eq $o) { return $null }
  if ($o -is [System.Management.Automation.PSCustomObject]) {
    $h = [ordered]@{}
    foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = ConvertTo-HsHashtable $p.Value }
    return $h
  }
  if (($o -is [System.Collections.IList]) -and ($o -isnot [string])) {
    $arr = @(foreach ($i in $o) { ConvertTo-HsHashtable $i })
    return , $arr
  }
  return $o
}

function Merge-HsDefaults($cfg, $def) {
  foreach ($k in @($def.Keys)) {
    if (-not $cfg.Contains($k)) { $cfg[$k] = $def[$k] }
    elseif (($def[$k] -is [System.Collections.Specialized.OrderedDictionary]) -and ($cfg[$k] -is [System.Collections.Specialized.OrderedDictionary])) {
      [void](Merge-HsDefaults $cfg[$k] $def[$k])
    }
  }
  return $cfg
}

function Get-HsRootFromConfigPath([string]$Path) {
  Split-Path -Parent (Split-Path -Parent ([IO.Path]::GetFullPath($Path)))
}

function Read-HsConfig([string]$Path) {
  $def = Get-HsDefaultConfig (Get-HsRootFromConfigPath $Path)
  if (-not (Test-Path $Path)) { return $def }
  $cfg = ConvertTo-HsHashtable (Get-Content $Path -Raw | ConvertFrom-Json)
  return (Merge-HsDefaults $cfg $def)
}

function Save-HsConfig($cfg, [string]$Path) {
  New-Item -ItemType Directory -Force (Split-Path -Parent $Path) | Out-Null
  if (Test-Path $Path) {
    Copy-Item $Path ("$Path.bak-{0:yyyyMMddHHmmss}" -f (Get-Date))
    Get-ChildItem "$Path.bak-*" | Sort-Object LastWriteTime -Descending | Select-Object -Skip 10 | Remove-Item -ErrorAction SilentlyContinue
  }
  $cfg | ConvertTo-Json -Depth 8 | Set-Content $Path -Encoding UTF8
}

function Get-HsCfgValue($cfg, [string]$dotted) {
  $o = $cfg
  foreach ($k in $dotted -split '\.') { if ($null -eq $o -or -not $o.Contains($k)) { return $null }; $o = $o[$k] }
  return $o
}
function Set-HsCfgValue($cfg, [string]$dotted, $value) {
  $parts = $dotted -split '\.'
  $o = $cfg
  for ($i = 0; $i -lt $parts.Count - 1; $i++) { if (-not $o.Contains($parts[$i])) { $o[$parts[$i]] = [ordered]@{} }; $o = $o[$parts[$i]] }
  $o[$parts[-1]] = $value
}

# ================================================================ read-only AD scope list
function Get-HsAdScope {
  $r = @{ Domain = ''; DomainDn = ''; Dns = @(); DCs = @(); DcDefault = ''; Error = '' }
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $dom = Get-ADDomain
    $r.Domain = $dom.DNSRoot
    $r.DomainDn = $dom.DistinguishedName
    $list = New-Object 'System.Collections.Generic.List[string]'
    $list.Add($dom.DistinguishedName)
    foreach ($c in 'Users', 'Computers') {
      $dn = "CN=$c,$($dom.DistinguishedName)"
      if ([DirectoryServices.DirectoryEntry]::Exists("LDAP://$dn")) { $list.Add($dn) }
    }
    foreach ($ou in (Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName)) { $list.Add($ou) }
    $r.Dns = @($list | Select-Object -Unique)
    try { $r.DCs = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName | Sort-Object) } catch { }
    try { $r.DcDefault = [string]((Get-ADDomainController -Discover).HostName | Select-Object -First 1) } catch { }
  }
  catch { $r.Error = $_.Exception.Message }
  return $r
}

# ================================================================ nested OU picker
function Split-HsDn([string]$dn) { [regex]::Split($dn, '(?<!\\),') }
function Get-HsParentDn([string]$dn) {
  $p = @(Split-HsDn $dn)
  if ($p.Count -le 1) { return '' }
  return ($p[1..($p.Count - 1)] -join ',')
}
function Get-HsDnLabel([string]$dn) {
  $parts = @(Split-HsDn $dn)
  if (@($parts | Where-Object { $_ -notmatch '^DC=' }).Count -eq 0) {
    return (($parts | ForEach-Object { $_.Substring(3) }) -join '.')   # domain root: corp.contoso.com
  }
  $first = $parts[0]
  $v = $first.Substring($first.IndexOf('=') + 1) -replace '\\,', ','
  if ($first -match '^CN=') { return "$v  [container]" }
  return $v
}

# One picker per process; its state lives in $script:HsOu so the event handlers can reach it.
function New-HsOuPicker {
  param([Windows.Forms.Control]$Parent, [int]$X, [int]$Y, [int]$Width, [int]$Height, [string[]]$Dns)
  $c = @{ Dns = New-Object 'System.Collections.Generic.List[string]'; Guard = $false
          Picked = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
  foreach ($d in $Dns) { if ($d) { $c.Dns.Add($d) } }
  $script:HsOu = $c

  $treeH = [Math]::Max(120, $Height - 140)
  $lblS = New-Object Windows.Forms.Label -Property @{ Text = 'Search'; Left = $X; Top = $Y + 4; Width = 48 }
  $c.Search = New-Object Windows.Forms.TextBox -Property @{ Left = $X + 52; Top = $Y; Width = $Width - 52 - 360 }
  $c.Count = New-Object Windows.Forms.Label -Property @{ Left = $X + $Width - 350; Top = $Y + 4; Width = 250; Text = '' }
  $btnClear = New-Object Windows.Forms.Button -Property @{ Text = 'Clear all'; Left = $X + $Width - 92; Top = $Y - 2; Width = 90; Height = 26 }
  $c.Tree = New-Object Windows.Forms.TreeView -Property @{ Left = $X; Top = $Y + 30; Width = $Width; Height = $treeH; CheckBoxes = $true; HideSelection = $false }
  $lblSel = New-Object Windows.Forms.Label -Property @{ Text = 'Scanned scopes (each includes everything underneath it). Double-click one to remove it:'; Left = $X; Top = $Y + 34 + $treeH; Width = $Width; Height = 18 }
  $c.List = New-Object Windows.Forms.ListBox -Property @{ Left = $X; Top = $Y + 54 + $treeH; Width = $Width; Height = 60 }
  $lblM = New-Object Windows.Forms.Label -Property @{ Text = 'Add a DN by hand'; Left = $X; Top = $Y + 120 + $treeH; Width = 110 }
  $c.Manual = New-Object Windows.Forms.TextBox -Property @{ Left = $X + 112; Top = $Y + 116 + $treeH; Width = $Width - 112 - 70 }
  $btnAdd = New-Object Windows.Forms.Button -Property @{ Text = 'Add'; Left = $X + $Width - 66; Top = $Y + 114 + $treeH; Width = 64; Height = 26 }
  $Parent.Controls.AddRange(@($lblS, $c.Search, $c.Count, $btnClear, $c.Tree, $lblSel, $c.List, $lblM, $c.Manual, $btnAdd))

  $c.Search.Add_TextChanged({ Update-HsOuTree })
  $c.Tree.Add_AfterCheck({
    param($s, $e)
    if ($script:HsOu.Guard) { return }
    $dn = [string]$e.Node.Tag
    if ($e.Node.Checked) { [void]$script:HsOu.Picked.Add($dn) } else { [void]$script:HsOu.Picked.Remove($dn) }
    Update-HsOuSelectionList
  })
  $c.List.Add_DoubleClick({
    $item = $script:HsOu.List.SelectedItem
    if ($item) { [void]$script:HsOu.Picked.Remove([string]$item); Update-HsOuTree }
  })
  $btnClear.Add_Click({ $script:HsOu.Picked.Clear(); Update-HsOuTree })
  $btnAdd.Add_Click({
    $v = $script:HsOu.Manual.Text.Trim()
    if ($v) {
      if (-not $script:HsOu.Dns.Contains($v)) { $script:HsOu.Dns.Add($v) }
      [void]$script:HsOu.Picked.Add($v)
      $script:HsOu.Manual.Text = ''
      Update-HsOuTree
    }
  })
  Update-HsOuTree
}

function Update-HsOuTree {
  $c = $script:HsOu
  $q = $c.Search.Text.Trim()
  $c.Guard = $true
  $c.Tree.BeginUpdate()
  $c.Tree.Nodes.Clear()
  # with a search, show the matches AND their ancestors so you always see where a match sits
  $include = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($dn in $c.Dns) {
    if ($q -eq '' -or $dn.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
      $cur = $dn
      while ($cur -and $include.Add($cur)) { $cur = Get-HsParentDn $cur }
    }
  }
  $nodes = @{}
  foreach ($dn in @($include | Sort-Object { @(Split-HsDn $_).Count }, { $_ })) {
    $n = New-Object Windows.Forms.TreeNode (Get-HsDnLabel $dn)
    $n.Tag = $dn
    $n.Checked = $c.Picked.Contains($dn)
    $pk = (Get-HsParentDn $dn).ToLowerInvariant()
    if ($pk -and $nodes.ContainsKey($pk)) { [void]$nodes[$pk].Nodes.Add($n) } else { [void]$c.Tree.Nodes.Add($n) }
    $nodes[$dn.ToLowerInvariant()] = $n
  }
  if ($q -ne '') { $c.Tree.ExpandAll() }
  else {
    foreach ($n in $c.Tree.Nodes) { $n.Expand() }
    foreach ($p in $c.Picked) { $nd = $nodes[$p.ToLowerInvariant()]; if ($nd -and $nd.Parent) { $nd.Parent.Expand() } }
  }
  $c.Tree.EndUpdate()
  $c.Guard = $false
  Update-HsOuSelectionList
}

# What is really scanned: ticked entries with the ones already covered by a ticked parent removed.
function Get-HsOuSelection {
  $all = @($script:HsOu.Picked)
  $res = @()
  foreach ($d in $all) {
    $covered = $false
    foreach ($o in $all) {
      if (($o -ne $d) -and $d.EndsWith(',' + $o, [StringComparison]::OrdinalIgnoreCase)) { $covered = $true; break }
    }
    if (-not $covered) { $res += $d }
  }
  return $res   # callers always wrap this in @() so zero or one item still become an array
}

function Update-HsOuSelectionList {
  $c = $script:HsOu
  $c.List.Items.Clear()
  $sel = @(Get-HsOuSelection)
  foreach ($d in ($sel | Sort-Object)) { [void]$c.List.Items.Add($d) }
  $c.Count.Text = '{0} scope(s) selected' -f $sel.Count
}

function Set-HsOuSelection([string[]]$dns) {
  $c = $script:HsOu
  $c.Picked.Clear()
  foreach ($d in $dns) {
    if ($d) { if (-not $c.Dns.Contains($d)) { $c.Dns.Add($d) }; [void]$c.Picked.Add($d) }
  }
  Update-HsOuTree
}

function Set-HsOuDns([string[]]$dns) {
  $c = $script:HsOu
  $c.Dns.Clear()
  foreach ($d in $dns) { if ($d) { $c.Dns.Add($d) } }
  foreach ($p in $c.Picked) { if (-not $c.Dns.Contains($p)) { $c.Dns.Add($p) } }
  Update-HsOuTree
}
