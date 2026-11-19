<#
.SYNOPSIS
  The shared look of the Hashslinger windows: banner header with a drawn logo, flat buttons, cards, owner-drawn tabs,
  a gradient progress bar, a 7-step pipeline graphic, tiles, a donut chart and bar chart.
.DESCRIPTION
  Everything is drawn with GDI+ in code. There are no image files and nothing is downloaded. Every paint handler is wrapped
  in try/catch, so a drawing problem can never break a window. Dot-source this file (it is loaded by HashslingerCommon.ps1
  and by the Running tool). It changes no settings and touches nothing outside the window it is applied to.
#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-HsColorFromHex([string]$hex) { return [Drawing.ColorTranslator]::FromHtml($hex) }
$script:HsC = @{
  Navy   = (Get-HsColorFromHex '#0B1226'); Indigo = (Get-HsColorFromHex '#1E3A8A'); Blue = (Get-HsColorFromHex '#2563EB')
  Sky    = (Get-HsColorFromHex '#38BDF8'); Bg = (Get-HsColorFromHex '#F1F5F9'); Card = [Drawing.Color]::White
  Line   = (Get-HsColorFromHex '#E2E8F0'); Text = (Get-HsColorFromHex '#0F172A'); Muted = (Get-HsColorFromHex '#64748B')
  Green  = (Get-HsColorFromHex '#16A34A'); Amber = (Get-HsColorFromHex '#F59E0B'); Red = (Get-HsColorFromHex '#DC2626')
  Grey   = (Get-HsColorFromHex '#CBD5E1'); Soft = (Get-HsColorFromHex '#EEF2FF'); Light = (Get-HsColorFromHex '#BFD3FF')
}
$script:HsFont = 'Segoe UI'

function Set-HsDoubleBuffer($c) {
  try { $c.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'Instance,NonPublic').SetValue($c, $true, $null) } catch { }
}
function New-HsFont([double]$size, [string]$style = 'Regular', [string]$name = '') {
  if (-not $name) { $name = $script:HsFont }
  try { return (New-Object Drawing.Font($name, [single]$size, [Drawing.FontStyle]$style)) } catch { return (New-Object Drawing.Font('Segoe UI', [single]$size)) }
}
function New-HsRoundPath([Drawing.RectangleF]$r, [single]$radius) {
  $p = New-Object Drawing.Drawing2D.GraphicsPath
  $d = $radius * 2
  if ($d -gt $r.Height) { $d = $r.Height }
  if ($d -gt $r.Width) { $d = $r.Width }
  $p.AddArc($r.X, $r.Y, $d, $d, 180, 90)
  $p.AddArc($r.Right - $d, $r.Y, $d, $d, 270, 90)
  $p.AddArc($r.Right - $d, $r.Bottom - $d, $d, $d, 0, 90)
  $p.AddArc($r.X, $r.Bottom - $d, $d, $d, 90, 90)
  $p.CloseFigure()
  return $p
}

# ---------------------------------------------------------------- the logo: a shield with a hash sign
$script:HsPatch = $null
function Get-HsPatch {
  if ($script:HsPatch) { return $script:HsPatch }
  try {
    . (Join-Path $PSScriptRoot 'HashslingerLogoData.ps1')
    $bytes = [Convert]::FromBase64String([string]$script:HsLogoB64)
    $ms = New-Object IO.MemoryStream(, $bytes)
    $script:HsPatch = New-Object Drawing.Bitmap($ms)   # stream must stay open for the bitmap's life
  } catch { $script:HsPatch = $null }
  return $script:HsPatch
}
function New-HsLogo([int]$size) {
  $bmp = New-Object Drawing.Bitmap($size, $size)
  $g = [Drawing.Graphics]::FromImage($bmp)
  $patch = Get-HsPatch
  if ($patch) {
    try {
      $g.SmoothingMode = 'AntiAlias'; $g.InterpolationMode = 'HighQualityBicubic'; $g.PixelOffsetMode = 'HighQuality'
      $g.DrawImage($patch, 0, 0, $size, $size)
      $g.Dispose()
      return $bmp
    } catch { }
  }
  try {
    $g.SmoothingMode = 'AntiAlias'
    $s = [single]$size; $m = [single]($s * 0.07)
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $path.AddLine([single]($s * 0.5), $m, [single]($s - $m), [single]($s * 0.2))
    $path.AddLine([single]($s - $m), [single]($s * 0.2), [single]($s - $m), [single]($s * 0.5))
    $path.AddBezier([single]($s - $m), [single]($s * 0.5), [single]($s - $m), [single]($s * 0.78), [single]($s * 0.68), [single]($s * 0.9), [single]($s * 0.5), [single]($s - $m))
    $path.AddBezier([single]($s * 0.5), [single]($s - $m), [single]($s * 0.32), [single]($s * 0.9), $m, [single]($s * 0.78), $m, [single]($s * 0.5))
    $path.AddLine($m, [single]($s * 0.5), $m, [single]($s * 0.2))
    $path.CloseFigure()
    $rect = New-Object Drawing.RectangleF(0, 0, $s, $s)
    $br = New-Object Drawing.Drawing2D.LinearGradientBrush($rect, $script:HsC.Sky, $script:HsC.Blue, 70.0)
    $g.FillPath($br, $path)
    $edge = New-Object Drawing.Pen([Drawing.Color]::FromArgb(200, 255, 255, 255), [single]([Math]::Max(1, $s * 0.03)))
    $g.DrawPath($edge, $path)
    $pen = New-Object Drawing.Pen([Drawing.Color]::White, [single]([Math]::Max(2, $s * 0.075)))
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $g.DrawLine($pen, [single]($s * 0.41), [single]($s * 0.3), [single]($s * 0.37), [single]($s * 0.7))
    $g.DrawLine($pen, [single]($s * 0.61), [single]($s * 0.3), [single]($s * 0.57), [single]($s * 0.7))
    $g.DrawLine($pen, [single]($s * 0.27), [single]($s * 0.43), [single]($s * 0.72), [single]($s * 0.43))
    $g.DrawLine($pen, [single]($s * 0.25), [single]($s * 0.58), [single]($s * 0.70), [single]($s * 0.58))
    $br.Dispose(); $pen.Dispose(); $edge.Dispose(); $path.Dispose()
  } catch { }
  $g.Dispose()
  return $bmp
}
function Set-HsFormIcon($form) {
  try { $bmp = New-HsLogo 32; $form.Icon = [Drawing.Icon]::FromHandle($bmp.GetHicon()) } catch { }
}

# ---------------------------------------------------------------- banner header
function Add-HsHeader($form, [string]$title, [string]$subtitle, [int]$height = 76, [bool]$shift = $true) {
  if ($shift) {
    foreach ($c in @($form.Controls)) { $c.Top += $height }
    $wa = [Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $form.Height = [Math]::Min($form.Height + $height, $wa.Height - 10)
  }
  $p = New-Object Windows.Forms.Panel -Property @{ Left = 0; Top = 0; Width = $form.ClientSize.Width; Height = $height; Anchor = 'Top,Left,Right' }
  $p.Tag = @{ Title = $title; Sub = $subtitle; Logo = (New-HsLogo 64) }
  Set-HsDoubleBuffer $p
  $p.Add_Paint({
    param($s, $e)
    try {
      $g = $e.Graphics; $t = $s.Tag
      $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
      $r = $s.ClientRectangle
      $bg = New-Object Drawing.Drawing2D.LinearGradientBrush($r, $script:HsC.Navy, $script:HsC.Indigo, 0.0)
      $g.FillRectangle($bg, $r)
      $bar = New-Object Drawing.Drawing2D.LinearGradientBrush($r, $script:HsC.Blue, $script:HsC.Sky, 0.0)
      $g.FillRectangle($bar, 0, $r.Height - 3, $r.Width, 3)
      $g.DrawImage($t.Logo, 16, [int](($r.Height - 64) / 2) - 1, 64, 64)
      $f1 = New-HsFont 17 'Bold'; $f2 = New-HsFont 9.5
      $w = New-Object Drawing.SolidBrush([Drawing.Color]::White); $l = New-Object Drawing.SolidBrush($script:HsC.Light)
      $g.DrawString($t.Title, $f1, $w, 90, 13)
      $g.DrawString($t.Sub, $f2, $l, 92, 44)
      $bg.Dispose(); $bar.Dispose(); $f1.Dispose(); $f2.Dispose(); $w.Dispose(); $l.Dispose()
    } catch { }
  })
  $form.Controls.Add($p)
  $p.BringToFront()
  return $p
}

# ---------------------------------------------------------------- applying the theme to ordinary controls
function Set-HsTabs($tc) {
  try {
    $tc.DrawMode = 'OwnerDrawFixed'
    $tc.SizeMode = 'Fixed'
    $tc.ItemSize = New-Object Drawing.Size(142, 34)
    $tc.Padding = New-Object Drawing.Point(18, 6)
    $tc.Add_DrawItem({
      param($s, $e)
      try {
        $g = $e.Graphics
        $r = $e.Bounds
        $sel = ($e.Index -eq $s.SelectedIndex)
        $bgc = if ($sel) { $script:HsC.Card } else { $script:HsC.Bg }
        $b = New-Object Drawing.SolidBrush($bgc); $g.FillRectangle($b, $r); $b.Dispose()
        $g.TextRenderingHint = 'ClearTypeGridFit'
        $f = New-HsFont 9.5 $(if ($sel) { 'Bold' } else { 'Regular' })
        $col = if ($sel) { $script:HsC.Blue } else { $script:HsC.Muted }
        $tb = New-Object Drawing.SolidBrush($col)
        $sf = New-Object Drawing.StringFormat; $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
        $g.DrawString($s.TabPages[$e.Index].Text, $f, $tb, (New-Object Drawing.RectangleF($r.X, $r.Y, $r.Width, $r.Height)), $sf)
        if ($sel) { $ub = New-Object Drawing.SolidBrush($script:HsC.Blue); $g.FillRectangle($ub, $r.X + 8, $r.Bottom - 3, $r.Width - 16, 3); $ub.Dispose() }
        $f.Dispose(); $tb.Dispose(); $sf.Dispose()
      } catch { }
    })
  } catch { }
}

function Set-HsControlTheme($c) {
  $type = $c.GetType().Name
  try {
    switch ($type) {
      'Button' {
        $c.UseVisualStyleBackColor = $false
        $c.FlatStyle = 'Flat'
        $c.Cursor = [Windows.Forms.Cursors]::Hand
        $c.Font = New-HsFont 9
        if ($c.Tag -is [string] -and $c.Tag -eq 'primary') {
          $c.BackColor = $script:HsC.Blue; $c.ForeColor = [Drawing.Color]::White
          $c.FlatAppearance.BorderColor = $script:HsC.Blue
          $c.FlatAppearance.MouseOverBackColor = $script:HsC.Indigo; $c.FlatAppearance.MouseDownBackColor = $script:HsC.Navy
        } else {
          $c.BackColor = [Drawing.Color]::White; $c.ForeColor = $script:HsC.Text
          $c.FlatAppearance.BorderColor = $script:HsC.Grey
          $c.FlatAppearance.MouseOverBackColor = $script:HsC.Soft; $c.FlatAppearance.MouseDownBackColor = $script:HsC.Light
        }
        $c.FlatAppearance.BorderSize = 1
      }
      'TextBox' { if (-not $c.Multiline -or $c.ReadOnly) { $c.BorderStyle = 'FixedSingle' } else { $c.BorderStyle = 'FixedSingle' } }
      'ComboBox' { $c.FlatStyle = 'Flat' }
      'TreeView' { $c.BorderStyle = 'FixedSingle'; $c.BackColor = [Drawing.Color]::White }
      'ListBox' { $c.BorderStyle = 'FixedSingle' }
      'Label' { $c.BackColor = [Drawing.Color]::Transparent }
      'CheckBox' { $c.BackColor = [Drawing.Color]::Transparent }
      'TabPage' { $c.BackColor = [Drawing.Color]::White }
      'TabControl' { Set-HsTabs $c }
      'FlowLayoutPanel' { $c.BackColor = [Drawing.Color]::Transparent }
    }
  } catch { }
  foreach ($child in @($c.Controls)) { Set-HsControlTheme $child }
}
function Set-HsTheme($form) {
  try { $form.BackColor = $script:HsC.Bg; $form.Font = New-HsFont 9; Set-HsFormIcon $form } catch { }
  foreach ($c in @($form.Controls)) { Set-HsControlTheme $c }
}

# ---------------------------------------------------------------- a white card (panel with a thin border and a title)
function New-HsCard([int]$left, [int]$top, [int]$width, [int]$height, [string]$title = '') {
  $p = New-Object Windows.Forms.Panel -Property @{ Left = $left; Top = $top; Width = $width; Height = $height; BackColor = [Drawing.Color]::White }
  $p.Tag = @{ Title = $title }
  Set-HsDoubleBuffer $p
  $p.Add_Paint({
    param($s, $e)
    try {
      $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
      $pen = New-Object Drawing.Pen($script:HsC.Line)
      $g.DrawRectangle($pen, 0, 0, $s.Width - 1, $s.Height - 1)
      $pen.Dispose()
      $t = [string]$s.Tag.Title
      if ($t) {
        $f = New-HsFont 11 'Bold'; $b = New-Object Drawing.SolidBrush($script:HsC.Text)
        $g.DrawString($t, $f, $b, 14, 9)
        $acc = New-Object Drawing.SolidBrush($script:HsC.Blue); $g.FillRectangle($acc, 0, 11, 4, 18)
        $f.Dispose(); $b.Dispose(); $acc.Dispose()
      }
    } catch { }
  })
  return $p
}

# ---------------------------------------------------------------- gradient progress bar (determinate or sliding)
function New-HsProgress([int]$left, [int]$top, [int]$width, [int]$height = 14) {
  $p = New-Object Windows.Forms.Panel -Property @{ Left = $left; Top = $top; Width = $width; Height = $height; BackColor = [Drawing.Color]::Transparent }
  $p.Tag = @{ Value = 0.0; Max = 100.0; Marquee = $false; Phase = 0.0; Timer = $null }
  Set-HsDoubleBuffer $p
  $t = New-Object Windows.Forms.Timer -Property @{ Interval = 35 }
  $t.Tag = $p
  $t.Add_Tick({ param($s, $e) try { $bar = $s.Tag; if ($bar.Tag.Marquee) { $bar.Tag.Phase = ($bar.Tag.Phase + 0.018) % 1.4; $bar.Invalidate() } } catch { } })
  $p.Tag.Timer = $t
  $p.Add_Paint({
    param($s, $e)
    try {
      $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'
      $d = $s.Tag
      $w = [single]($s.Width - 1); $h = [single]($s.Height - 1)
      $track = New-HsRoundPath (New-Object Drawing.RectangleF(0, 0, $w, $h)) ([single]($h / 2))
      $tb = New-Object Drawing.SolidBrush($script:HsC.Line); $g.FillPath($tb, $track); $tb.Dispose()
      $fillW = $null; $x0 = 0.0
      if ($d.Marquee) { $len = $w * 0.3; $x0 = (($d.Phase * $w) - $len); if ($x0 -lt 0) { $x0 = 0 }; $fillW = [Math]::Min($len, $w - $x0) }
      elseif ($d.Max -gt 0) { $fillW = $w * [Math]::Min(1.0, [Math]::Max(0.0, $d.Value / $d.Max)) }
      if ($fillW -and $fillW -gt 2) {
        $r = New-Object Drawing.RectangleF([single]$x0, 0, [single]$fillW, $h)
        $fp = New-HsRoundPath $r ([single]($h / 2))
        $fb = New-Object Drawing.Drawing2D.LinearGradientBrush((New-Object Drawing.RectangleF([single]$x0, 0, [single]([Math]::Max(2, $fillW)), $h)), $script:HsC.Blue, $script:HsC.Sky, 0.0)
        $g.FillPath($fb, $fp); $fb.Dispose(); $fp.Dispose()
      }
      $track.Dispose()
    } catch { }
  })
  return $p
}
function Set-HsProgress($bar, [double]$value, [double]$max = 100) { try { $bar.Tag.Value = $value; $bar.Tag.Max = $max; $bar.Tag.Marquee = $false; $bar.Invalidate() } catch { } }
function Start-HsMarquee($bar) { try { $bar.Tag.Marquee = $true; $bar.Tag.Timer.Start(); $bar.Invalidate() } catch { } }
function Stop-HsMarquee($bar) { try { $bar.Tag.Marquee = $false; $bar.Tag.Timer.Stop(); $bar.Tag.Value = 0; $bar.Invalidate() } catch { } }

# ---------------------------------------------------------------- the 7-step pipeline graphic
function New-HsStepper([int]$left, [int]$top, [int]$width, [int]$height, [string[]]$labels) {
  $p = New-Object Windows.Forms.Panel -Property @{ Left = $left; Top = $top; Width = $width; Height = $height; BackColor = [Drawing.Color]::White }
  $p.Tag = @{ Labels = $labels; Stage = 0; State = 'idle'; Phase = 0.0; Timer = $null }
  Set-HsDoubleBuffer $p
  $t = New-Object Windows.Forms.Timer -Property @{ Interval = 60 }
  $t.Tag = $p
  $t.Add_Tick({ param($s, $e) try { $st = $s.Tag; if ($st.Tag.State -eq 'running') { $st.Tag.Phase = ($st.Tag.Phase + 0.08) % 6.2832; $st.Invalidate() } } catch { } })
  $p.Tag.Timer = $t
  $t.Start()
  $p.Add_Paint({
    param($s, $e)
    try {
      $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
      $d = $s.Tag; $n = $d.Labels.Count
      if ($n -lt 2) { return }
      $r = 13; $cy = 22; $pad = 40
      $span = ($s.Width - 2 * $pad)
      $f = New-HsFont 8.5; $fb = New-HsFont 8.5 'Bold'
      $sf = New-Object Drawing.StringFormat; $sf.Alignment = 'Center'
      for ($i = 0; $i -lt $n; $i++) {
        $x = $pad + ($span * $i / ($n - 1))
        if ($i -gt 0) {
          $xp = $pad + ($span * ($i - 1) / ($n - 1))
          $done = ($d.State -eq 'success') -or ($i -lt $d.Stage -and $d.State -ne 'idle') -or ($d.State -eq 'failed' -and $i -lt $d.Stage)
          $col = if ($done) { $script:HsC.Blue } else { $script:HsC.Grey }
          $pen = New-Object Drawing.Pen($col, 3); $g.DrawLine($pen, [single]($xp + $r), [single]$cy, [single]($x - $r), [single]$cy); $pen.Dispose()
        }
        $stage = $i + 1
        $isDone = ($d.State -eq 'success') -or ($d.State -ne 'idle' -and $stage -lt $d.Stage)
        $isCur = ($d.State -eq 'running' -and $stage -eq $d.Stage)
        $isFail = ($d.State -eq 'failed' -and $stage -eq $d.Stage)
        $fill = $script:HsC.Card; $edge = $script:HsC.Grey
        if ($isDone) { $fill = $script:HsC.Blue; $edge = $script:HsC.Blue }
        if ($isCur) { $edge = $script:HsC.Blue }
        if ($isFail) { $fill = $script:HsC.Red; $edge = $script:HsC.Red }
        if ($d.State -eq 'success') { $fill = $script:HsC.Green; $edge = $script:HsC.Green }
        if ($isCur) {
          $pulse = 4 + 3 * [Math]::Sin($d.Phase)
          $hp = New-Object Drawing.Pen([Drawing.Color]::FromArgb(70, 37, 99, 235), 3)
          $g.DrawEllipse($hp, [single]($x - $r - $pulse), [single]($cy - $r - $pulse), [single](2 * ($r + $pulse)), [single](2 * ($r + $pulse))); $hp.Dispose()
        }
        $fbru = New-Object Drawing.SolidBrush($fill); $g.FillEllipse($fbru, [single]($x - $r), [single]($cy - $r), [single](2 * $r), [single](2 * $r)); $fbru.Dispose()
        $ep = New-Object Drawing.Pen($edge, 2); $g.DrawEllipse($ep, [single]($x - $r), [single]($cy - $r), [single](2 * $r), [single](2 * $r)); $ep.Dispose()
        $mark = New-Object Drawing.Pen([Drawing.Color]::White, 2.4); $mark.StartCap = 'Round'; $mark.EndCap = 'Round'
        if ($isDone -or $d.State -eq 'success') {
          $g.DrawLine($mark, [single]($x - 5), [single]($cy + 1), [single]($x - 1), [single]($cy + 5))
          $g.DrawLine($mark, [single]($x - 1), [single]($cy + 5), [single]($x + 6), [single]($cy - 4))
        } elseif ($isFail) {
          $g.DrawLine($mark, [single]($x - 4), [single]($cy - 4), [single]($x + 4), [single]($cy + 4))
          $g.DrawLine($mark, [single]($x + 4), [single]($cy - 4), [single]($x - 4), [single]($cy + 4))
        } else {
          $nb = New-Object Drawing.SolidBrush($(if ($isCur) { $script:HsC.Blue } else { $script:HsC.Muted }))
          $g.DrawString([string]$stage, $fb, $nb, (New-Object Drawing.RectangleF([single]($x - $r), [single]($cy - 8), [single](2 * $r), 18)), $sf); $nb.Dispose()
        }
        $mark.Dispose()
        $lb = New-Object Drawing.SolidBrush($(if ($isCur -or $isFail) { $script:HsC.Text } else { $script:HsC.Muted }))
        $g.DrawString([string]$d.Labels[$i], $(if ($isCur) { $fb } else { $f }), $lb, (New-Object Drawing.RectangleF([single]($x - 50), [single]($cy + $r + 6), 100, 18)), $sf); $lb.Dispose()
      }
      $f.Dispose(); $fb.Dispose(); $sf.Dispose()
    } catch { }
  })
  return $p
}
function Set-HsStepper($st, [string]$state, [int]$stage) { try { $st.Tag.State = $state; $st.Tag.Stage = $stage; $st.Invalidate() } catch { } }

# ---------------------------------------------------------------- status badge (a coloured pill)
function New-HsBadge([int]$left, [int]$top, [int]$width, [int]$height = 28) {
  $p = New-Object Windows.Forms.Panel -Property @{ Left = $left; Top = $top; Width = $width; Height = $height; BackColor = [Drawing.Color]::White }
  $p.Tag = @{ Text = 'NO SCAN'; Color = $script:HsC.Muted }
  Set-HsDoubleBuffer $p
  $p.Add_Paint({
    param($s, $e)
    try {
      $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
      $d = $s.Tag
      $path = New-HsRoundPath (New-Object Drawing.RectangleF(0, 0, [single]($s.Width - 1), [single]($s.Height - 1))) ([single]($s.Height / 2))
      $b = New-Object Drawing.SolidBrush($d.Color); $g.FillPath($b, $path); $b.Dispose(); $path.Dispose()
      $f = New-HsFont 9.5 'Bold'; $wb = New-Object Drawing.SolidBrush([Drawing.Color]::White)
      $sf = New-Object Drawing.StringFormat; $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
      $g.DrawString([string]$d.Text, $f, $wb, (New-Object Drawing.RectangleF(0, 0, [single]$s.Width, [single]$s.Height)), $sf)
      $f.Dispose(); $wb.Dispose(); $sf.Dispose()
    } catch { }
  })
  return $p
}
function Set-HsBadge($b, [string]$text, $color) { try { $b.Tag.Text = $text; $b.Tag.Color = $color; $b.Invalidate() } catch { } }

# ---------------------------------------------------------------- big-number tile
function New-HsTile([int]$left, [int]$top, [int]$width, [int]$height, [string]$label, $color) {
  $p = New-Object Windows.Forms.Panel -Property @{ Left = $left; Top = $top; Width = $width; Height = $height; BackColor = [Drawing.Color]::White }
  $p.Tag = @{ Label = $label; Value = '-'; Color = $color }
  Set-HsDoubleBuffer $p
  $p.Add_Paint({
    param($s, $e)
    try {
      $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
      $d = $s.Tag
      $path = New-HsRoundPath (New-Object Drawing.RectangleF(0, 0, [single]($s.Width - 1), [single]($s.Height - 1))) 8
      $fb = New-Object Drawing.SolidBrush($script:HsC.Bg); $g.FillPath($fb, $path); $fb.Dispose()
      $ab = New-Object Drawing.SolidBrush($d.Color); $g.FillRectangle($ab, 0, 12, 4, $s.Height - 24); $ab.Dispose()
      $f1 = New-HsFont 19 'Bold'; $f2 = New-HsFont 8.5
      $tb = New-Object Drawing.SolidBrush($script:HsC.Text); $mb = New-Object Drawing.SolidBrush($script:HsC.Muted)
      $g.DrawString([string]$d.Value, $f1, $tb, 14, 6)
      $g.DrawString([string]$d.Label, $f2, $mb, 16, $s.Height - 24)
      $f1.Dispose(); $f2.Dispose(); $tb.Dispose(); $mb.Dispose(); $path.Dispose()
    } catch { }
  })
  return $p
}
function Set-HsTile($t, [string]$value) { try { $t.Tag.Value = $value; $t.Invalidate() } catch { } }

# ---------------------------------------------------------------- donut chart
function New-HsDonut([int]$left, [int]$top, [int]$size) {
  $p = New-Object Windows.Forms.Panel -Property @{ Left = $left; Top = $top; Width = $size; Height = $size; BackColor = [Drawing.Color]::White }
  $p.Tag = @{ Items = @(); Center = ''; Sub = '' }
  Set-HsDoubleBuffer $p
  $p.Add_Paint({
    param($s, $e)
    try {
      $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
      $d = $s.Tag
      $m = 6; $dia = [Math]::Min($s.Width, $s.Height) - 2 * $m
      $rect = New-Object Drawing.RectangleF([single]$m, [single]$m, [single]$dia, [single]$dia)
      $total = 0.0; foreach ($it in $d.Items) { $total += [double]$it.Value }
      if ($total -le 0) {
        $pen = New-Object Drawing.Pen($script:HsC.Line, 14); $g.DrawEllipse($pen, [single]($m + 7), [single]($m + 7), [single]($dia - 14), [single]($dia - 14)); $pen.Dispose()
      } else {
        $start = -90.0
        foreach ($it in $d.Items) {
          $sweep = 360.0 * ([double]$it.Value / $total)
          if ($sweep -gt 0.2) { $b = New-Object Drawing.SolidBrush($it.Color); $g.FillPie($b, [int]$rect.X, [int]$rect.Y, [int]$rect.Width, [int]$rect.Height, [single]$start, [single]([Math]::Max(0.5, $sweep - 1.0))); $b.Dispose() }
          $start += $sweep
        }
        $hole = $dia * 0.62; $hb = New-Object Drawing.SolidBrush([Drawing.Color]::White)
        $g.FillEllipse($hb, [single]($m + ($dia - $hole) / 2), [single]($m + ($dia - $hole) / 2), [single]$hole, [single]$hole); $hb.Dispose()
      }
      $f1 = New-HsFont 16 'Bold'; $f2 = New-HsFont 8.5
      $tb = New-Object Drawing.SolidBrush($script:HsC.Text); $mb = New-Object Drawing.SolidBrush($script:HsC.Muted)
      $sf = New-Object Drawing.StringFormat; $sf.Alignment = 'Center'
      $g.DrawString([string]$d.Center, $f1, $tb, (New-Object Drawing.RectangleF(0, [single]($s.Height / 2 - 20), [single]$s.Width, 28)), $sf)
      $g.DrawString([string]$d.Sub, $f2, $mb, (New-Object Drawing.RectangleF(0, [single]($s.Height / 2 + 8), [single]$s.Width, 18)), $sf)
      $f1.Dispose(); $f2.Dispose(); $tb.Dispose(); $mb.Dispose(); $sf.Dispose()
    } catch { }
  })
  return $p
}
function Set-HsDonut($d, $items, [string]$center, [string]$sub) { try { $d.Tag.Items = @($items); $d.Tag.Center = $center; $d.Tag.Sub = $sub; $d.Invalidate() } catch { } }

# ---------------------------------------------------------------- horizontal bar chart
function New-HsBars([int]$left, [int]$top, [int]$width, [int]$height) {
  $p = New-Object Windows.Forms.Panel -Property @{ Left = $left; Top = $top; Width = $width; Height = $height; BackColor = [Drawing.Color]::White }
  $p.Tag = @{ Rows = @() }
  Set-HsDoubleBuffer $p
  $p.Add_Paint({
    param($s, $e)
    try {
      $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
      $rows = @($s.Tag.Rows)
      if ($rows.Count -eq 0) {
        $f = New-HsFont 9.5; $mb = New-Object Drawing.SolidBrush($script:HsC.Muted)
        $g.DrawString('The reasons accounts were flagged will show here.', $f, $mb, 4, 8); $f.Dispose(); $mb.Dispose(); return
      }
      $max = 1.0; foreach ($r in $rows) { if ([double]$r.Value -gt $max) { $max = [double]$r.Value } }
      $rowH = [Math]::Min(26, [Math]::Floor($s.Height / $rows.Count))
      $labelW = 150; $valW = 60
      $f = New-HsFont 9; $tb = New-Object Drawing.SolidBrush($script:HsC.Text); $mb = New-Object Drawing.SolidBrush($script:HsC.Muted)
      $sf = New-Object Drawing.StringFormat; $sf.LineAlignment = 'Center'; $sf.Trimming = 'EllipsisCharacter'
      $sr = New-Object Drawing.StringFormat; $sr.LineAlignment = 'Center'; $sr.Alignment = 'Far'
      for ($i = 0; $i -lt $rows.Count; $i++) {
        $y = $i * $rowH
        $g.DrawString([string]$rows[$i].Label, $f, $tb, (New-Object Drawing.RectangleF(0, [single]$y, [single]$labelW, [single]$rowH)), $sf)
        $bw = ($s.Width - $labelW - $valW - 8) * ([double]$rows[$i].Value / $max)
        if ($bw -lt 3) { $bw = 3 }
        $br = New-Object Drawing.Drawing2D.LinearGradientBrush((New-Object Drawing.RectangleF([single]$labelW, [single]($y + 5), [single]$bw, [single]($rowH - 10))), $rows[$i].Color, $script:HsC.Sky, 0.0)
        $path = New-HsRoundPath (New-Object Drawing.RectangleF([single]$labelW, [single]($y + 5), [single]$bw, [single]($rowH - 10))) 4
        $g.FillPath($br, $path); $br.Dispose(); $path.Dispose()
        $g.DrawString(('{0:N0}' -f [double]$rows[$i].Value), $f, $mb, (New-Object Drawing.RectangleF([single]($s.Width - $valW), [single]$y, [single]$valW, [single]$rowH)), $sr)
      }
      $f.Dispose(); $tb.Dispose(); $mb.Dispose(); $sf.Dispose(); $sr.Dispose()
    } catch { }
  })
  return $p
}
function Set-HsBars($b, $rows) { try { $b.Tag.Rows = @($rows); $b.Invalidate() } catch { } }
