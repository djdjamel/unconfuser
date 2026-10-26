param([string]$TargetDll, [string]$Group, [int]$Iter = 3000, [int]$SleepAfter = 0)
# C4 - Isolation par famille : boucle $Iter appels d'une famille de fonctions, dans un processus dedie.
$DepDir = 'G:\XpertPharm5'
$guard = New-Object 'System.Collections.Generic.HashSet[string]'
[System.AppDomain]::CurrentDomain.add_AssemblyResolve({
    param($sender, $e)
    $name = (New-Object System.Reflection.AssemblyName($e.Name)).Name
    if ($guard.Contains($name)) { return $null }
    $guard.Add($name) | Out-Null
    $p = Join-Path $DepDir "$name.dll"
    if (Test-Path $p) { return [System.Reflection.Assembly]::LoadFrom($p) }
    return $null
})
$asm = [System.Reflection.Assembly]::LoadFrom($TargetDll)
$h  = $asm.GetType('Xpert.Common.XpertHelper')
$cl = $asm.GetType('Xpert.Common.ChiffresLettres')
$nw = $asm.GetType('Xpert.Common.NumberToWords')
switch ($Group) {
  'trim'   { $m = $h.GetMethod('StringTrim', [Type[]]@([string])); for ($i=0;$i -lt $Iter;$i++){ $null = $m.Invoke($null, @('  hello  ')) } }
  'crypto' { $e = $h.GetMethod('Encrypt', [Type[]]@([string])); $d = $h.GetMethod('Decrypt', [Type[]]@([string])); for ($i=0;$i -lt $Iter;$i++){ $x = $e.Invoke($null, @('Hello World')); $null = $d.Invoke($null, @($x)) } }
  'timbre' { $m = $h.GetMethod('CalculMtTimbre', [Type[]]@([decimal])); for ($i=0;$i -lt $Iter;$i++){ $null = $m.Invoke($null, @([decimal]2500)) } }
  'round'  { $m = $h.GetMethod('RoundMontant', [Type[]]@([decimal],[int])); for ($i=0;$i -lt $Iter;$i++){ $null = $m.Invoke($null, @([decimal]'12.3456', 2)) } }
  'money'  { $m = $cl.GetMethod('MoneyToLetter', [Type[]]@([decimal])); for ($i=0;$i -lt $Iter;$i++){ $null = $m.Invoke($null, @([decimal]'1234.56')) } }
  'arabic' { $m = $cl.GetMethod('MoneyToArabicLetter', [Type[]]@([decimal])); for ($i=0;$i -lt $Iter;$i++){ $null = $m.Invoke($null, @([decimal]'1234.56')) } }
  'words'  { $m = $nw.GetMethod('changeNumericToWords', [Type[]]@([decimal])); for ($i=0;$i -lt $Iter;$i++){ $null = $m.Invoke($null, @([decimal]1234)) } }
}
if ($SleepAfter -gt 0) { Start-Sleep -Seconds $SleepAfter }
"DONE $Group $Iter"
