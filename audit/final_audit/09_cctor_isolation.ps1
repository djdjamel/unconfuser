param([string]$TargetDll, [int]$SleepSec = 8)
# C4 - Experience d'isolation : charge la DLL, declenche son <Module>.cctor via UN appel trivial,
# puis attend sans appeler d'autre fonction metier. Si le processus plante, la cause est le cctor/threads de protection.
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
$helper = $asm.GetType('Xpert.Common.XpertHelper')
$mTrim = $helper.GetMethod('StringTrim', [Type[]]@([string]))
$r = $mTrim.Invoke($null, @('  x  '))
"cctor declenche, StringTrim='$r' ; attente $SleepSec s ..."
Start-Sleep -Seconds $SleepSec
"ALIVE"
