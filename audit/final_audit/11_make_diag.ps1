# C4 - Copies de DIAGNOSTIC (jamais la finale). Ecrit dans audit\final_audit\diag\.
#   diag_control.dll  : simple reecriture dnlib, aucune modification (temoin)
#   diag_nocctor.dll  : l'appel '<Module>::smethod_0' du <Module>.cctor est remplace par nop
Add-Type -Path 'c:\Users\acer\claude\xp_src\ConfuserExKillerRunner\bin\Debug\net48\dnlib.dll'
$src = 'c:\Users\acer\claude\xp_src\audit\final_audit\frozen\Xpert.Common.BLL_final.dll'
$out = 'c:\Users\acer\claude\xp_src\audit\final_audit\diag'
New-Item -ItemType Directory -Force $out | Out-Null

function Write-Mod($mod, $path) {
    $o = New-Object dnlib.DotNet.Writer.ModuleWriterOptions($mod)
    $o.MetaDataOptions.Flags = $o.MetaDataOptions.Flags -bor [dnlib.DotNet.Writer.MetaDataFlags]::KeepOldMaxStack
    $mod.Write($path, $o)
}

$m1 = [dnlib.DotNet.ModuleDefMD]::Load($src)
Write-Mod $m1 "$out\diag_control.dll"
$m1.Dispose()

$m2 = [dnlib.DotNet.ModuleDefMD]::Load($src)
$cctor = $m2.GlobalType.FindStaticConstructor()
$n = 0
foreach ($i in $cctor.Body.Instructions) {
    if ($i.OpCode.Code -eq [dnlib.DotNet.Emit.Code]::Call -and $i.Operand.Name -eq 'smethod_0') {
        $i.OpCode = [dnlib.DotNet.Emit.OpCodes]::Nop
        $i.Operand = $null
        $n++
    }
}
"Appels neutralises dans le cctor de diag_nocctor: $n"
Write-Mod $m2 "$out\diag_nocctor.dll"
$m2.Dispose()
Get-ChildItem $out | Select Name, Length
