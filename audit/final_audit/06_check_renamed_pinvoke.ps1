# C5 - Cherche, dans toutes les assemblies de G:\XpertPharm5, des references aux membres publics renommes,
# et affiche les ImplMap (nom natif importe) des 2 P/Invoke dans l'originale et la finale.
Add-Type -Path 'c:\Users\acer\claude\xp_src\ConfuserExKillerRunner\bin\Debug\net48\dnlib.dll'
$names = 'OpenPrinter','OpenPrinterA','StartDocPrinter','StartDocPrinterA'

foreach ($pair in @(@('ORIGINALE','c:\Users\acer\claude\xp_src\audit\final_audit\frozen\Xpert.Common.BLL.original.dll'), @('FINALE','c:\Users\acer\claude\xp_src\audit\final_audit\frozen\Xpert.Common.BLL_final.dll'))) {
    "=== ImplMap " + $pair[0] + " ==="
    $m = [dnlib.DotNet.ModuleDefMD]::Load($pair[1])
    $t = $m.Types | Where-Object { $_.FullName -eq 'Xpert.Common.XpertHelperPrinter' }
    foreach ($x in $t.Methods | Where-Object { $_.IsPinvokeImpl }) {
        "  {0,-20} -> dll={1} entry={2} charset/flags={3}" -f $x.Name, $x.ImplMap.Module.Name, $x.ImplMap.Name, $x.ImplMap.Attributes
    }
}

"`n=== Consommateurs dans G:\XpertPharm5 (MemberRef/MethodDef vers XpertHelperPrinter) ==="
$hits = 0; $scanned = 0; $failed = 0
foreach ($f in Get-ChildItem 'G:\XpertPharm5' -Include *.dll,*.exe -Recurse -File) {
    try {
        $mod = [dnlib.DotNet.ModuleDefMD]::Load($f.FullName)
        $scanned++
        foreach ($r in $mod.GetMemberRefs()) {
            if ($r.Class -ne $null -and $r.Class.FullName -like '*XpertHelperPrinter*' -and $names -contains $r.Name.String) {
                "  {0}: {1}" -f $f.Name, $r.FullName
                $hits++
            }
        }
    } catch { $failed++ }
}
"Assemblies analysees: $scanned | illisibles (natives?): $failed | references trouvees: $hits"
