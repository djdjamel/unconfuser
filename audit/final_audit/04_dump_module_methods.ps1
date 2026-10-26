# C3 - Corps IL des methodes restantes de <Module> dans la DLL finale figee.
Add-Type -Path 'c:\Users\acer\claude\xp_src\ConfuserExKillerRunner\bin\Debug\net48\dnlib.dll'
$m = [dnlib.DotNet.ModuleDefMD]::Load('c:\Users\acer\claude\xp_src\audit\final_audit\frozen\Xpert.Common.BLL_final.dll')
$g = $m.GlobalType
foreach ($x in $g.Methods | Where-Object { $_.Name -like 'smethod_*' }) {
    "=== {0} (RID {1}) ===" -f $x.FullName, $x.Rid
    foreach ($i in $x.Body.Instructions) { "  {0:X4}: {1} {2}" -f $i.Offset, $i.OpCode, $i.Operand }
    ""
}
"=== Struct4 ==="
$g.NestedTypes | ForEach-Object { "  {0} classSize={1}" -f $_.FullName, $_.ClassSize }
"=== Ressources embarquees ==="
$m.Resources | ForEach-Object { "  {0} ({1}) size={2}" -f $_.Name, $_.ResourceType, $(if($_ -is [dnlib.DotNet.EmbeddedResource]){$_.Data.Length}else{'n/a'}) }
