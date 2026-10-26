# C2/C3 - Eclaire l'erreur PEVerify unique et les 6 avertissements /md sur la DLL finale figee.
Add-Type -Path 'c:\Users\acer\claude\xp_src\ConfuserExKillerRunner\bin\Debug\net48\dnlib.dll'
$m = [dnlib.DotNet.ModuleDefMD]::Load('c:\Users\acer\claude\xp_src\audit\final_audit\frozen\Xpert.Common.BLL_final.dll')

"=== Methode MDToken 0x600019f ==="
$meth = $m.ResolveToken(0x0600019f)
$meth.FullName
"Corps IL (12 premieres instructions):"
$meth.Body.Instructions | Select-Object -First 12 | ForEach-Object { "  {0:X4}: {1} {2}" -f $_.Offset, $_.OpCode, $_.Operand }

"`n=== Types references depuis QRCoder ==="
$m.GetTypeRefs() | Where-Object { $_.ResolutionScope -is [dnlib.DotNet.AssemblyRef] -and $_.ResolutionScope.Name -eq 'QRCoder' } | ForEach-Object { "  " + $_.FullName }

"`n=== <Module> (type global) ==="
$g = $m.GlobalType
"Champs: " + $g.Fields.Count + " | Methodes: " + $g.Methods.Count
foreach ($f in $g.Fields) { "  FIELD  0x{0:X8} {1} {2}" -f $f.MDToken.Raw, $f.Name, $f.FieldType }
foreach ($x in $g.Methods) { "  METHOD 0x{0:X8} {1} (instr={2}) pinvoke={3}" -f $x.MDToken.Raw, $x.Name, $(if($x.HasBody){$x.Body.Instructions.Count}else{0}), $x.IsPinvokeImpl }
"`n=== <Module>.cctor ==="
$c = $g.FindStaticConstructor()
if ($c -and $c.HasBody) { $c.Body.Instructions | ForEach-Object { "  {0:X4}: {1} {2}" -f $_.Offset, $_.OpCode, $_.Operand } } else { "  (pas de cctor)" }
