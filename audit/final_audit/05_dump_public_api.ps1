param(
    [Parameter(Mandatory=$true)][string]$Dll,
    [Parameter(Mandatory=$true)][string]$Out
)
# C5 - Dump normalise du contrat public d'une assembly (types exportes, membres public/family/famorassem).
Add-Type -Path 'c:\Users\acer\claude\xp_src\ConfuserExKillerRunner\bin\Debug\net48\dnlib.dll'
$m = [dnlib.DotNet.ModuleDefMD]::Load($Dll)
$L = New-Object System.Collections.Generic.List[string]

function Exported($t) {
    if ($t.DeclaringType -eq $null) { return $t.IsPublic }
    if (-not (Exported $t.DeclaringType)) { return $false }
    return ($t.IsNestedPublic -or $t.IsNestedFamily -or $t.IsNestedFamilyOrAssembly)
}
function Attrs($owner, $tag) {
    foreach ($a in $owner.CustomAttributes) {
        $args = ($a.ConstructorArguments | ForEach-Object { "" + $_.Value }) -join ','
        $named = ($a.NamedArguments | ForEach-Object { $_.Name.String + '=' + $_.Argument.Value }) -join ','
        $L.Add("A|$tag|" + $a.TypeFullName + "($args;$named)")
    }
}

$asm = $m.Assembly
$L.Add("ASM|" + $asm.Name + "|" + $asm.Version + "|culture=" + $asm.Culture + "|pkt=" + $asm.PublicKeyToken)
$L.Add("MOD|runtime=" + $m.RuntimeVersion + "|machine=" + $m.Machine + "|corflags=" + $m.Cor20HeaderFlags)
Attrs $asm 'assembly'

foreach ($t in $m.GetTypes()) {
    if (-not (Exported $t)) { continue }
    $bt = if ($t.BaseType) { $t.BaseType.FullName } else { '' }
    $ifs = ($t.Interfaces | ForEach-Object { $_.Interface.FullName } | Sort-Object) -join ','
    $gp = ($t.GenericParameters | ForEach-Object { $_.Name.String + ':' + $_.Flags + ':' + (($_.GenericParamConstraints | ForEach-Object { $_.Constraint.FullName }) -join '+') }) -join ','
    $L.Add("T|" + $t.FullName + "|vis=" + $t.Visibility + "|abs=" + $t.IsAbstract + "|sealed=" + $t.IsSealed + "|iface=" + $t.IsInterface + "|enum=" + $t.IsEnum + "|ser=" + $t.IsSerializable + "|layout=" + $t.Layout + "|base=" + $bt + "|ifs=" + $ifs + "|gp=" + $gp)
    Attrs $t ("T:" + $t.FullName)
    foreach ($f in $t.Fields) {
        if (-not ($f.IsPublic -or $f.IsFamily -or $f.IsFamilyOrAssembly)) { continue }
        $cv = if ($f.IsLiteral -and $f.Constant) { "" + $f.Constant.Value } else { '' }
        $L.Add("F|" + $t.FullName + "|" + $f.Name + "|" + $f.FieldType.FullName + "|vis=" + $f.Access + "|static=" + $f.IsStatic + "|lit=" + $f.IsLiteral + "|ro=" + $f.IsInitOnly + "|const=" + $cv)
        Attrs $f ("F:" + $t.FullName + "::" + $f.Name)
    }
    foreach ($x in $t.Methods) {
        if (-not ($x.IsPublic -or $x.IsFamily -or $x.IsFamilyOrAssembly)) { continue }
        $L.Add("M|" + $x.FullName + "|vis=" + $x.Access + "|virt=" + $x.IsVirtual + "|abs=" + $x.IsAbstract + "|final=" + $x.IsFinal + "|newslot=" + $x.IsNewSlot + "|static=" + $x.IsStatic + "|pinvoke=" + $x.IsPinvokeImpl)
        Attrs $x ("M:" + $x.FullName)
    }
    foreach ($p in $t.Properties) {
        $acc = @($p.GetMethod, $p.SetMethod) | Where-Object { $_ -ne $null -and ($_.IsPublic -or $_.IsFamily -or $_.IsFamilyOrAssembly) }
        if ($acc.Count -eq 0) { continue }
        $L.Add("P|" + $t.FullName + "|" + $p.Name + "|" + $p.PropertySig.RetType.FullName + "|get=" + ($p.GetMethod -ne $null) + "|set=" + ($p.SetMethod -ne $null))
    }
    foreach ($e in $t.Events) {
        $L.Add("E|" + $t.FullName + "|" + $e.Name + "|" + $e.EventType.FullName)
    }
}
$L | Sort-Object | Set-Content -Path $Out -Encoding UTF8
"Lignes ecrites: " + $L.Count + " -> " + $Out
