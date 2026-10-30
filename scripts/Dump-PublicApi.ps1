<#
.SYNOPSIS
    Dumps the normalized public API contract of a .NET assembly using dnlib.
.DESCRIPTION
    Exports all visible types, methods, fields, properties, events, and custom attributes
    in a deterministic, sorted format suitable for regression comparison and diffing.
.PARAMETER Dll
    Path to the target .NET assembly.
.PARAMETER Out
    Path to the output text file.
.PARAMETER DnlibPath
    Optional path to dnlib.dll. If omitted, auto-discovers dnlib.dll in standard build directories.
#>
param(
    [Parameter(Mandatory=$true)][string]$Dll,
    [Parameter(Mandatory=$true)][string]$Out,
    [Parameter(Mandatory=$false)][string]$DnlibPath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Dll)) {
    throw "Target DLL not found: $Dll"
}

if (-not $DnlibPath) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $repoRoot = Resolve-Path (Join-Path $scriptDir "..")
    $candidates = @(
        (Join-Path $repoRoot "ConfuserExKillerRunner\bin\Release\net48\dnlib.dll"),
        (Join-Path $repoRoot "ConfuserExKillerRunner\bin\Debug\net48\dnlib.dll"),
        (Join-Path $repoRoot "ConfuserExKillerRunner\bin\Release\net8.0-windows\dnlib.dll"),
        (Join-Path $repoRoot "ConfuserExKillerRunner\bin\Debug\net8.0-windows\dnlib.dll")
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) {
            $DnlibPath = $cand
            break
        }
    }
}

if (-not $DnlibPath -or -not (Test-Path $DnlibPath)) {
    throw "dnlib.dll could not be located. Please provide -DnlibPath or build ConfuserExKillerRunner."
}

Add-Type -Path $DnlibPath

$resolvedDll = (Resolve-Path $Dll).Path
$m = [dnlib.DotNet.ModuleDefMD]::Load($resolvedDll)
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

$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$L | Sort-Object | Set-Content -Path $Out -Encoding UTF8
Write-Host "Normalized public API dump written ($($L.Count) records): $Out"
