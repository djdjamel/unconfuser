# Rejoue InterpretPEVerifyILResult du runner sur le journal PEVerify reel (/il) de la DLL finale figee.
# Doit etre lance avec PowerShell 32-bit (le runner est x86).
$asmP = 'c:\Users\acer\claude\xp_src\ConfuserExKillerRunner\bin\Debug\net48'
[Reflection.Assembly]::LoadFrom("$asmP\dnlib.dll") | Out-Null
$a  = [Reflection.Assembly]::LoadFrom("$asmP\ConfuserExKillerRunner.exe")
$qa = $a.GetType('ConfuserExKillerRunner.Analysis.QualityAuditor')
$rt = $a.GetType('ConfuserExKillerRunner.Analysis.AuditReport')
$r  = [Activator]::CreateInstance($rt)
$logPath = 'c:\Users\acer\claude\xp_src\audit\final_audit\out\C2_peverify_il.log'
$bytes = [IO.File]::ReadAllBytes($logPath)
$clean = New-Object System.Collections.Generic.List[byte]
foreach ($b in $bytes) { if ($b -ne 0) { $clean.Add($b) } }
$txt = [Text.Encoding]::GetEncoding(1252).GetString($clean.ToArray())
$lines = ($txt -split "`r?`n") | Where-Object { $_ -match '^\[IL\]' }
"Lignes d'erreur injectees: " + @($lines).Count
$m = $qa.GetMethod('InterpretPEVerifyILResult', [Reflection.BindingFlags]'NonPublic,Static')
$m.Invoke($null, @(1, ($lines -join "`n"), '', $false, $r)) | Out-Null
'ILVerificationStatus=' + $rt.GetProperty('ILVerificationStatus').GetValue($r)
'ILVerificationNotes='  + $rt.GetProperty('ILVerificationNotes').GetValue($r)
