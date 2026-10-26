param([int]$Runs = 25)
# C4 - Test de stabilite : N executions des 95 vecteurs sur l'originale et la finale (PowerShell 32-bit, memes conditions).
$root = 'c:\Users\acer\claude\xp_src'
$d = "$root\audit\final_audit"
$ps = 'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
foreach ($label in 'original','final') {
    $dll = if ($label -eq 'original') { "$d\frozen\Xpert.Common.BLL.original.dll" } else { "$d\frozen\Xpert.Common.BLL_final.dll" }
    $ok = 0; $crash = 0; $other = 0; $codes = @{}
    for ($i = 1; $i -le $Runs; $i++) {
        $out = "$d\out\C4_stab_${label}_$i.txt"
        & $ps -NoProfile -ExecutionPolicy Bypass -File "$d\07_run_vectors.ps1" -TargetDll $dll -OutputFile $out -DepDir 'G:\XpertPharm5' 2>&1 | Out-Null
        $code = $LASTEXITCODE
        $lines = @(Get-Content $out -ErrorAction SilentlyContinue).Count
        $key = "exit=$code;lines=$lines"
        if ($codes.ContainsKey($key)) { $codes[$key]++ } else { $codes[$key] = 1 }
        if ($code -eq 0 -and $lines -eq 95) { $ok++ } elseif ($code -eq -1073741571) { $crash++ } else { $other++ }
    }
    "{0,-8} runs={1} OK={2} STACKOVERFLOW={3} autre={4}  detail: {5}" -f $label, $Runs, $ok, $crash, $other, (($codes.GetEnumerator() | ForEach-Object { $_.Key + 'x' + $_.Value }) -join ' | ')
}
