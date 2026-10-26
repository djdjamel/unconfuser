param(
    [string]$TargetDll,
    [string]$OutputFile,
    [string]$DepDir = "G:\XpertPharm5"
)

$guard = New-Object 'System.Collections.Generic.HashSet[string]'
$resolveHandler = {
    param($sender, $args)
    $name = (New-Object System.Reflection.AssemblyName($args.Name)).Name
    if ($guard.Contains($name)) { return $null }
    $guard.Add($name) | Out-Null
    $path = Join-Path $DepDir "$name.dll"
    if (Test-Path $path) {
        return [System.Reflection.Assembly]::LoadFrom($path)
    }
    return $null
}
[System.AppDomain]::CurrentDomain.add_AssemblyResolve($resolveHandler)

if (Test-Path $OutputFile) { Remove-Item $OutputFile }

function RecordResult($id, $val) {
    [System.IO.File]::AppendAllText($OutputFile, "$id:::$val`r`n", [System.Text.Encoding]::UTF8)
}

try {
    $asm = [System.Reflection.Assembly]::LoadFrom($TargetDll)
    $helper = $asm.GetType("Xpert.Common.XpertHelper")
    $chiffres = $asm.GetType("Xpert.Common.ChiffresLettres")
    $nw = $asm.GetType("Xpert.Common.NumberToWords")
    $app = $asm.GetType("Xpert.XpertApplication")

    # A. Cryptography
    $mEncrypt = $helper.GetMethod("Encrypt", [Type[]]@([string]))
    $mDecrypt = $helper.GetMethod("Decrypt", [Type[]]@([string]))
    $cryptoTests = @("Hello World", "XAS_ADMIN", "1234567890", "Special_!@#Â§$%&*()_+", "ConfuserEx_Cleaner")
    foreach ($p in $cryptoTests) {
        $enc = $mEncrypt.Invoke($null, @($p))
        $dec = $mDecrypt.Invoke($null, @($enc))
        RecordResult "Crypto_Encrypt_$p" $enc
        RecordResult "Crypto_Decrypt_$p" $dec
    }

    # B. Fiscal Timbre
    $mTimbre = $helper.GetMethod("CalculMtTimbre", [Type[]]@([decimal]))
    $timbreInputs = @(0, 50, 100, 500, 1000, 2500, 10000, 25000, 50000, 100000)
    foreach ($t in $timbreInputs) {
        $res = $mTimbre.Invoke($null, @([decimal]$t))
        RecordResult "Timbre_$t" $res
    }

    # C. Financial Arithmetic & Rounding
    $mRoundMontant = $helper.GetMethod("RoundMontant", [Type[]]@([decimal], [int]))
    $rmTests = @(
        @([decimal]"12.3456", 2),
        @([decimal]"12.3456", 0),
        @([decimal]"12.3456", 3),
        @([decimal]"0.0001", 2),
        @([decimal]"-5.678", 1),
        @([decimal]"100.5", 0),
        @([decimal]"99.999", 2)
    )
    foreach ($rm in $rmTests) {
        $res = $mRoundMontant.Invoke($null, @($rm[0], $rm[1]))
        RecordResult "RoundMontant_$($rm[0])_$($rm[1])" $res
    }

    $mRoundPrix = $helper.GetMethod("RoundPrix", [Type[]]@([decimal]))
    $rpTests = @([decimal]"10.5", [decimal]"10.25", [decimal]"10.123", [decimal]"99.99", [decimal]0, [decimal]"1500.75")
    foreach ($rp in $rpTests) {
        $res = $mRoundPrix.Invoke($null, @($rp))
        RecordResult "RoundPrix_$rp" $res
    }

    $mGetValP = $helper.GetMethod("GetValuePourcentage", [Type[]]@([decimal], [decimal]))
    $mGetAddP = $helper.GetMethod("GetAddPourcentage", [Type[]]@([decimal], [decimal]))
    $mGetSubP = $helper.GetMethod("GetSubPourcentage", [Type[]]@([decimal], [decimal]))
    $mSub = $helper.GetMethod("Subtract", [Type[]]@([decimal], [decimal]))

    RecordResult "Pct_Val_100_19" ($mGetValP.Invoke($null, @([decimal]100, [decimal]19)))
    RecordResult "Pct_Val_250_9" ($mGetValP.Invoke($null, @([decimal]250, [decimal]9)))
    RecordResult "Pct_Val_0_19" ($mGetValP.Invoke($null, @([decimal]0, [decimal]19)))
    RecordResult "Pct_Add_100_19" ($mGetAddP.Invoke($null, @([decimal]100, [decimal]19)))
    RecordResult "Pct_Add_250_9" ($mGetAddP.Invoke($null, @([decimal]250, [decimal]9)))
    RecordResult "Pct_Sub_100_10" ($mGetSubP.Invoke($null, @([decimal]100, [decimal]10)))
    RecordResult "Pct_Sub_200_15" ($mGetSubP.Invoke($null, @([decimal]200, [decimal]15)))
    RecordResult "Sub_100_25" ($mSub.Invoke($null, @([decimal]100, [decimal]25)))
    RecordResult "Sub_123.45_23.45" ($mSub.Invoke($null, @([decimal]"123.45", [decimal]"23.45")))

    # D. String Manipulation & Parsing
    $mTrim = $helper.GetMethod("StringTrim", [Type[]]@([string]))
    $mLeft = $helper.GetMethod("StringLeft", [Type[]]@([string], [int]))
    $mRight = $helper.GetMethod("StringRight", [Type[]]@([string], [int]))
    $mParse = $helper.GetMethod("StringtoIntParseValueDefault", [Type[]]@([string], [int]))

    RecordResult "Str_Trim_1" ($mTrim.Invoke($null, @("   hello   ")))
    RecordResult "Str_Trim_2" ($mTrim.Invoke($null, @("   ")))
    RecordResult "Str_Trim_3" ($mTrim.Invoke($null, @("Xpert Pharm ")))
    RecordResult "Str_Left_1" ($mLeft.Invoke($null, @("XpertPharm", 5)))
    RecordResult "Str_Left_2" ($mLeft.Invoke($null, @("Test", 4)))
    RecordResult "Str_Left_3" ($mLeft.Invoke($null, @("Test", 0)))
    RecordResult "Str_Right_1" ($mRight.Invoke($null, @("XpertPharm", 5)))
    RecordResult "Str_Right_2" ($mRight.Invoke($null, @("Test", 4)))
    RecordResult "Str_Right_3" ($mRight.Invoke($null, @("Test", 0)))
    RecordResult "Str_Parse_1" ($mParse.Invoke($null, @("1234", 0)))
    RecordResult "Str_Parse_2" ($mParse.Invoke($null, @("invalid", 42)))
    RecordResult "Str_Parse_3" ($mParse.Invoke($null, @("", 99)))
    RecordResult "Str_Parse_4" ($mParse.Invoke($null, @("-500", 0)))

    # E. ChiffresLettres (French & Arabic)
    $mMoneyToLetter = $chiffres.GetMethod("MoneyToLetter", [Type[]]@([decimal]))
    $mMoneyToArabic = $chiffres.GetMethod("MoneyToArabicLetter", [Type[]]@([decimal]))
    $mConverti = $chiffres.GetMethod("Converti", [Type[]]@([double]))

    $moneyTests = @([decimal]0, [decimal]1, [decimal]12, [decimal]100, [decimal]"1234.56", [decimal]1000000, [decimal]"9876543.21")
    foreach ($m in $moneyTests) {
        RecordResult "Chiffres_MoneyToLetter_$m" ($mMoneyToLetter.Invoke($null, @($m)))
        RecordResult "Chiffres_MoneyToArabicLetter_$m" ($mMoneyToArabic.Invoke($null, @($m)))
    }

    $convTests = @(0.0, 1.0, 15.0, 100.0, 1234.0, 50000.0)
    foreach ($c in $convTests) {
        RecordResult "Chiffres_Converti_$c" ($mConverti.Invoke($null, @([double]$c)))
    }

    # F. NumberToWords
    $mNumDec = $nw.GetMethod("changeNumericToWords", [Type[]]@([decimal]))
    $mCurrDec = $nw.GetMethod("changeCurrencyToWords", [Type[]]@([decimal]))
    $mNumStr = $nw.GetMethod("changeNumericToWords", [Type[]]@([string]))
    $mCurrStr = $nw.GetMethod("changeCurrencyToWords", [Type[]]@([string]))

    $nwDecTests = @([decimal]0, [decimal]1, [decimal]25, [decimal]350, [decimal]1234, [decimal]54321)
    foreach ($d in $nwDecTests) {
        RecordResult "NumWords_NumDec_$d" ($mNumDec.Invoke($null, @($d)))
        RecordResult "NumWords_CurrDec_$d" ($mCurrDec.Invoke($null, @($d)))
    }

    $nwStrTests = @("0", "123", "999")
    foreach ($s in $nwStrTests) {
        RecordResult "NumWords_NumStr_$s" ($mNumStr.Invoke($null, @($s)))
        RecordResult "NumWords_CurrStr_$s" ($mCurrStr.Invoke($null, @($s)))
    }

    # G. System Constants
    $mSysPass = $app.GetMethod("GetSysPass", [System.Reflection.BindingFlags]"Public,Static")
    $sysPass = $mSysPass.Invoke($null, @())
    $isSysPassValid = $sysPass -match '^@\d{4}@$'
    RecordResult "SysPass_FormatValid" $isSysPassValid

    RecordResult "Execution_Status" "SUCCESS"
} catch {
    RecordResult "Execution_Status" "ERROR: $($_.Exception.ToString())"
}

# ---- Instrumentation d'audit (ajoutee) ----
$meta = $OutputFile + '.meta.txt'
$ml = New-Object System.Collections.Generic.List[string]
$ml.Add("Target=$TargetDll")
$ml.Add("TargetSHA256=" + (Get-FileHash $TargetDll -Algorithm SHA256).Hash)
$ml.Add("PSVersion=" + $PSVersionTable.PSVersion)
$ml.Add("Bitness=" + ([IntPtr]::Size * 8))
$ml.Add("CLR=" + [Environment]::Version)
$ml.Add("Culture=" + [Threading.Thread]::CurrentThread.CurrentCulture.Name)
$ml.Add("TimeZone=" + [TimeZoneInfo]::Local.Id)
$ml.Add("COR_ENABLE_PROFILING=" + $env:COR_ENABLE_PROFILING)
foreach ($as in [AppDomain]::CurrentDomain.GetAssemblies()) {
    $loc = ''
    try { $loc = $as.Location } catch { }
    if ($loc -and ($loc -notlike "$env:windir*")) {
        $ml.Add("LOADED|" + $as.GetName().Name + "|" + $as.GetName().Version + "|" + $loc + "|" + (Get-FileHash $loc -Algorithm SHA256).Hash)
    }
}
$ml | Set-Content $meta
