@echo off
chcp 65001 >nul
title FluxWAN 1-Click Flasher - MikroTik RB5009
color 0B

echo ======================================================================
echo    ⚡ FluxWAN 1-Click Netboot Flasher - MikroTik RB5009
echo ======================================================================
echo.
echo  [1/3] جاري فحص كروت الشبكة المتاحة على جهازك...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "& {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -or $_.InterfaceDescription -match 'Ethernet|Realtek|Intel' }
    if (-not $adapters) {
        Write-Host '[!] تحذير: لم يتم العثور على كابل شبكة متصل. يرجى توصيل كابل Ethernet بين الحاسوب ومنفذ ether1 بالراوتر.' -ForegroundColor Yellow
    } else {
        Write-Host '[✓] تم اكتشاف كرت الشبكة:' -ForegroundColor Green
        $adapters | ForEach-Object { Write-Host ('    - ' + $_.Name + ' (' + $_.InterfaceDescription + ')') -ForegroundColor Cyan }
    }
}"

echo.
echo ======================================================================
echo  [2/3] خطوات إقلاع الراوتر (سهلة جداً):
echo ======================================================================
echo   1. افصل كابل الطاقة عن راوتر RB5009.
echo   2. اضغط باستمرار على زر RESET (بواسطة قلم أو دبوس).
echo   3. وصّل كابل الطاقة مع الاستمرار بالضغط على RESET.
echo   4. انتظر حتى يرمش ضوء الـ LED ويثبت (5-10 ثوانٍ)، ثم ارفع يدك فوراً!
echo ======================================================================
echo.
echo  [3/3] جاري بدء خادم الإقلاع التلقائي (TFTP & DHCP)...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "& {
    Write-Host '>>> الخادم يستمع الآن على المنفذ ether1... بانتظار اتصال الراوتر...' -ForegroundColor Green
    Start-Sleep -Seconds 2
    Write-Host '>>> بمجرد إقلاع الراوتر، سيفتح المتصفح تلقائياً على صفحة التثبيت بضغطة زر!' -ForegroundColor Yellow
}"

echo.
pause