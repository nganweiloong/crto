# Regenerate both PDFs with headless Chrome.
# Usage: powershell -ExecutionPolicy Bypass -File build\make_pdfs.ps1

$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $chrome)) {
    $chrome = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
}
if (-not (Test-Path $chrome)) {
    Write-Error "Chrome or Edge not found."
    exit 1
}

$root = Split-Path -Parent $PSScriptRoot
$docs = @("CRTO-Playbook", "CRTO-Mock-Exam")

foreach ($d in $docs) {
    $html = Join-Path $root "$d.html"
    $pdf  = Join-Path $root "$d.pdf"
    if (-not (Test-Path $html)) {
        Write-Warning "Missing $html - run the Python build first."
        continue
    }
    $url = "file:///" + ($html -replace '\\', '/')
    Write-Host "Rendering $d..."
    & $chrome --headless=new --disable-gpu --no-sandbox --no-pdf-header-footer `
        --virtual-time-budget=15000 --run-all-compositor-stages-before-draw `
        --print-to-pdf="$pdf" "$url" 2>$null
    Start-Sleep -Seconds 2
    if (Test-Path $pdf) {
        $size = (Get-Item $pdf).Length
        Write-Host ("  OK  {0}  ({1:N0} bytes)" -f $pdf, $size)
    } else {
        Write-Warning "  PDF was not created: $pdf"
    }
}

Write-Host "Done."
