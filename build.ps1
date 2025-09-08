$d = $args[0]
if ($d.length -lt 1) {
    Write-Host "Specify directory to copy executable."
}
else {
    $s = [System.IO.Path]::DirectorySeparatorChar
    if (-not $d.EndsWith($s)) {
        $d += $s
    }

    go build -o $d

    if ($LASTEXITCODE -eq 0) {
        "[FINISHED] Executable was built on {0}" -f $d | Write-Host -ForegroundColor Blue
    }
    else {
        "Failed to build. Nothing was copied." | Write-Host -ForegroundColor Magenta
    }
}
