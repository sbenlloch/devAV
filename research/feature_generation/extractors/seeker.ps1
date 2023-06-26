# Get the base path as the root of the C:\ drive
$basePath = "C:\"

# Get the directory containing the script file
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Create the destination folder path by joining the script directory with the "PEfiles" folder name
$destination = Join-Path -Path $scriptDir -ChildPath "PEfiles"

# Create the destination folder if it doesn't exist
if (!(Test-Path $destination)) {
    New-Item -ItemType Directory -Path $destination
}

# Get all files in the source directory with .exe, .dll, and .sys extensions
$files = Get-ChildItem -Path $basePath -Include *.exe, *.dll, *.sys -Recurse -ErrorAction SilentlyContinue | Where-Object {
    try {
        [System.BitConverter]::ToUInt16([System.IO.File]::ReadAllBytes($_.FullName)[0..1], 0) -eq 0x5A4D
    }
    catch {
        $false
    }
}

# Initialize the counter and total number of files
$count = 0
$total = $files.Count

# Initialize the timer
$timer = [Diagnostics.Stopwatch]::StartNew()

# Loop through each file and copy it to the destination directory with an MD5 hash filename
foreach ($file in $files) {


    # Get the MD5 hash of the file
    $md5 = Get-FileHash $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Hash

    # If an error occurs getting the hash, skip the file
    if (!$md5) {
        Write-Host "Error getting hash for $($file.FullName) - Skipping file" -ForegroundColor Yellow
        continue
    }

    # Create the destination filename with the MD5 hash
    $destinationFilename = "{0}_{1}" -f $md5, $file.name
    $destinationFilePath = Join-Path -Path $destination -ChildPath $destinationFilename

    # Copy the file to the destination directory with the MD5 hash filename
    Copy-Item $file.FullName -Destination $destinationFilePath -ErrorAction SilentlyContinue

    # Update the progress bar
    $percent = ($count / $total) * 100
    Write-Progress -Activity "Copying Files" -PercentComplete $percent -CurrentOperation $file.FullName -Status "File $count of $total"

    # If an error occurs copying the file, skip the file
    if (!$?) {
        Write-Host "Error copying $($file.FullName) - Skipping file" -ForegroundColor Yellow
        continue
    }

    # Increment the counter
    $count++
}

# Stop the timer and calculate the elapsed time
$timer.Stop()
$timeTaken = $timer.Elapsed.ToString("hh\:mm\:ss")

# Output a summary of the copy operation
Write-Host "`nCopy operation completed in $timeTaken`n" -ForegroundColor Green
Write-Host "Total files: $total"
Write-Host "Successful copies: $($count-($total-$files.Count))"
Write-Host "Skipped files: $($total-$files.Count)" -ForegroundColor Yellow
