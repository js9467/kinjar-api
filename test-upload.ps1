# Test upload script
$uri = "https://kinjar-api.fly.dev/upload"
$filePath = "D:\Software\Kinjar API\kinjar-api\test-upload.txt"

# Create multipart form data
$boundary = [System.Guid]::NewGuid().ToString()
$LF = "`r`n"

$bodyLines = @(
    "--$boundary",
    "Content-Disposition: form-data; name=`"family_slug`"$LF",
    "slaughterbeck$LF",
    "--$boundary",
    "Content-Disposition: form-data; name=`"type`"$LF", 
    "photo$LF",
    "--$boundary",
    "Content-Disposition: form-data; name=`"file`"; filename=`"test-upload.txt`"",
    "Content-Type: text/plain$LF",
    [System.IO.File]::ReadAllText($filePath),
    "--$boundary--$LF"
)

$body = $bodyLines -join $LF

try {
    $response = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType "multipart/form-data; boundary=$boundary" -Headers @{"Origin"="http://localhost:3000"}
    Write-Host "Success: $($response.StatusCode)"
    Write-Host "Response: $($response.Content)"
} catch {
    Write-Host "Error: $($_.Exception.Message)"
    Write-Host "Status: $($_.Exception.Response.StatusCode)"
}