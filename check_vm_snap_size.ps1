param ( [string] $Hostname = "",
 [double] $crit = 100,
 [double] $warn = 50,
 [string] $CredFile,
 [string] $HostExclude =@(""),
 [string] $GuestExclude =@(""),
 [switch] $help
)
$countLargeSnap = 0
$critcount = 0
$warncount = 0
$snapcount = 0
$crittsize = 0
$warntsize = 0
$snaptsize = 0
$LargeSnapNames = ""
$critSnapNames = ""
$warnSnapNames = ""
$GuestExcludeA=$GuestExclude.split(" ")
# parameter error checking
if ( $warn -ge $crit) {
 Write-Host "Error - crit vaule must be larger than warn value" -foregroundcolor "red"
 exit 3
}
if ( $Hostname -eq "") {
 Write-Host "Error - Hostname must be specified" -foregroundcolor "red"
 exit 3
}
  
#load VMware PowerCLI
#use the followig if PowerCLI less than version 6.5
#add-pssnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue
#use the following for PowerCLI version 6.5 or later
Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue
  
# If no credential file specific use the account permission from the user running the script
# otherwise use the credential file to get the host, user, and password strings
if ($CredFile -eq "" ) {
 Connect-VIServer -Server $Hostname -WarningAction SilentlyContinue > $null
}
else {
 $creds = Get-VICredentialStoreItem -file $CredFile
 # check to see if the hostname specific matches hostname in credential file
 if ( $Hostname -eq $creds.Host) {
  Connect-VIServer -Server $creds.Host -User $creds.User -Password $creds.Password -WarningAction SilentlyContinue > $null
 }
 else{
  Write-Host "Unknown - Hostname specific does not match hostname in credentials file" -foregroundcolor "red"
  exit 3
 }
}
  
if ($global:DefaultVIServers.Count -lt 1) {
 write-host "Unknown - Connection to host failed!"
 exit 3
}

# Get the list of snaphosts to evaluate from the host, excluding hosts and
# guests if defined
$snapshots = get-VMhost | ?{$HostExclude -notcontains $_.Name} | get-vm | ?{$GuestExcludeA -notcontains $_.Name} | get-snapshot
  
# Loop through each snapshot and see any sizes exceed the warning or crital
# thresholds. If so then store their names and sizes. Could put into an array
# but that is for another day.
foreach ( $snap in $snapshots ) {
 $snapcount++
 $snaptsize = $snaptsize + $snap.SizeMB
 if ( $snap.SizeMB -ge $warn -and $snap.SizeMB -lt $crit ) {
  $warncount++
  $wVMName = $snap.VM
  $wVMSize = $snap.SizeMB
  $warntsize = $warntsize + $snap.SizeMB
if ( $warnSnapNames -eq "") {
    $warnSnapNames = "${wVMName}:${wVMSize}MB "
    }
   else {
    $warnSnapNames += "${wVMName}:${wVMSize}MB "
    }
        }

  elseif ( $snap.SizeMB -ge $crit  ) {
   $critcount++
   $cVMName = $snap.VM
   $cVMSize = $snap.SizeMB
   $crittsize = $crittsize + $snap.SizeMB
   if ( $critSnapNames -eq "") {
    $critSnapNames = "${cVMName}:${cVMSize}MB "
    }
   else {
    $critSnapNames += "${cVMName}:${cVMSize}MB "
    }
 }
}
  
if ( $critcount -gt 0 ) {
 Write-Host "Critical -" $critcount "VM's with snapshosts larger than" $crit "MB :" $critSnapNames "|snaps=$snapcount;$warncount;$critcount;; ssize=${snaptsize}MB;$warn;$crit;;"
 exit 2
}
elseif( $warncount -gt 0 ) {
 Write-Host "Warning -" $warncount "VM's with snapshosts larger than" $warn "MB :" $warnSnapNames "|snaps=$snapcount;$warncount;$critcount;; ssize=${snaptsize}MB;$warn;$crit;;"
 exit 1
}
if ( $critcount -eq 0 ) {
 Write-Host "OK - No VM's with snapshosts larger than " $warn "MB" "or" $crit "MB" "|snaps=$snapcount;$warncount;$critcount;; ssize=${snaptsize}MB;$warn;$crit;;"
 exit 0
}