#V0.6 
#Status: working, but not every combination is tested in depth.
#Use "-help" to get help



param ( [string] $Hostname = "",
 [double] $sizec,
 [double] $sizew,
 [double] $agew, 
 [double] $agec,
 [double] $allcrit = 20,
 [string] $CredFile,
 [string] $HostExclude =@(""),
 [string] $GuestExclude =@(""),
 [switch] $help,
 [string] $vmwareusername,
 [string] $vmwarepassword
)


#Configuration
$scriptpath = $MyInvocation.MyCommand.Path | Split-Path
$path2psexec = $scriptpath


#Default values
$countLargeSnap = 0
$critcountSize = 0
$warncountSize = 0
$snapcountSize = 0
$critcountAge = 0
$warncountAge = 0
$snapcount = 0
$crittsize = 0
$warntsize = 0
$snaptsize = 0
$oldSnaps  = 0
$LargeSnapNames = ""
$critSnapNamesSize = ""
$warnSnapNamesSize = ""
$critSnapNamesAge = ""
$warnSnapNames = ""
$authfilerequired = $false
#set exitcode to unknown, in case something strange happens
$exitcode = 3

#HELP
if (!($Hostname)) {
   write-host "NO HOSTNAME SPECIFIED!!"
   $help = $true
} 


if ($help) {
    write-host "Version: 0.6" -ForegroundColor Green
    write-host "Arguments:
-Hostname : IP/DNS NAME of ESXi/vCenter
-sizew/-sizec    : Max warning/critical size of snapshots in gigabyte
-agew/-agec      : Max warning/critical age of Snapshots in days
-allcrit         : Max size (sum) of all snapshots in gigabyte befor critical
-CredFile        : Full path to VMWare credential file
-hostexclude     : exclude Virtual Machine Hosts. Name of Host needs to be exact.
-guestexclude    : exclude virtual machines. Searches if Name contains, dont' need to be exact match.
-help            : This help message
-vmwareusername  : Username to generate vcenter/esxi credfile (WARNING User/Password send in CLEAR text and will shown in logs!
-vmwarepassword  : Password for vcenter/esxi.  As long as these username/password is specified, the script will not return userfull values.

Examples: 
SIZE and AGE      - '.\check_vmware_snapshots.ps1 -hostname 192.168.0.2 -CredFile `"C:\ProgramData\icinga2\opt\credentials\192.168.0.2.admin.credfile.xml`" -sizew 5 -sizec 10 -agew 7 -agec 10'
SIZE with allcrit - '.\check_vmware_snapshots.ps1 -hostname 192.168.0.2 -CredFile `"C:\ProgramData\icinga2\opt\credentials\192.168.0.2.admin.credfile.xml`" -sizew 5 -sizec 10 -allcrit 50'

Requirements: psexec is requirerd to setup the credential file, as the file will be encrypted with this user, its not necessary after it.

INSTALLATION DETAILS:
This script needs a vmware credentialfile. If the script can't fine the specified credfile, it will display a command which can be used on the agent machine to create it. It's also possible to specify username and password to create the credfile from Icinga2/nagios on the fly but password will be send in cleartext!. If your service account is 'nt authority\network service' that the only working method th script is offering.

Examples to create a Credfile with another user:
Local system: 
`"$scriptpath\psexec`" -i -s Powershell.exe -command `"& '$scriptpath\check_vmware_snapshots.ps1'`" -args `"-hostname 192.168.0.2 -credfile C:\ProgramData\icinga2\opt\credentials\192.168.0.2_admin_vmware_credfile.xml`" <--- (incuding all quotes!)
Some other user:
`"$scriptpath\psexec`" -i -u `"mydomain\someuser`" Powershell.exe -command `"& '$scriptpath\check_vmware_snapshots.ps1'`" -args `"-hostname 192.168.0.2 -credfile C:\ProgramData\icinga2\opt\credentials\credfile.xml`"
" -ForegroundColor Gray
 
exit 3
 
}
 

  
# parameter error checking
if ( $sizew -ge $sizec -and $sizew -gt 0 -and $sizec -gt 0 -or $agew -ge $agec -and $agew -gt 0 -and $agec -gt 0 ) {
 Write-Host "Error - crit value must be larger than warn value" -foregroundcolor "red"
 exit 3
}
if ( $Hostname -eq "") {
 Write-Host "Error - Hostname must be specified" -foregroundcolor "red"
 exit 3
}
  
#load VMware PowerCLI
Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue

#Function to read or create credfile if not found
function get_credfile ($CredFile, $username, $password) { #v0.5
  $creds = ""
  if (test-path $CredFile) {
    #Warn if vmwareusername and password are specified. REMOVE THIS IF YOU DON'T CARE ABOUT SECURITY
    if ( $vmwarepassword ) { 
       write-host "Found Credfile - Please remove '-vmwarepassword' parameter!"
       exit 3
    }
    $creds = Get-VICredentialStoreItem -file $CredFile
  } else {
    $loggedOnUser = $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    if ($loggedOnUser -match '\SYSTEM' ) { 
      $psexecusercommand = "-s"   
    } else {
      $psexecusercommand = "-u $loggedOnUser"
    }
    write-host "Credfile not exists!"
    if ( $loggedOnUser -match "network service" -or  $loggedOnUser -match "netzwerkdienst"  -and (!( $vmwareusername -and $vmwarepassword ))) {
      write-host "Network service is used as service account, please specify -vmwareusername and -vmwarepassword to create the credfile."
      exit 3
    } else {
      write-host "You need to run  --> `"$scriptpath\psexec`" -i $psexecusercommand Powershell.exe -command `"& '$scriptpath\check_vmware_snapshots.ps1'`" -args `"-hostname $hostname -credfile $credfile`" on $hostname <--- (incuding all quotes!) once to create it!"
      write-host "Alternatively, you can specify the -vmwareuserner/-vmwarepassword parameter to create the credfile from monitoring server directly, but you must remove this parameters afterward"
    }
    If (!( $username -or $password) ) { 
      $login=GET-CREDENTIAL -Message "vCenter/ESXi Login" –Username “administrator@vsphere.local” 
      #Convert to Plaintext 
      $username = $login.UserName #Is always Plaintext
   
      #Convert Password to Plaintext
      $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($login.Password)
      $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }    
    New-VICredentialStoreItem -Host "$Hostname" -User "$username" -Password "$password" -file $CredFile
    "Authfile created - Recheck to test it"
    exit 3
  }
  return $creds
}


# If no credential file specified use the user account credentials from logon on user
# otherwise use the credential file to get the host, user, and password strings
if ($CredFile -eq "" ) {
 Connect-VIServer -Server $Hostname -WarningAction SilentlyContinue > $null
}
else {
  if ($vmwareusername -and $vmwarepassword) {      
     get_credfile $CredFile $vmwareusername $vmwarepassword
  } else {
    $Creds = get_credfile $CredFile
  }
 # check to see if the hostname specified matches hostname in credential file
 if ( $Hostname -match $creds.Host) {
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
$snapshots = get-VMhost | ?{ $_.Name -notcontains $HostExclude} | get-vm | ?{ $_.Name -notmatch $GuestExclude} | get-snapshot
  
# Loop through each snapshot and see any sizes exceed the warning or crital
# thresholds. If so then store their names and sizes. Could put into an array
# but that is for another day.

foreach ( $snap in $snapshots ) {
 $snapcount++
 $snapAge = ((get-date) - [dateTime]$snap.Created).Days
 $snaptsize = $snaptsize + [math]::Round($snap.SizeGB, 2)
 
 #CHECK SIZE
 if ( $snap.SizeGB -gt $sizew -and $snap.SizeGB -lt $sizec -and $sizew) {
  $warncountSize++
  $wVMName = $snap.VM
  $wVMSize = [math]::Round($snap.SizeGB, 2)
  $warntsize = $warntsize + [math]::Round($snap.SizeGB, 2)
  if ( $warnSnapNamesSize -eq "") {
    $warnSnapNamesSize = "${wVMName}: ${wVMSize}GB Age:$snapAge days`n"
  }
  else {
   $warnSnapNamesSize += "${wVMName}: ${wVMSize}GB Age:$snapAge days`n"
  }
 }      
 elseif ( $snap.SizeGB -gt $sizec -and $sizec ) {
  $critcountSize++
  $cVMName = $snap.VM
  $cVMSize = [math]::Round($snap.SizeGB, 2)
  $crittsize = $crittsize + [math]::Round($snap.SizeGB, 2)
  if ( $critSnapNamesSize -eq "") {
   $critSnapNamesSize = "${cVMName}: Size:${cVMSize}GB Age:$snapAge days`n"
  }
   else {
    $critSnapNamesSize += "${cVMName}: ${cVMSize}GB Age:$snapAge days`n"
   } 
 } 
 
 #CHECK AGE
 #Get oldest Snapshot for Perfdata
 if (!($oldestsnap)) {
  $oldestsnap =  $snapAge
 }
 if ($snapAge -lt $oldestsnap ) {
  $oldestsnap = $snapAge
 }
 #Warning
 if ( $snapAge -ge $agew -and $snapAge -le $agec -and $agec -and $agew ) {
  $warncountage++
  $wVMName = $snap.VM
  if ( $warnSnapNamesAge -eq "") {
   $warnSnapNamesAge = "${wVMName}:${snapAge} days`n"
  } else {
   $warnSnapNamesAge += "${wVMName}:${snapAge} days`n"
  }
  #critical
 } elseif ( $snapAge -ge $agec -and $agec ) {
  $critcountage++
  $cVMName = $snap.VM
  if ( $critSnapNamesAge -eq "") {
   $critSnapNamesAge = "${cVMName}:${snapAge} days`n"
  } else {
   $critSnapNamesAge += "${cVMName}:${snapAge} days`n"
  } 
 } 
#If okay, still return existing snapshots
 if ( $snap.SizeGB -lt $sizew -or $snapAge -lt $agew -or ((!($sizew)) -and (!($sizec))) -and ((!($agew)) -and (!($agec)))  ) {
  $VMName = $snap.VM
  $VMSize = $snap.SizeGB
  $VMSize = [math]::Round($snap.SizeGB, 2)
  $allSnaps += "${VMName}: Size:${VMSize}GB - Age:${snapAge} days`n" 
 }
}



if ( $snaptsize -gt $allcrit ) { 
   Write-Host "Critical - Sum of Snapshots exceeding " $allcrit "GB`n"
    if ($exitcode -lt 2 -or $exitcode -eq 3 ) { $exitcode = 2 }
} 

#DEBUG: 
#write-host "$critcountSize - $warncountSize - $critcountAge - $warncountAge "

#SIZE
if ( $snapcount -le 0 ) {
  Write-Host "OK - No Snapshosts available" 
  $exitcode = 0
} else {
  if ( $critcountSize -gt 0 -and $sizec ) {
    Write-Host "Critical -" $critcountSize "VM's with snapshost(s) larger than" $sizec "GB:`n"$critSnapNamesSize
    if ($exitcode -lt 2 -or $exitcode -eq 3 ) { $exitcode = 2 }
  } elseif ( $warncountSize -gt 0 -and $critcountSize -eq 0 -and $sizew ) {
    Write-Host "Warning -" $warncountSize "VM's with snapshost(s) larger than" $sizew "GB:`n"$warnSnapNamesSize
    if ($exitcode -lt 1 -or $exitcode -eq 3 ) { $exitcode = 1 }
  }

  #AGE
  if ( $critcountAge -gt 0 -and $agec ) {
    Write-Host "Critical -" $critcountAge "VM's with snapshost(s) older than" $agec "days`n"$critSnapNamesAge
    if ($exitcode -lt 2 -or $exitcode -eq 3 ) { $exitcode = 2 }
  } elseif( $warncountAge -gt 0 -and (!($critcountAge -gt 0)) -and $agew ) {
    Write-Host "Warning -" $warncountAge "VM's with snapshost(s) older than" $agew "days:`n"$warnSnapNamesAge
    if ($exitcode -lt 1 -or $exitcode -eq 3 ) { $exitcode = 1 }
  }
  #DEBUG
  #write-host $agew - $agec - $sizew - $sizec

  if ( $critcountSize -eq 0 -and $warncountSize -eq 0 -and $critcountAge -eq 0 -and $warncountAge -eq 0 ) {
    if ( ( $agew -le 0 -and $agec -le 0 ) -and ( $sizew -gt 0 -or $sizec -gt 0 )) {
      Write-Host "OK - No VM's with snapshosts larger than" $sizew/$sizec "GB" - Snaps:$snapcount - Snaps Overview:`n" " $allSnaps 
    } elseif ( ( $sizew -le 0 -and $sizec -le 0 ) -and ( $agew -gt 0 -or $agec -gt 0 ) ) {
      Write-Host "OK - No VM's with snapshosts older than $agew/$agec days" - Snaps:$snapcount - Snaps Overview:`n" " $allSnaps 
    } else {
      Write-Host "OK - No VM's with snapshosts larger than" $sizew/$sizec "GB or older than $agew/$agec days" - Snaps:$snapcount - Snaps Overview:`n" " $allSnaps 
    }
    $exitcode = 0
  } 
}
Write-Host "| snaps=$snapcount ssize=${snaptsize}GB;$warntsize;$crittsize oldestSnap=${oldestsnap}s;$warncountAge;$critcountAge"
exit $exitcode

