/** Windows private backup ACLs. Refuse install if Windows cannot prove a private DACL.
 * This operates only on FARADAY-owned directories/files. Never relax user policy.
 */
import {spawnSync} from 'node:child_process';
import {lstatSync} from 'node:fs';
import {join} from 'node:path';

const command=String.raw`
$ErrorActionPreference = 'Stop'
$path = $env:FARADAY_ACL_PATH
$mode = $env:FARADAY_ACL_MODE
if ([string]::IsNullOrWhiteSpace($path) -or $mode -notin @('protect','verify')) { throw 'bad-input' }
$item = Get-Item -LiteralPath $path -ErrorAction Stop
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse-point' }
$who = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($who,'S-1-5-18','S-1-5-32-544')
$acl = Get-Acl -LiteralPath $path
if ($mode -eq 'protect') {
  $acl.SetAccessRuleProtection($true,$false)
  foreach ($entry in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($entry) }
  $inherit = [Security.AccessControl.InheritanceFlags]::None
  if ($item.PSIsContainer) { $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit }
  foreach ($id in $allowed) {
    $sid = [Security.Principal.SecurityIdentifier]::new($id)
    $ace = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl,
      $inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.AddAccessRule($ace)
  }
  Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
  $acl = Get-Acl -LiteralPath $path
}
if (-not $acl.AreAccessRulesProtected) { throw 'inherited-ace' }
$aces = $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
$ownerFound = $false
foreach ($ace in $aces) {
  $id = $ace.IdentityReference.Value
  if ($id -notin $allowed -or $ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw 'unexpected-ace' }
  if ($id -eq $who -and (($ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)) {
    $ownerFound = $true
  }
}
if (-not $ownerFound) { throw 'owner-not-authorized' }
`;
function windowsAcl(path,mode) {
 if(process.platform!=='win32') return;
 if(typeof path!=='string'||!path||!['protect','verify'].includes(mode))throw Error('Invalid Windows backup ACL request');
 const stat=lstatSync(path);
 if(stat.isSymbolicLink())throw Error('Unsafe Windows backup reparse point');
 const windowsRoot=process.env.SystemRoot;
 if(typeof windowsRoot!=='string'||!windowsRoot)throw Error('Windows backup ACL protection is not verified');
 const powershell=join(windowsRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');
 const child=spawnSync(powershell,['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(command,'utf16le').toString('base64')],{
  encoding:'utf8',timeout:20000,maxBuffer:256*1024,windowsHide:true,
  env:{...process.env,FARADAY_ACL_PATH:path,FARADAY_ACL_MODE:mode}
 });
 // Never echo the subprocess output, which could disclose path names.
 if(child.error||child.status!==0)throw Error('Windows backup ACL protection is not verified');
}
export const protectWindowsAcl=path=>windowsAcl(path,'protect');
export const verifyWindowsAcl=path=>windowsAcl(path,'verify');
