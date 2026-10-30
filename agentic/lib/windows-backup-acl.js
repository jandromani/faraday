/** Windows private backup ACLs. Refuse install if Windows cannot prove a private DACL.
 * This operates only on FARADAY-owned directories/files. Never relax user policy.
 */
import {spawnSync} from 'node:child_process';
import {lstatSync} from 'node:fs';
import {join} from 'node:path';

const command=String.raw`
$ErrorActionPreference = 'Stop'
$phase = 'initialize'
trap { [Console]::Error.WriteLine('FARADAY-ACL-PHASE:'+$phase); exit 1 }
$path = $env:FARADAY_ACL_PATH
$mode = $env:FARADAY_ACL_MODE
if ([string]::IsNullOrWhiteSpace($path) -or $mode -notin @('protect','verify')) { throw 'bad-input' }
$phase='get-item'
$item = Get-Item -LiteralPath $path -ErrorAction Stop
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse-point' }
$who = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($who,'S-1-5-18','S-1-5-32-544')
$phase='get-acl'
$acl = Get-Acl -LiteralPath $path
if ($mode -eq 'protect') {
  $phase='protect-inheritance'
  $acl.SetAccessRuleProtection($true,$false)
  $phase='remove-access'
  foreach ($entry in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($entry) }
  $inherit = [Security.AccessControl.InheritanceFlags]::None
  if ($item.PSIsContainer) { $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit }
  $phase='add-access'
  foreach ($id in $allowed) {
    $sid = [Security.Principal.SecurityIdentifier]::new($id)
    $ace = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl,
      $inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.AddAccessRule($ace)
  }
  $phase='set-acl'
  Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
  $phase='reopen-acl'
  $acl = Get-Acl -LiteralPath $path
}
$phase='verify-acl'
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
 if(child.error||child.status!==0){
  if(process.env.FARADAY_CI_DIAGNOSTICS==='1'){
    const component=path.includes('.config-')?'staged-config':
      path.endsWith('.faraday')?'private-parent':
      path.endsWith('targets')?'target-directory':
      path.endsWith('.mcp.json')?'active-config':
      path.endsWith('.json')?'private-backup':'other';
    const output=String(child.stderr||'')+' '+String(child.stdout||'');
    const phase=output.match(/FARADAY-ACL-PHASE:(initialize|get-item|get-acl|protect-inheritance|remove-access|add-access|set-acl|reopen-acl|verify-acl)/)?.[1]||'unknown';
    const reason=/owner-not-authorized/.test(output)?'owner-not-authorized':
      /unexpected-ace/.test(output)?'unexpected-ace':
      /inherited-ace/.test(output)?'inherited-ace':
      /Access is denied|UnauthorizedAccessException/i.test(output)?'access-denied':
      /Cannot find path|ItemNotFoundException/.test(output)?'not-found':
      child.error?'launch-failure':'platform-acl-rejection';
    process.stderr.write('[FARADAY ACL] '+mode+'/'+component+'/'+reason+'/'+phase+'\\n');
  }
  throw Error('Windows backup ACL protection is not verified');
 }
}
export const protectWindowsAcl=path=>windowsAcl(path,'protect');
export const verifyWindowsAcl=path=>windowsAcl(path,'verify');
