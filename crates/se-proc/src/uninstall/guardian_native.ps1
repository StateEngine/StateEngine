# Emit fixed P/Invoke signatures in memory. No compiler process, C# source,
# generated DLL, caller module search path or executable text is accepted.
function Initialize-CleanupNative {
    $assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        [Reflection.AssemblyName]::new('StateEngine.UninstallCleanup'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule('NativeCleanup')
    $type = $module.DefineType('StateEngine.UninstallNative', [Reflection.TypeAttributes]::Public)
    $dll = [IO.Path]::Combine($env:SystemRoot, 'System32', 'kernel32.dll')
    $constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([type[]]@([string]))
    $fields = [Reflection.FieldInfo[]]@(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
        [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet'))
    $signatures = @(
        @('ReOpenFile', [IntPtr], [type[]]@([IntPtr],[uint32],[uint32],[uint32])),
        @('CreateFileW', [IntPtr], [type[]]@([string],[uint32],[uint32],[IntPtr],[uint32],[uint32],[IntPtr])),
        @('GetFileInformationByHandleEx', [bool], [type[]]@([IntPtr],[int],[IntPtr],[uint32])),
        @('GetFileInformationByHandle', [bool], [type[]]@([IntPtr],[IntPtr])),
        @('SetFileInformationByHandle', [bool], [type[]]@([IntPtr],[int],[IntPtr],[uint32])),
        @('CloseHandle', [bool], [type[]]@([IntPtr])))
    foreach ($signature in $signatures) {
        $method = $type.DefineMethod($signature[0],
            [Reflection.MethodAttributes]'Public,Static,PinvokeImpl',
            [Reflection.CallingConventions]::Standard, $signature[1], $signature[2])
        $attribute = [Reflection.Emit.CustomAttributeBuilder]::new($constructor, [object[]]@($dll),
            $fields, [object[]]@($signature[0],$true,$true,[Runtime.InteropServices.CharSet]::Unicode))
        $method.SetCustomAttribute($attribute)
        $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    }
    $script:CleanupNative = $type.CreateType()
}
function Native-Call([string]$name, [object[]]$arguments) {
    return $script:CleanupNative.GetMethod($name).Invoke($null, $arguments)
}
function Native-Failure([string]$operation) {
    $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "$operation : $([ComponentModel.Win32Exception]::new($code).Message) (native error $code)"
}
function Native-Identity([IntPtr]$handle, [bool]$directory) {
    $data = [Runtime.InteropServices.Marshal]::AllocHGlobal(52)
    try {
        if (-not (Native-Call 'GetFileInformationByHandle' @($handle,$data))) { Native-Failure 'read private object type' }
        $attributes = [Runtime.InteropServices.Marshal]::ReadInt32($data)
        $isDirectory = ($attributes -band 16) -ne 0
        if (($attributes -band 1024) -ne 0 -or $isDirectory -ne $directory -or
            (-not $directory -and [Runtime.InteropServices.Marshal]::ReadInt32($data,40) -ne 1)) {
            throw 'private cleanup requires an original no-reparse object without extra links'
        }
        if (-not (Native-Call 'GetFileInformationByHandleEx' @($handle,18,$data,[uint32]24))) {
            Native-Failure 'read private object identity'
        }
        $bytes = New-Object byte[] 24
        [Runtime.InteropServices.Marshal]::Copy($data,$bytes,0,24)
        return ([BitConverter]::ToUInt64($bytes,0).ToString('x16') + ':' +
            [BitConverter]::ToString($bytes,8,16).Replace('-','').ToLowerInvariant())
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($data) }
}
function Native-Unlink([IntPtr]$handle) {
    # Reopen the inherited exact object, never a pathname selected by a reply.
    $raw = Native-Call 'ReOpenFile' @($handle,[uint32]0x10080,[uint32]5,[uint32]0x200000)
    if ($raw -eq [IntPtr]::new(-1)) { Native-Failure 'reopen private cleanup object' }
    try { Native-Disposition $raw }
    finally { if (-not (Native-Call 'CloseHandle' @($raw))) { Native-Failure 'close private delete handle' } }
}
function Native-Disposition([IntPtr]$handle) {
    $disposition = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
    try {
        # DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE, not force-image.
        [Runtime.InteropServices.Marshal]::WriteInt32($disposition,19)
        if (-not (Native-Call 'SetFileInformationByHandle' @($handle,21,$disposition,[uint32]4))) {
            Native-Failure 'unlink private cleanup object'
        }
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($disposition) }
}
function Retire-Pin($raw, [string]$path) {
    # The parent verified the newly created ID, bytes and private metadata before
    # duplicating this immutable read pin. No path is reopened for file deletion.
    $safe = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr][long]$raw,$true)
    try { Native-Unlink $safe.DangerousGetHandle() }
    finally { $safe.Dispose() }
    if (-not (Absent $path)) { throw "private object name remains: $path" }
}
function Retire-Directory([string]$path, [string]$identity) {
    if (Absent $path) { return }
    $raw = Native-Call 'CreateFileW' @($path,[uint32]0x10080,[uint32]7,[IntPtr]::Zero,
        [uint32]3,[uint32]0x02200000,[IntPtr]::Zero)
    if ($raw -eq [IntPtr]::new(-1)) { Native-Failure 'open private cleanup directory' }
    try {
        if ((Native-Identity $raw $true) -cne $identity) { throw "private directory replaced; preserved: $path" }
        Native-Disposition $raw
    } finally { if (-not (Native-Call 'CloseHandle' @($raw))) { Native-Failure 'close private directory' } }
    if (-not (Absent $path)) { throw "private directory name remains: $path" }
}
