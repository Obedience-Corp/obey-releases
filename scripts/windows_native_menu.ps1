# Click only the exact native menu owned by the previously verified App identity.
param([long]$Window, [int]$OwnerPid)
$ErrorActionPreference = 'Stop'
if ($env:CANDIDATE_NATIVE_DISPOSABLE -ne '1' -or $env:CANDIDATE_RUNNER_KIND -ne 'github-hosted') {
    throw 'Native menu interaction requires a disposable hosted runner'
}
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class OwnedNativeMenu {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left,Top,Right,Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct Point { public int X,Y; }
    [StructLayout(LayoutKind.Sequential)] public struct MouseInput { public int X,Y; public uint Data,Flags,Time; public UIntPtr Extra; }
    [StructLayout(LayoutKind.Explicit)] public struct InputUnion { [FieldOffset(0)] public MouseInput Mouse; }
    [StructLayout(LayoutKind.Sequential)] public struct Input { public uint Type; public InputUnion Value; }
    [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr window);
    [DllImport("user32.dll")] public static extern IntPtr GetSubMenu(IntPtr menu,int index);
    [DllImport("user32.dll")] public static extern int GetMenuItemCount(IntPtr menu);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetMenuString(IntPtr menu,uint item,StringBuilder text,int size,uint flags);
    [DllImport("user32.dll")] public static extern uint GetMenuState(IntPtr menu,uint item,uint flags);
    [DllImport("user32.dll")] public static extern bool GetMenuItemRect(IntPtr window,IntPtr menu,uint item,out Rect rect);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr window,out Rect rect);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(Point point);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out Point point);
    [DllImport("user32.dll",SetLastError=true)] static extern uint SendInput(uint count,Input[] inputs,int size);
    public static string Label(IntPtr menu,int index) {
        var text=new StringBuilder(512); GetMenuString(menu,(uint)index,text,text.Capacity,0x400);
        return text.ToString().Replace("&", "").Split('\t')[0].Trim();
    }
    public static void Click(Point point,uint pid) {
        uint actual; GetWindowThreadProcessId(WindowFromPoint(point),out actual);
        if(actual!=pid) throw new Exception("Native menu point is obscured or not owned");
        if(!SetCursorPos(point.X,point.Y)) throw new Exception("Cannot position pointer on owned menu");
        var inputs=new Input[2]; inputs[0].Value.Mouse.Flags=2; inputs[1].Value.Mouse.Flags=4;
        if(SendInput(2,inputs,Marshal.SizeOf(typeof(Input)))!=2) throw new Exception("Owned menu click was not delivered");
    }
}
'@
function AssertOwner {
    $owned = Get-Process -Id $OwnerPid -ErrorAction Stop
    if ($owned.Path -ne $env:APP_UPGRADE_EXE -or $owned.StartTime.ToUniversalTime().Ticks.ToString() -ne $env:APP_UPGRADE_STARTED -or $owned.MainWindowHandle.ToInt64() -ne $Window) {
        throw 'Native menu App identity changed before input'
    }
}
function NativeStage($stage, $data) {
    if ($env:APP_UPGRADE_MENU_DIAGNOSTICS) {
        [IO.File]::AppendAllText($env:APP_UPGRADE_MENU_DIAGNOSTICS, ((@{stage=$stage; utc=[DateTime]::UtcNow.ToString('o'); owner_pid=$OwnerPid; window=$Window; data=$data} | ConvertTo-Json -Depth 6 -Compress) + "`n"))
    }
}
$handle = [IntPtr]$Window
$actual = [uint32]0
[void][OwnedNativeMenu]::GetWindowThreadProcessId($handle,[ref]$actual)
if ($actual -ne $OwnerPid) { throw 'Native menu window is not owned' }
$menu = [OwnedNativeMenu]::GetMenu($handle)
if ($menu -eq [IntPtr]::Zero) { return @{native_menu=$false; invoked=$false} }
function FindExact($handle, $label) {
    $count = [OwnedNativeMenu]::GetMenuItemCount($handle)
    if ($count -lt 0 -or $count -gt 100) { throw 'Invalid owned native menu size' }
    $labels = @(); $matches = @()
    for ($i=0; $i -lt $count; $i++) {
        $text = [OwnedNativeMenu]::Label($handle,$i); $labels += $text
        if ($text -ceq $label) { $matches += $i }
    }
    if ($matches.Count -ne 1) { throw "Exact native menu '$label' missing/ambiguous: $($labels -join ', ')" }
    $state = [OwnedNativeMenu]::GetMenuState($handle,$matches[0],0x400)
    if ($state -eq [uint32]::MaxValue -or ($state -band 3)) { throw "Owned native menu '$label' is disabled" }
    return @{index=$matches[0]; labels=$labels}
}
NativeStage 'native-menu-found' @{}
$top = FindExact $menu 'App'
$submenu = [OwnedNativeMenu]::GetSubMenu($menu,$top.index)
if ($submenu -eq [IntPtr]::Zero) { throw 'Owned App submenu missing' }
$action = FindExact $submenu 'Check for app updates'
NativeStage 'exact-labels' @{top=$top; action=$action}
$rect = [OwnedNativeMenu+Rect]::new(); $frame = [OwnedNativeMenu+Rect]::new()
if (-not [OwnedNativeMenu]::GetMenuItemRect($handle,$menu,$top.index,[ref]$rect) -or
    -not [OwnedNativeMenu]::GetWindowRect($handle,[ref]$frame) -or
    $rect.Right -le $rect.Left -or $rect.Bottom -le $rect.Top -or
    $rect.Left -lt $frame.Left -or $rect.Top -lt $frame.Top -or $rect.Right -gt $frame.Right -or $rect.Bottom -gt $frame.Bottom) {
    throw 'Owned native menu rectangle invalid/outside App'
}
$cursor = [OwnedNativeMenu+Point]::new()
if (-not [OwnedNativeMenu]::GetCursorPos([ref]$cursor)) { throw 'Cannot retain pointer position' }
try {
    [void][OwnedNativeMenu]::SetForegroundWindow($handle)
    if ([OwnedNativeMenu]::GetForegroundWindow() -ne $handle) { throw 'Owned App did not become foreground for menu click' }
    $point = [OwnedNativeMenu+Point]::new(); $point.X=($rect.Left+$rect.Right)/2; $point.Y=($rect.Top+$rect.Bottom)/2
    AssertOwner
    NativeStage 'click-owned-app-menu' @{x=$point.X;y=$point.Y}
    [OwnedNativeMenu]::Click($point,$OwnerPid)
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $valid = [OwnedNativeMenu]::GetMenuItemRect([IntPtr]::Zero,$submenu,$action.index,[ref]$rect)
        if ($valid -and $rect.Right -gt $rect.Left -and $rect.Bottom -gt $rect.Top) { break }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $valid -or $rect.Right -le $rect.Left -or $rect.Bottom -le $rect.Top) { throw 'Owned native popup rectangle unavailable' }
    $actual = [uint32]0; [void][OwnedNativeMenu]::GetWindowThreadProcessId($handle,[ref]$actual)
    if ($actual -ne $OwnerPid -or [OwnedNativeMenu]::GetForegroundWindow() -ne $handle) { throw 'Native menu ownership/focus changed' }
    $point.X=($rect.Left+$rect.Right)/2; $point.Y=($rect.Top+$rect.Bottom)/2
    AssertOwner
    NativeStage 'click-owned-update-action' @{x=$point.X;y=$point.Y}
    [OwnedNativeMenu]::Click($point,$OwnerPid)
    return @{native_menu=$true; invoked=$true; method='owned Win32 menu bounds + SendInput'; root_pid=$OwnerPid;
        menu_path=@('App','Check for app updates'); top_labels=$top.labels; action_labels=$action.labels}
} finally { [void][OwnedNativeMenu]::SetCursorPos($cursor.X,$cursor.Y) }
