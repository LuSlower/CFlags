# Check administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell "-File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Console {
    param ([Switch]$Show, [Switch]$Hide)
    if (-not ("Console.Window" -as [type])) { 
        Add-Type -Name Window -Namespace Console -MemberDefinition '
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
        '
    }

    if ($Show) {
        $consolePtr = [Console.Window]::GetConsoleWindow()
        $null = [Console.Window]::ShowWindow($consolePtr, 5)
    }

    if ($Hide) {
        $consolePtr = [Console.Window]::GetConsoleWindow()
        $null = [Console.Window]::ShowWindow($consolePtr, 0)
    }
}

$flags = @(
    @{Name = "DisableDxMaximizedWindowedMode"; Description = "Disable Fullscreen Optimizations (FSO)."; Abbreviation = "DDXMW"}
    @{Name = "HighDpiAware"; Description = "High DPI Awareness for Application."; Abbreviation = "HDAWR"}
    @{Name = "DpiUnaware"; Description = "System DPI Unaware."; Abbreviation = "DUNWR"}
    @{Name = "GdiDpiScaling DpiUnaware"; Description = "GDI DPI Scaling for DPI Unaware System Enhancement."; Abbreviation = "GDSCE"}
    @{Name = "PerProcessSystemDpiForceOff"; Description = "Disables Per Process System DPI for Windows."; Abbreviation = "PPSFO"}
    @{Name = "PerProcessSystemDpiForceOn"; Description = "Enables Per Process System DPI for Program."; Abbreviation = "PPSFN"}
    @{Name = "Bit16Color"; Description = "16-bit color mode."; Abbreviation = "B16CL"}
    @{Name = "256Color"; Description = "8-bit color mode."; Abbreviation = "B08CL"}
    @{Name = "640x480"; Description = "640x480 screen resolution mode."; Abbreviation = "R6480"}
    @{Name = "8And16BitAggregateBlts"; Description = "8/16-bit mitigation can cause performance issues in applications. `nThis layer aggregates all the blt operations and improves performance."; Abbreviation = "8AGB" }
    @{Name ="8And16BitDXMaxWinMode"; Description = "The 8/16-bit mitigation runs applications that use DX8/9 in a maximized windowed mode. `nThis layer mitigates applications that exhibit graphical corruption in full screen mode."; Abbreviation = "8DXM" }
    @{Name ="8And16BitGDIRedraw"; Description = "This fix repairs applications that use GDI and that work in 8-bit color mode. `nThe application is forced to repaint its window on RealizePalette."; Abbreviation = "8GDR" }
    @{Name ="AccelGdipFlush"; Description = "This fix increases the speed of GdipFlush, which has perf issues in DWM."; Abbreviation = "AGF" }
    @{Name ="AoaMp4Converter"; Description = "This fix resolves a display issue for the AoA Mp4 Converter."; Abbreviation = "AOMC" }
    @{Name ="BIOSRead"; Description = "The fix enables OEM executable (.exe) files to use the GetSystemFirmwareTable function instead of the NtOpenSection function`nwhen the BIOS is queried for the \\Device\\Physical memory information."; Abbreviation = "BIOS" }
    @{Name ="BlockRunasInteractiveUser"; Description = "The fix blocks InstallShield from setting the value of RunAs registry keys to InteractiveUser Because InteractiveUser no longer has Administrator rights."; Abbreviation = "BRIU" }
    @{Name ="ChangeFolderPathToXPStyle"; Description = "The fix intercepts the SHGetFolderpath request to the common appdata file path `nand returns the Windows® XP-style file path instead of the Windows Vista-style file path."; Abbreviation = "CFXP" }
    @{Name ="ClearLastErrorStatusonIntializeCriticalSection"; Description = "The fix modifies the InitializeCriticalSection function call so that it checks the NTSTATUS error code, and then sets the last error to ERROR_SUCCESS."; Abbreviation = "CLEC" }
    @{Name ="CopyHKCUSettingsFromOtherUsers"; Description = "The fix scans the existing user profiles and tries to copy the specified keys into the HKEY_CURRENT_USER registry area."; Abbreviation = "CHKCU" }
    @{Name ="CorrectCreateBrushIndirectHatch"; Description = "The fix corrects the brush style hatch value, which is passed to the CreateBrushIndirect() function and enables the information to be correctly interpreted."; Abbreviation = "CCBI" }
    @{Name ="CorrectFilePaths"; Description = "The fix modifies the file path names to point to a new location on the hard disk."; Abbreviation = "CFP" }
    @{Name ="CorrectFilePathsUninstall"; Description = "The fix corrects the file paths that are used by the uninstallation process of an application."; Abbreviation = "CFPU" }
    @{Name ="CorrectShellExecuteHWND"; Description = "The fix intercepts the ShellExecute(Ex) calls, and then inspects the HWND value.`nIf the value is invalid, this fix enables the call to use the currently active HWND value."; Abbreviation = "CSEH" }
    @{Name ="CustomNCRender"; Description = "This fix instructs DWM to not render the non-client area forcing the application to do its own NC rendering."; Abbreviation = "CNR" }
    @{Name ="DelayApplyFlag"; Description = "This fix applies a KERNEL, USER, or PROCESS flag if the specified DLL is loaded."; Abbreviation = "DAF" }
    @{Name ="DeprecatedServiceShim"; Description = "The fix intercepts the CreateService function calls and removes the deprecated dependency service from the lpDependencies parameter."; Abbreviation = "DSS" }
    @{Name ="DirectXVersionLie"; Description = "The fix modifies the DXDIAGN GetProp function call to return the correct DirectX version."; Abbreviation = "DXVL" }
    @{Name ="DetectorDWM8And16Bit"; Description = "The fix offers mitigation for applications that work in 8/16-bit display color mode."; Abbreviation = "DD8B" }
    @{Name ="Disable8And16BitD3D"; Description = "This fix improves performance of 8/16-bit color applications that render using D3D."; Abbreviation = "D8D" }
    @{Name ="Disable8And16BitModes"; Description = "This fix disables 8/16-bit color mitigation and enumeration of 8/16-bit color modes."; Abbreviation = "D8M" }
    @{Name ="DisableDWM"; Description = "The fix temporarily disables the Windows Aero menu theme functionality for unsupported applications."; Abbreviation = "DDWM" }
    @{Name ="DisableFadeAnimations"; Description = "The fix disables the fade animations functionality for unsupported applications."; Abbreviation = "DFA" }
    @{Name ="DisableThemeMenus"; Description = "The fix temporarily disables the Windows Aero menu theme functionality for unsupported applications."; Abbreviation = "DTM" }
    @{Name ="DisableWindowsDefender"; Description = "The fix disables Windows Defender for security applications that don't work with Windows Defender."; Abbreviation = "DWD" }
    @{Name ="DWM8And16BitMitigation"; Description = "The fix offers mitigation for applications that work in 8/16-bit display color mode."; Abbreviation = "DWM8" }
    @{Name ="DXGICompat"; Description = "The fix allows application-specific compatibility instructions to be passed to the DirectX engine."; Abbreviation = "DXGI" }
    @{Name ="DXMaximizedWindowedMode"; Description = "Applications that use DX8/9 are run in a maximized windowed mode."; Abbreviation = "DXMW" }
    @{Name ="ElevateCreateProcess"; Description = "The fix handles the error code and attempts to recall the CreateProcess function together with requested elevation."; Abbreviation = "ECP" }
    @{Name ="EmulateOldPathIsUNC"; Description = "The fix exchanges the PathIsUNC function to return a value of True for UNC paths in Windows."; Abbreviation = "EOP" }
    @{Name ="EmulateGetDiskFreeSpace"; Description = "The fix determines the amount of free space and returns a value of 2 GB if the amount of free space is larger than 2 GB."; Abbreviation = "EGDS" }
    @{Name ="EmulateSorting"; Description = "The fix forces applications that use the CompareStringW/LCMapString sorting table to use an older version of the table."; Abbreviation = "ES" }
    @{Name ="EmulateSortingWindows61"; Description = "The fix emulates the sorting order of Windows 7 and Windows Server 2008 R2 for various APIs."; Abbreviation = "ESW" }
    @{Name ="EnableRestarts"; Description = "The fix enables the computer to restart and finish the installation process by verifying and enabling the SeShutdownPrivilege service privilege exists."; Abbreviation = "ER" }
    @{Name ="ExtraAddRefDesktopFolder"; Description = "Invokes AddRef() on the Desktop folder to prevent premature destruction of an object due to excessive Release() calls."; Abbreviation = "EAD" }
    @{Name ="FailObsoleteShellAPIs"; Description = "Implements or stubs obsolete APIs to prevent application failures caused by deprecated calls."; Abbreviation = "FOSA" }
    @{Name ="FailRemoveDirectory"; Description = "Fails RemoveDirectory() calls with a specified path to ensure proper folder deletion during uninstallation."; Abbreviation = "FRD" }
    @{Name ="FakeLunaTheme"; Description = "Intercepts GetCurrentThemeName API to return the Windows XP default Luna theme for better display."; Abbreviation = "FLT" }
    @{Name ="FlushFile"; Description = "Enables WriteFile function to call FlushFileBuffers to ensure file changes appear on disk immediately."; Abbreviation = "FF" }
    @{Name ="FontMigration"; Description = "Replaces an application-requested font with a better selection to avoid text truncation."; Abbreviation = "FM" }
    @{Name ="ForceAdminAccess"; Description = "Temporarily imitates being an Administrator to resolve failures during explicit admin checks."; Abbreviation = "FAA" }
    @{Name ="ForceInvalidateOnClose"; Description = "Invalidates windows under a closing or hiding window to ensure proper rendering."; Abbreviation = "FIC" }
    @{Name ="ForceLoadMirrorDrvMitigation"; Description = "Loads the Windows 8-mirror driver mitigation where it's not automatically applied."; Abbreviation = "FLDM" }
    @{Name ="FreestyleBMX"; Description = "Resolves race conditions related to window message order in applications."; Abbreviation = "FBMX" }
    @{Name ="GetDriveTypeWHook"; Description = "Modifies GetDriveType() to only return root information for incomplete or malformed file paths."; Abbreviation = "GDTW" }
    @{Name ="GlobalMemoryStatusLie"; Description = "Modifies memory status structure to report a fixed swap file size to avoid memory full errors."; Abbreviation = "GMSL" }
    @{Name ="HandleBadPtr"; Description = "Supports pointer validation to avoid access violation errors due to API pointer checks."; Abbreviation = "HBP" }
    @{Name ="HandleMarkedContentNotIndexed"; Description = "Resets FILE_ATTRIBUTE_NOT_CONTENT_INDEXED attribute to original state for files in %TEMP% directory."; Abbreviation = "HMCI" }
    @{Name ="HeapClearAllocation"; Description = "Clears heap allocation with zeros to prevent unexpected shutdowns during allocation."; Abbreviation = "HCA" }
    @{Name ="IgnoreAltTab"; Description = "Prevents WM_INPUT messages delivery by intercepting RegisterRawInputDevices API to ignore special key combinations."; Abbreviation = "IAT" }
    @{Name ="IgnoreChromeSandbox"; Description = "Allows Google Chrome to run with ntdll loaded above 4 GB."; Abbreviation = "ICS" }
    @{Name ="IgnoreDirectoryJunction"; Description = "Prevents directory junctions from being returned by various file-related APIs."; Abbreviation = "IDJ" }
    @{Name ="IgnoreException"; Description = "Ignores specified exceptions to prevent immediate application failures."; Abbreviation = "IE" }
    @{Name ="IgnoreFloatingPointRoundingControl"; Description = "Ignores rounding control requests to support applications relying on old behavior."; Abbreviation = "IFPRC" }
    @{Name ="IgnoreFontQuality"; Description = "Enables color-keyed fonts to work properly with anti-aliasing to avoid text distortion."; Abbreviation = "IFQ" }
    @{Name ="IgnoreMessageBox"; Description = "Intercepts and skips MessageBox APIs to avoid displaying debugging or extraneous content."; Abbreviation = "IMB" }
    @{Name ="IgnoreMSOXMLMF"; Description = "Ignores the registered MSOXMLMF.DLL object to prevent errors related to missing MSVCR80D.DLL."; Abbreviation = "IMF" }
    @{Name ="IgnoreSetROP2"; Description = "Ignores read-modify-write operations on the desktop to avoid performance issues."; Abbreviation = "ISROP2" }
    @{Name ="InstallComponent"; Description = "Prompts to install .NET 3.5 or .NET 2.0 when not included with Windows 8."; Abbreviation = "IC" }
    @{Name ="LoadLibraryRedirect"; Description = "Forces loading of system library versions instead of application-supplied redistributables."; Abbreviation = "LLR" }
    @{Name ="LocalMappedObject"; Description = "Replaces 'Global' with 'Local' in object creation to resolve global namespace issues."; Abbreviation = "LMO" }
    @{Name ="MakeShortcutRunas"; Description = "Forces RunDLL.exe-based uninstallers to run with different credentials for successful uninstallation."; Abbreviation = "MSR" }
    @{Name ="ManageLinks"; Description = "Converts symbolic or directory junctions to standard paths before passing to APIs."; Abbreviation = "ML" }
    @{Name ="MirrorDriverWithComposition"; Description = "Allows mirror drivers to work properly with desktop composition."; Abbreviation = "MDWC" }
    @{Name ="MoveToCopyFileShim"; Description = "Forces CopyFile APIs to avoid security access issues during setup by not moving security descriptors."; Abbreviation = "MTCF" }
    @{Name ="OpenDirectoryAcl"; Description = "Reduces security privilege levels on specified files and folders to resolve access errors."; Abbreviation = "ODA" }
    @{Name ="PopCapGamesForceResPerf"; Description = "Resolves performance issues in PopCap games at certain resolutions by scaling buffers."; Abbreviation = "PCG" }
    @{Name ="PreInstallDriver"; Description = "Preinstalls drivers for applications that install or start drivers during initial startup."; Abbreviation = "PID" }
    @{Name ="PreInstallSmarteSECURE"; Description = "Preinstalls CLSIDs for SmartSECURE applications to avoid installation during initial startup."; Abbreviation = "PISS" }
    @{Name ="ProcessPerfData"; Description = "Handles registry key failure to prevent Unhandled Exception errors when checking if another instance of an application is running."; Abbreviation = "PPD" }
    @{Name ="PromoteDAM"; Description = "Registers applications for power state change notifications."; Abbreviation = "PAD" }
    @{Name ="PropagateProcessHistory"; Description = "Sets _PROCESS_HISTORY environment variable to aid child processes in finding application fixes."; Abbreviation = "PPH" }
    @{Name ="ProtectedAdminCheck"; Description = "Addresses issues with non-standard admin checks by fixing false positives for Protected Administrators."; Abbreviation = "PAC" }
    @{Name ="RedirectCRTTempFile"; Description = "Redirects failing CRT calls creating temporary files at the root to the user's temp directory."; Abbreviation = "RCTF" }
    @{Name ="RedirectHKCUKeys"; Description = "Duplicates newly created HKCU keys to other users' accounts to overcome UAC restrictions."; Abbreviation = "RHKCU" }
    @{Name ="RedirectMP3Codec"; Description = "Redirects CoCreateInstance calls for missing MP3 filters to supported versions."; Abbreviation = "RM3C" }
    @{Name ="RedirectShortcut"; Description = "Redirects shortcuts to a specified path to resolve UAC-related access issues."; Abbreviation = "RS" }
    @{Name ="RelaunchElevated"; Description = "Allows child .exe files to run with elevated privileges when parent process is unknown."; Abbreviation = "RE" }
    @{Name ="RetryOpenSCManagerWithReadAccess"; Description = "Retries SCM access with restricted rights if an Access Denied error occurs."; Abbreviation = "ROSCMRA" }
    @{Name ="RetryOpenServiceWithReadAccess"; Description = "The problem occurs when an Unable to open service due to your application using the OpenService() API to test for the existence of a particular service error message displays.`nThe fix retries the OpenService() API call and verifies that the user has Administrator rights, isn't a Protected Administrator, and by using read-only access. Applications can test for the existence of a service by calling the OpenService() API but some applications ask for all access when making this check. This fix retries the call but only asking for read-only access. The user needs to be an administrator for this fix to work."; Abbreviation = "ROSCRA" }
    @{Name ="RunAsAdmin"; Description = "The problem occurs when an application fails to function by using the Standard User or Protected Administrator account. The fix enables the application to run by using elevated privileges.`nThe fix is the equivalent of specifying requireAdministrator in an application manifest."; Abbreviation = "RA" }
    @{Name ="RunAsHighest"; Description = "The problem occurs when administrators can't view the read/write version of an application that presents a read-only view to standard users.`nThe fix enables the application to run by using the highest available permissions.`nThis fix is the equivalent of specifying highestAvailable in an application manifest."; Abbreviation = "RAH" }
    @{Name ="RunAsInvoker"; Description = "The problem occurs when an application isn't detected as requiring elevation. The fix enables the application to run by using the privileges that are associated with the creation process,`nwithout requiring elevation. This fix is the equivalent of specifying asInvoker in an application manifest."; Abbreviation = "RAI" }
    @{Name ="SecuROM7"; Description = "The fix repairs applications by using SecuROM7 for copy protection."; Abbreviation = "SR7" }
    @{Name ="SessionShim"; Description = "The fix intercepts API calls from applications that are trying to interact with services that are running in another session,`nby using the terminal service name prefix (Global or Local) as the parameter. At the command prompt, you can supply a list of objects to modify, separating the values by a double backslash ().`nOr, you can choose not to include any parameters, so that all of the objects are modified. Important: Users can't sign in as Session 0 (Global Session) in Windows Vista and later.`nTherefore, applications that require access to Session 0 automatically fail."; Abbreviation = "SS" }
    @{Name ="SetProtocolHandler"; Description = "The fix registers an application as a protocol handler. You can control this fix further by typing the following command at the command prompt:Client;Protocol;App Where the Client is the name of the email protocol,`nProtocol is mailto, and App is the name of the application. Note: Only the mail client and the mailto protocol are supported. You can separate multiple clients by using a backslash ()."; Abbreviation = "SPH" }
    @{Name ="SetupCommitFileQueueIgnoreWow"; Description = "The problem occurs when a 32-bit setup program fails to install because it requires 64-bit drivers. The fix disables the Wow64 file system that is used by the 64-bit editions of Windows, to prevent 32-bit applications from accessing 64-bit file systems during the application setup."; Abbreviation = "SCFIW" }
    @{Name ="SharePointDesigner2007"; Description = "The fix resolves an application bug that severely slows the application when it runs in DWM."; Abbreviation = "SPD2007" }
    @{Name ="ShimViaEAT"; Description = "The problem occurs when an application fails, even after applying a compatibility fix that is known to fix an issue. Applications that use unicows.dll or copy protection often present this issue. The fix applies the specified compatibility fixes by modifying the export table and by nullifying the use of module inclusion and exclusion."; Abbreviation = "SVE" }
    @{Name ="ShowWindowIE"; Description = "The problem occurs when a web application experiences navigation and display issues because of the tabbing feature.`nThe fix intercepts the ShowWindow API call to address the issues that can occur when a web application determines that it is in a child window. This fix calls the real ShowWindow API on the top-level parent window."; Abbreviation = "SWIE" }
    @{Name ="SierraWirelessHideCDROM"; Description = "The fix repairs the Sierra Wireless Driver installation preventing bugcheck."; Abbreviation = "SWHCD" }
    @{Name ="Sonique2"; Description = "The application uses an invalid window style, which breaks in DWM. This fix replaces the window style with a valid value."; Abbreviation = "S2" }
    @{Name ="SpecificInstaller"; Description = "The problem occurs when the GenericInstaller function fails to pick up an application installation file. The fix flags the application as being an installer file (for example, setup.exe), and then prompts for elevation. Note: For more detailed information about this application fix, see Using the SpecificInstaller Fix."; Abbreviation = "SI" }
    @{Name ="SpecificNonInstaller"; Description = "The problem occurs when an application that isn't an installer (and has sufficient privileges) generates a false positive from the GenericInstaller function. The fix flags the application to exclude it from detection by the GenericInstaller function. Note: For more detailed information about this application fix, see Using the SpecificNonInstaller Fix."; Abbreviation = "SNI" }
    @{Name ="SystemMetricsLie"; Description = "The fix replaces SystemMetrics values and SystemParametersInfo values with the values of previous Windows versions."; Abbreviation = "SML" }
    @{Name ="TextArt"; Description = "The application receives different mouse coordinates with DWM ON versus DWM OFF, which causes the application to hang. This fix resolves the issue."; Abbreviation = "TA" }
    @{Name ="TrimDisplayDeviceNames"; Description = "The fix trims the names returned by the EnumDisplayDevices API of the display devices."; Abbreviation = "TDDN" }
    @{Name ="UIPICompatLogging"; Description = "The fix enables the logging of Windows messages from Internet Explorer and other processes."; Abbreviation = "UCL" }
    @{Name ="UIPIEnableCustomMsgs"; Description = "The problem occurs when an application doesn't properly communicate with other processes because customized Windows messages aren't delivered.`nThe fix enables customized Windows messages to pass through to the current process from a lower Desktop integrity level.`nThis fix is the equivalent of calling the RegisterWindowMessage function, followed by the ChangeWindowMessageFilter function in the code."; Abbreviation = "UECM" }
    @{Name ="UIPIEnableStandardMsgs"; Description = "The problem occurs when an application doesn't communicate properly with other processes because standard Windows messages aren't delivered.`nThe fix enables standard Windows messages to pass through to the current process from a lower Desktop integrity level.`nThis fix is the equivalent of calling the ChangeWindowMessageFilter function in the code."; Abbreviation = "UESM" }
    @{Name ="VirtualizeDeleteFileLayer"; Description = "The fix virtualizes DeleteFile operations for applications that try to delete protected files."; Abbreviation = "VDFL" }
    @{Name ="VirtualizeDesktopPainting"; Description = "This fix improves the performance of several operations on the Desktop DC while using DWM."; Abbreviation = "VDP" }
    @{Name ="VirtualRegistry"; Description = "The problem is indicated when a Component failed to be located error message displays when an application is started.`nThe fix enables the registry functions to allow for virtualization, redirection, expansion values, version spoofing, the simulation of performance data counters, and so on."; Abbreviation = "VR" }
    @{Name ="VirtualizeDeleteFile"; Description = "The problem occurs when several error messages display and the application can't delete files. The fix makes the application's DeleteFile function call a virtual call to remedy the UAC and file virtualization issues that were introduced with Windows Vista.`nThis fix also links other file APIs (for example, GetFileAttributes) to ensure that the virtualization of the file is deleted."; Abbreviation = "VDF" }
    @{Name ="VirtualizeHKCRLite"; Description = "The problem occurs when an application fails to register COM components at runtime. The fix redirects the HKCR write calls (HKLM) to the HKCU hive for a per-user COM registration.`nThis fix operates much like the VirtualizeRegistry fix when you use the VirtualizeHKCR parameter; however, VirtualizeHKCRLite provides better performance."; Abbreviation = "VHKCRL" }
    @{Name ="VirtualizeRegisterTypeLib"; Description = "The fix when used with the VirtualizeHKCRLite fix, ensures that the type library and the COM class registration happen simultaneously.`nThis fix functions much like the RegistryTypeLib fix when the RegisterTypeLibForUser parameter is used."; Abbreviation = "VRTL" }
    @{Name ="WaveOutIgnoreBadFormat"; Description = "When this problem occurs when an Unable to initialize sound device from your audio driver error occurs; the application then closes.`nThe fix enables the application to ignore the format error and continue to function properly."; Abbreviation = "WIBF" }
    @{Name ="WerDisableReportException"; Description = "The fix prevents an application from reporting the exception to the Windows Error Reporting (WER) service."; Abbreviation = "WDR" }
)



$cfPath = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\"

function Load-Processes-CF {
    $listBoxProcesses.Items.Clear()
        
    $keys = (Get-ItemProperty -Path $cfPath | Select-Object * -ExcludeProperty PS*).PSObject.Properties

    foreach ($key in $keys) {
        # Obtener el nombre del proceso y su bandera
        $processPath = $key.Name

        $processName = [System.IO.Path]::GetFileName($processPath)

        $listBoxProcesses.Items.Add($processName)
    }
}

function Set-CF {
    param (
        [Parameter(Mandatory=$true)]
        [String]$processName
    )

    # Crear una cadena de flags
    $flagsToSet = @()

    foreach ($entry in $checkboxesFlags) {
        $checkbox = $entry.CheckBox
        $option = $entry.Option

        if ($checkbox.Checked) {
            $flagsToSet += $option.Name.ToUpper()
        }
    }

    # Crear la cadena final para el registro
    $flagsString = "~ " + ($flagsToSet -join " ")

    # Obtener todas las propiedades del registro
    $keys = (Get-ItemProperty -Path $cfPath | Select-Object * -ExcludeProperty PS*).PSObject.Properties

    $found = $false

    foreach ($key in $keys) {
        $processPath = $key.Name
        if ($processPath -match '\\([^\\]+)$') {
            $extractedProcessName = $matches[1]
            
            # Comparar el nombre del proceso extraído
            if ($extractedProcessName -ieq $processName) {
                $found = $true

                if ($flagsToSet.Count -eq 0) {
                    # Si no hay flags seleccionadas, eliminar el valor del registro
                    Remove-ItemProperty -Path $cfPath -Name $processPath
                } else {
                    # Establecer el nuevo valor
                    Set-ItemProperty -Path $cfPath -Name $processPath -Value $flagsString
                }

                return # Salir de la función si el proceso ha sido encontrado y actualizado
            }
        }
    }

    # Si no se encuentra el proceso en el registro
    if (-not $found) {
        Write-Output "Process name '$processName' not found in registry."
    }
}

function Load-CF {
    param (
        [Parameter(Mandatory=$true)]
        [String]$processName
    )

    $keys = (Get-ItemProperty -Path $cfPath | Select-Object * -ExcludeProperty PS*).PSObject.Properties

    foreach ($entry in $checkboxesFlags) {
        $checkbox = $entry.CheckBox
        $option = $entry.Option

        # Limpiar todos los CheckBoxes antes de proceder
        $checkbox.Checked = $false

        foreach ($key in $keys) {
            $processPath = $key.Name
            if ($processPath -match '\\([^\\]+)$') {
                $extractedProcessName = $matches[1]
                
                # Comparar el nombre del proceso extraído
                if ($extractedProcessName -ieq $processName) {
                    # Obtener y formatear las flags
                    $flags = $key.Value -replace '^~\s*', ''
                    $flagList = $flags -split '\s+' 
                    
                    # Comparar cada flag
                    foreach ($flag in $flagList) {
                        if ($flag -ieq $option.Name) {
                            $checkbox.Checked = $true
                        }
                    }
                }
            }
        }
    }
}

# Ocultar consola, crear form
Console -Hide
[System.Windows.Forms.Application]::EnableVisualStyles();
$form = New-Object System.Windows.Forms.Form
$form.ClientSize = New-Object System.Drawing.Size(880, 320)
$form.Text = "CFlags"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.KeyPreview = $true
$form.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::F5) {
        Load-Processes-cf
    }
})

$listBoxProcesses = New-Object System.Windows.Forms.ListBox
$listBoxProcesses.Location = New-Object System.Drawing.Point(10, 20)
$listBoxProcesses.Size = New-Object System.Drawing.Size(150, 270)
$form.Controls.Add($listBoxProcesses)
$listBoxProcesses.add_SelectedIndexChanged({
    # Obtener el proceso seleccionado
    $processName = $listBoxProcesses.SelectedItem
    if (-not [string]::IsNullOrEmpty($processName)){
        Load-CF -processName $processName
    }
})

$btnDel = New-Object System.Windows.Forms.Button
$btnDel.Location = New-Object System.Drawing.Point(20, 290)
$btnDel.Size = New-Object System.Drawing.Size(55, 20)
$btnDel.Text = "Delete"
$form.Controls.Add($btnDel)
$btnDel.Add_Click({
    $keys = (Get-ItemProperty -Path $cfPath | Select-Object * -ExcludeProperty PS*).PSObject.Properties
    $processName = $listBoxProcesses.SelectedItem
    if (-not [string]::IsNullOrEmpty($processName)){
        foreach ($key in $keys) {
            $processPath = $key.Name
            if ($processPath -match '\\([^\\]+)$') {
                $extractedProcessName = $matches[1]
                
                # Comparar el nombre del proceso extraído
                if ($extractedProcessName -ieq $processName) {
                    Remove-ItemProperty -Path $cfPath -Name $processPath   
                }
            }
        }
        Load-Processes-cf | Out-Null
    }
})

$btnReg = New-Object System.Windows.Forms.Button
$btnReg.Location = New-Object System.Drawing.Point(100, 290)
$btnReg.Size = New-Object System.Drawing.Size(55, 20)
$btnReg.Text = "Register"
$form.Controls.Add($btnReg)
$btnReg.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*"
    $openFileDialog.Title = "Select File"
    
    $result = $openFileDialog.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        # Obtener la ruta del archivo seleccionado
        $selectedFile = $openFileDialog.FileName
        $processPath = $selectedFile
        
        # Verificar si existe
        $keys = (Get-ItemProperty -Path $cfPath | Select-Object * -ExcludeProperty PS*).PSObject.Properties

        foreach ($key in $keys) {
        # Obtener el nombre del proceso y su bandera
            if ($processPath -eq $key.Name) {
                [System.Windows.Forms.MessageBox]::Show("The process is already registered", "Info", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                return
            }

        }
        Set-ItemProperty -Path $cfPath -Name $processPath -Value $null
        Load-Processes-cf
    }
})


Load-Processes-cf | Out-Null

# Configuración de posición inicial y dimensiones del área visible
$startX = 180
$startY = 10
$currentX = $startX
$currentY = $startY
$columnWidth = 90  # Ancho de la columna
$rowHeight = 20     # Espacio entre filas
$maxCheckboxesPerColumn = 15  # Número máximo de CheckBoxes por columna
$checkboxCount = 0  # Contador de CheckBoxes en la columna actual

$tooltip = New-Object System.Windows.Forms.ToolTip

$checkboxesFlags = @()

foreach ($flag in $flags) {
    # Crear CheckBox
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = $flag.Abbreviation
    $checkbox.Location = New-Object System.Drawing.Point($currentX, $currentY)
    $checkbox.Size = New-Object System.Drawing.Size(85, 20)  # Ajustar el tamaño del CheckBox
    $form.Controls.Add($checkbox)

    $checkboxesFlags += [PSCustomObject]@{ CheckBox = $checkbox; Option = $flag }

    # Añadir SymbolicName al ToolTip
    $tooltip.SetToolTip($checkbox, "$($flag.Name)`n`nDescription:`n$($flag.Description)")

    # Ajustar la posición para el próximo CheckBox
    $checkboxCount++
    $currentY += $rowHeight

    # Si se ha alcanzado el número máximo de CheckBoxes en la columna, mover a la siguiente columna
    if ($checkboxCount -ge $maxCheckboxesPerColumn) {
        $checkboxCount = 0
        $currentY = $startY
        $currentX += $columnWidth
    }
}

# SaveConfig
$buttonSave = New-Object System.Windows.Forms.Button
$buttonSave.Location = New-Object System.Drawing.Point(810, 290)
$buttonSave.Size = New-Object System.Drawing.Size(60, 20)
$buttonSave.Text = "Save"
$form.Controls.Add($buttonSave)

# aplicar todos los cambios
$buttonSave.Add_Click({
    $processName = $listBoxProcesses.SelectedItem
    if ([String]::IsNullOrEmpty($processName)) {
        [System.Windows.Forms.MessageBox]::Show("Select a process", "Info", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }

    Set-CF -processName $processName
})

$form.ShowDialog()