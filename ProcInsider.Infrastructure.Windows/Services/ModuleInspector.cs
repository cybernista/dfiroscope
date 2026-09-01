using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Inspects loaded modules/DLLs for a process.
/// Handles access denied and other errors gracefully.
/// </summary>
public class ModuleInspector
{
    // Cache for module hashes to avoid repeated computation
    private readonly Dictionary<string, string> _hashCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _cacheLock = new();

    /// <summary>
    /// Gets all loaded modules for a process.
    /// </summary>
    /// <param name="processId">The process ID to inspect.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of module info, or error message.</returns>
    public async Task<ModuleInspectionResult> GetModulesAsync(int processId, CancellationToken cancellationToken = default)
    {
        try
        {
            return await Task.Run(() => GetModulesInternal(processId, cancellationToken), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return new ModuleInspectionResult
            {
                Success = false,
                ErrorMessage = "Module inspection was canceled."
            };
        }
    }

    public async Task<ModuleInspectionResult> GetModulesAsync(Process process, CancellationToken cancellationToken = default)
    {
        try
        {
            return await Task.Run(() => GetModulesInternal(process, ownsProcess: false, cancellationToken), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return new ModuleInspectionResult
            {
                Success = false,
                ErrorMessage = "Module inspection was canceled."
            };
        }
    }

    private ModuleInspectionResult GetModulesInternal(int processId, CancellationToken cancellationToken)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return GetModulesInternal(process, ownsProcess: false, cancellationToken);
        }
        catch (ArgumentException)
        {
            return new ModuleInspectionResult
            {
                Success = false,
                ErrorMessage = "Process has exited and is no longer available for module inspection."
            };
        }
        catch (Exception ex)
        {
            return new ModuleInspectionResult
            {
                Success = false,
                ErrorMessage = $"Unable to access process: {ex.Message}"
            };
        }
    }

    private ModuleInspectionResult GetModulesInternal(Process process, bool ownsProcess, CancellationToken cancellationToken)
    {
        var modules = new List<ModuleInfo>();
        try
        {
            ProcessModuleCollection? processModules = null;
            try
            {
                processModules = process.Modules;
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                return new ModuleInspectionResult
                {
                    Success = false,
                    ErrorMessage = $"Unable to read modules for this process: {GetFriendlyError(ex)}"
                };
            }
            catch (InvalidOperationException)
            {
                return new ModuleInspectionResult
                {
                    Success = false,
                    ErrorMessage = "Process has exited and is no longer available for module inspection."
                };
            }

            if (processModules == null)
            {
                return new ModuleInspectionResult
                {
                    Success = false,
                    ErrorMessage = "Unable to enumerate modules for this process."
                };
            }

            foreach (ProcessModule module in processModules)
            {
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }
                catch (OperationCanceledException)
                {
                    // Return what we've collected so far when cancellation is requested
                    return new ModuleInspectionResult
                    {
                        Success = true,
                        Modules = modules
                    };
                }

                try
                {
                    var moduleInfo = new ModuleInfo
                    {
                        ModuleName = module.ModuleName ?? "<unknown>",
                        FullPath = module.FileName ?? "<not available>",
                        BaseAddress = $"0x{module.BaseAddress.ToInt64():X}",
                        ModuleMemorySize = module.ModuleMemorySize
                    };

                    // Get file version info
                    if (!string.IsNullOrEmpty(module.FileName) && File.Exists(module.FileName))
                    {
                        try
                        {
                            var versionInfo = module.FileVersionInfo;
                            moduleInfo.FileVersion = versionInfo.FileVersion ?? "<not available>";
                            moduleInfo.CompanyName = versionInfo.CompanyName ?? "<not available>";
                            moduleInfo.Description = versionInfo.FileDescription ?? "<not available>";
                        }
                        catch
                        {
                            moduleInfo.FileVersion = "<access denied>";
                            moduleInfo.CompanyName = "<access denied>";
                            moduleInfo.Description = "<access denied>";
                        }

                        // Get hash (cached)
                        moduleInfo.Sha256Hash = GetCachedHash(module.FileName);
                    }

                    modules.Add(moduleInfo);
                }
                catch
                {
                    // Skip modules we can't fully inspect
                    modules.Add(new ModuleInfo
                    {
                        ModuleName = module.ModuleName ?? "<unknown>",
                        FullPath = "<access denied>",
                        BaseAddress = "<access denied>"
                    });
                }
            }
        }
        finally
        {
            if (ownsProcess)
            {
                process.Dispose();
            }
        }

        return new ModuleInspectionResult
        {
            Success = true,
            Modules = modules
        };
    }

    /// <summary>
    /// Gets a cached SHA256 hash for a file path.
    /// </summary>
    private string GetCachedHash(string filePath)
    {
        lock (_cacheLock)
        {
            if (_hashCache.TryGetValue(filePath, out var cachedHash))
                return cachedHash;
        }

        string hash;
        try
        {
            using var stream = File.OpenRead(filePath);
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(stream);
            hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }
        catch
        {
            hash = "<access denied>";
        }

        lock (_cacheLock)
        {
            _hashCache[filePath] = hash;
        }

        return hash;
    }

    /// <summary>
    /// Gets a friendly error message for Win32 exceptions.
    /// </summary>
    private static string GetFriendlyError(System.ComponentModel.Win32Exception ex)
    {
        return ex.NativeErrorCode switch
        {
            5 => "access denied (insufficient privileges)",
            299 => "32/64-bit architecture mismatch",
            _ => ex.Message
        };
    }
}

/// <summary>
/// Result of module inspection.
/// </summary>
public class ModuleInspectionResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public List<ModuleInfo> Modules { get; set; } = new();
}
