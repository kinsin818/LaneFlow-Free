using System;
using System.Runtime.InteropServices;

namespace LaneFlow;

/// <summary>
/// Kills every child process when this process dies, including a hard kill. The gate kernel
/// owns the TUN; without this backstop a task-manager kill could leave the network pointed at
/// a dead adapter. Best effort: if the host already put us in a job, installation is skipped.
/// </summary>
internal static class ChildJob
{
    private const uint JobObjectLimitKillOnJobClose = 0x2000;
    private const int JobObjectExtendedLimitInformationClass = 9;

    private static IntPtr _job;

    public static void Install()
    {
        try
        {
            _job = CreateJobObject(IntPtr.Zero, null);
            if (_job == IntPtr.Zero)
                return;

            var info = new JobObjectExtendedLimitInformation
            {
                BasicLimitInformation = new JobObjectBasicLimitInformation
                {
                    LimitFlags = JobObjectLimitKillOnJobClose
                }
            };
            var length = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(info, buffer, false);
                SetInformationJobObject(_job, JobObjectExtendedLimitInformationClass, buffer, (uint)length);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

        }
        catch
        {
            // Never block startup on the backstop; the explicit Stop paths remain.
        }
    }

    public static void Assign(System.Diagnostics.Process process)
    {
        try
        {
            if (_job != IntPtr.Zero && process.Handle != IntPtr.Zero)
                AssignProcessToJobObject(_job, process.Handle);
        }
        catch
        {
            // Best effort: an unassigned kernel still dies through the explicit Stop path.
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string? name);

    [DllImport("kernel32.dll")]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);

    [DllImport("kernel32.dll")]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

}
