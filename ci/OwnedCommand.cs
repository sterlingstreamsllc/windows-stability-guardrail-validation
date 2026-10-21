// Test-harness containment only. Never compiled/executed in Cloud.
// .NET Framework / C# 5 compatible; package and workload limits are unchanged.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace PcsgSmoke {
    public sealed class NativeFailure : Win32Exception {
        public string Operation { get; private set; }
        public uint Pid { get; private set; }
        public int Winerror { get; private set; }
        internal NativeFailure(string operation, uint pid, int error)
            : base(error, operation + " pid=" + pid + " winerror=" + error) {
            Operation=operation; Pid=pid; Winerror=error;
        }
    }

    public sealed class OwnedCommand : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct Basic {
            public long ProcessTime, JobTime;
            public uint Flags;
            public UIntPtr MinWS, MaxWS;
            public uint ActiveLimit;
            public UIntPtr Affinity;
            public uint Priority, Scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] struct IO {
            public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
        }
        [StructLayout(LayoutKind.Sequential)] struct Extended {
            public Basic Basic; public IO IO;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }
        [StructLayout(LayoutKind.Sequential)] struct Accounting {
            public long User, Kernel, PeriodUser, PeriodKernel;
            public uint Faults, Total, Active, Terminated;
        }
        [StructLayout(LayoutKind.Sequential)] struct Security {
            public uint Length; public IntPtr Descriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool Inherit;
        }
        [StructLayout(LayoutKind.Sequential)] struct Startup {
            public uint Size; public IntPtr Reserved, Desktop, Title;
            public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;
            public ushort Show, Reserved2Size;
            public IntPtr Reserved2, Input, Output, Error;
        }
        [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup Startup; public IntPtr Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public uint Pid, Tid; }

        [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool SetInformationJobObject(IntPtr job, int kind, ref Extended data, uint size);
        [DllImport("kernel32.dll", ExactSpelling=true, EntryPoint="QueryInformationJobObject", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool QueryLimits(IntPtr job, int kind, out Extended data, uint size, IntPtr returned);
        [DllImport("kernel32.dll", ExactSpelling=true, EntryPoint="QueryInformationJobObject", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool QueryAccounting(IntPtr job, int kind, out Accounting data, uint size, IntPtr returned);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool GetHandleInformation(IntPtr handle, out uint flags);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool InitializeProcThreadAttributeList(IntPtr list, uint count, uint flags, ref UIntPtr size);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr key, IntPtr value, UIntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll", ExactSpelling=true)] static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr CreateFileW(string path, uint access, uint share, ref Security security, uint creation, uint attributes, IntPtr template);
        [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity,
            [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, IntPtr environment, string directory, ref StartupEx startup, out ProcessInfo info);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool TerminateProcess(IntPtr process, uint code);

        const uint KillOnClose=0x2000;
        IntPtr job, process, thread;
        bool disposed;
        public uint Id { get; private set; }
        public uint ExitCode { get; private set; }
        public uint ActiveLast { get; private set; }
        public uint TotalLast { get; private set; }
        public uint LimitFlags { get; private set; }
        public bool Created { get; private set; }
        public bool Resumed { get; private set; }
        public bool WrapperExitConfirmed { get; private set; }
        public bool TreeEmptyConfirmed { get; private set; }
        public bool TerminationAttempted { get; private set; }
        public bool TerminationSucceeded { get; private set; }
        public bool OwnedRootFallbackAttempted { get; private set; }
        public readonly List<string> CleanupErrors = new List<string>();
        OwnedCommand() { ActiveLast=UInt32.MaxValue; }

        void Check(bool ok, string operation) {
            if (!ok) throw new NativeFailure(operation, Id, Marshal.GetLastWin32Error());
        }
        static void Require(bool ok, string reason) { if (!ok) throw new InvalidOperationException(reason); }
        void Close(ref IntPtr handle, string label) {
            IntPtr h=handle; handle=IntPtr.Zero;
            if (h!=IntPtr.Zero && h!=new IntPtr(-1) && !CloseHandle(h))
                CleanupErrors.Add(label+" winerror="+Marshal.GetLastWin32Error());
        }
        static string Quote(string s) {
            Require(!String.IsNullOrEmpty(s) && s.IndexOfAny(new char[]{'"','\r','\n','\0'})<0 && !s.EndsWith("\\"), "UNSAFE_EXECUTABLE_ARGUMENT");
            return "\""+s+"\"";
        }
        public static string VerifyAbi() {
            Require(IntPtr.Size==8 && Marshal.SizeOf(typeof(Basic))==64 && Marshal.SizeOf(typeof(Extended))==144 &&
                Marshal.SizeOf(typeof(Accounting))==48 && Marshal.SizeOf(typeof(Security))==24 &&
                Marshal.SizeOf(typeof(Startup))==104 && Marshal.SizeOf(typeof(StartupEx))==112 &&
                Marshal.SizeOf(typeof(ProcessInfo))==24 && Marshal.OffsetOf(typeof(Basic),"Flags").ToInt32()==16 &&
                Marshal.OffsetOf(typeof(Startup),"Input").ToInt32()==80 &&
                Marshal.OffsetOf(typeof(StartupEx),"Attributes").ToInt32()==104, "OWNED_COMMAND_X64_ABI_MISMATCH");
            return "x64 Basic64 Extended144 Accounting48 Security24 Startup104 StartupEx112 ProcessInfo24";
        }
        public static OwnedCommand Start(string executable, string arguments, string directory, string stdout, string stderr, int launchMilliseconds) {
            VerifyAbi();
            Require(launchMilliseconds>0 && launchMilliseconds<=45000,"LAUNCH_DEADLINE_REQUIRED");
            Stopwatch launchClock=Stopwatch.StartNew();
            OwnedCommand o=new OwnedCommand();
            IntPtr attrs=IntPtr.Zero, jobs=IntPtr.Zero, handles=IntPtr.Zero;
            IntPtr input=IntPtr.Zero, output=IntPtr.Zero, error=IntPtr.Zero;
            bool initialized=false; Exception primary=null;
            try {
                o.job=CreateJobObjectW(IntPtr.Zero,null); o.Check(o.job!=IntPtr.Zero,"CreateJobObjectW(outer)");
                Extended limits=new Extended(); limits.Basic.Flags=KillOnClose;
                o.Check(SetInformationJobObject(o.job,9,ref limits,144),"SetInformationJobObject(outer)");
                Extended readback;
                o.Check(QueryLimits(o.job,9,out readback,144,IntPtr.Zero),"QueryInformationJobObject(outer limits)");
                o.LimitFlags=readback.Basic.Flags;
                Require(o.LimitFlags==KillOnClose,"OUTER_LIMITS_NOT_EXACT_KILL_ON_CLOSE");
                uint handleFlags;
                o.Check(GetHandleInformation(o.job,out handleFlags),"GetHandleInformation(outer)");
                Require((handleFlags&1)==0,"OUTER_JOB_MUST_NOT_BE_INHERITED");
                Security sa=new Security();sa.Length=24;sa.Inherit=true;
                input=CreateFileW("NUL",0x80000000,3,ref sa,3,0,IntPtr.Zero);
                o.Check(input!=new IntPtr(-1),"CreateFileW(stdin NUL)");
                output=CreateFileW(stdout,0x40000000,1,ref sa,1,128,IntPtr.Zero);
                o.Check(output!=new IntPtr(-1),"CreateFileW(stdout CREATE_NEW)");
                error=CreateFileW(stderr,0x40000000,1,ref sa,1,128,IntPtr.Zero);
                o.Check(error!=new IntPtr(-1),"CreateFileW(stderr CREATE_NEW)");
                UIntPtr size=UIntPtr.Zero;
                bool sizing=InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size);
                int sizingError=Marshal.GetLastWin32Error();
                if (sizing || sizingError!=122) throw new NativeFailure("InitializeProcThreadAttributeList(size)",0,sizingError);
                Require(size.ToUInt64()>0 && size.ToUInt64()<=65536,"ATTRIBUTE_ALLOCATION_BOUND");
                attrs=Marshal.AllocHGlobal((int)size.ToUInt64());
                o.Check(InitializeProcThreadAttributeList(attrs,2,0,ref size),"InitializeProcThreadAttributeList");initialized=true;
                jobs=Marshal.AllocHGlobal(8); Marshal.WriteIntPtr(jobs,o.job);
                handles=Marshal.AllocHGlobal(24); Marshal.WriteIntPtr(handles,0,input);Marshal.WriteIntPtr(handles,8,output);Marshal.WriteIntPtr(handles,16,error);
                o.Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x2000D),jobs,new UIntPtr(8),IntPtr.Zero,IntPtr.Zero),"UpdateProcThreadAttribute(JOB_LIST)");
                o.Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x20002),handles,new UIntPtr(24),IntPtr.Zero,IntPtr.Zero),"UpdateProcThreadAttribute(HANDLE_LIST)");
                StartupEx startup=new StartupEx();startup.Startup.Size=112;startup.Startup.Flags=0x100;
                startup.Startup.Input=input;startup.Startup.Output=output;startup.Startup.Error=error;startup.Attributes=attrs;
                ProcessInfo info;
                // Atomic job membership at creation, then suspended membership check.
                // No CREATE_BREAKAWAY_FROM_JOB; only explicit stdio handles inherit.
                o.Check(CreateProcessW(executable,new StringBuilder(Quote(executable)+" "+arguments),IntPtr.Zero,IntPtr.Zero,true,
                    0x08080004,IntPtr.Zero,directory,ref startup,out info),"CreateProcessW(atomic outer job)");
                o.process=info.Process;o.thread=info.Thread;o.Id=info.Pid;o.Created=true;
                bool member;
                o.Check(IsProcessInJob(o.process,o.job,out member),"IsProcessInJob(outer before resume)");
                Require(member,"ATOMIC_OUTER_MEMBERSHIP_REQUIRED");
            } catch(Exception ex) { primary=ex; }
            finally {
                if (initialized) DeleteProcThreadAttributeList(attrs);
                if (attrs!=IntPtr.Zero) Marshal.FreeHGlobal(attrs);
                if (jobs!=IntPtr.Zero) Marshal.FreeHGlobal(jobs);
                if (handles!=IntPtr.Zero) Marshal.FreeHGlobal(handles);
                o.Close(ref input,"CloseHandle(parent stdin)");o.Close(ref output,"CloseHandle(parent stdout)");o.Close(ref error,"CloseHandle(parent stderr)");
            }
            if (primary==null && o.CleanupErrors.Count!=0) primary=new InvalidOperationException("SETUP_HANDLE_CLEANUP_FAILED");
            if (primary==null) {
                try {
                    Require(launchClock.ElapsedMilliseconds<launchMilliseconds,"LAUNCH_DEADLINE_BEFORE_RESUME");
                    uint resumed=ResumeThread(o.thread);
                    if (resumed==UInt32.MaxValue) throw new NativeFailure("ResumeThread(outer member)",o.Id,Marshal.GetLastWin32Error());
                    Require(resumed==1,"UNEXPECTED_INITIAL_SUSPEND_COUNT");o.Resumed=true;
                    o.Close(ref o.thread,"CloseHandle(primary thread)");
                    Require(o.CleanupErrors.Count==0,"PRIMARY_THREAD_CLOSE_FAILED");
                    return o;
                } catch(Exception ex) { primary=ex; }
            }
            // Failed creation/setup/resume cannot leave a runnable unowned wrapper.
            o.Dispose(); primary.Data["owned_job_cleanup"]=String.Join("; ",o.CleanupErrors.ToArray());
            primary.Data["owned_tree_empty_confirmed"]=o.TreeEmptyConfirmed;
            primary.Data["owned_wrapper_exit_confirmed"]=o.WrapperExitConfirmed;
            primary.Data["owned_root_fallback_attempted"]=o.OwnedRootFallbackAttempted;
            throw primary;
        }
        public bool WaitForExit(int milliseconds) {
            Require(!disposed && process!=IntPtr.Zero && milliseconds>=0 && milliseconds<=3000,"INVALID_BOUNDED_PROCESS_WAIT");
            uint result=WaitForSingleObject(process,(uint)milliseconds);
            if(result==258)return false;
            if(result!=0)throw new NativeFailure("WaitForSingleObject(owned wrapper)",Id,Marshal.GetLastWin32Error());
            uint code;Check(GetExitCodeProcess(process,out code),"GetExitCodeProcess(owned wrapper)");
            ExitCode=code;WrapperExitConfirmed=true;return true;
        }
        public bool ConfirmEmpty(int milliseconds) {
            Require(!disposed && job!=IntPtr.Zero && milliseconds>=0 && milliseconds<=3000,"INVALID_BOUNDED_JOB_WAIT");
            Stopwatch clock=Stopwatch.StartNew();
            do {
                Accounting a;Check(QueryAccounting(job,1,out a,48,IntPtr.Zero),"QueryInformationJobObject(outer accounting)");
                ActiveLast=a.Active;TotalLast=a.Total;
                bool rootGone=process==IntPtr.Zero || WaitForExit(0);
                if(a.Active==0 && rootGone) { TreeEmptyConfirmed=true;return true; }
                if(clock.ElapsedMilliseconds>=milliseconds)return false;
                Thread.Sleep(20);
            } while(true);
        }
        public bool TerminateAndConfirm(int milliseconds) {
            Require(!disposed && job!=IntPtr.Zero,"OUTER_JOB_REQUIRED_FOR_TERMINATION");
            if(!TerminationAttempted) {
                // Latch before the call; no new Resume/Create path and no retries.
                TerminationAttempted=true;
                Check(TerminateJobObject(job,0xE001),"TerminateJobObject(owned tree)");
                TerminationSucceeded=true;
            }
            return ConfirmEmpty(milliseconds);
        }
        public void Dispose() {
            if(disposed)return;
            if(job!=IntPtr.Zero && !TreeEmptyConfirmed && !TerminationAttempted) {
                try { if(!TerminateAndConfirm(3000))CleanupErrors.Add("OWNED_TREE_EXIT_UNCONFIRMED"); }
                catch(Exception ex) { CleanupErrors.Add(ex.Message); }
            }
            if(process!=IntPtr.Zero && !WrapperExitConfirmed) {
                // Creation succeeded but membership/observation might have failed.
                // Never trust membership to clean up that exact retained process.
                // Before successful resume it is suspended and cannot have children.
                try {
                    if(!WaitForExit(0)) {
                        OwnedRootFallbackAttempted=true;
                        Check(TerminateProcess(process,0xE002),"TerminateProcess(exact owned wrapper fallback)");
                        if(!WaitForExit(3000))CleanupErrors.Add("OWNED_WRAPPER_EXIT_UNCONFIRMED");
                    }
                } catch(Exception ex) { CleanupErrors.Add(ex.Message); }
                try { if(job!=IntPtr.Zero && !ConfirmEmpty(0))CleanupErrors.Add("OWNED_TREE_EXIT_UNCONFIRMED"); }
                catch(Exception ex) { CleanupErrors.Add(ex.Message); }
            }
            // Last handle closure is a crash/failure backstop, never exit proof.
            Close(ref job,"CloseHandle(outer job)");
            Close(ref thread,"CloseHandle(primary thread)");Close(ref process,"CloseHandle(wrapper process)");
            disposed=true;GC.SuppressFinalize(this);
        }
        ~OwnedCommand() {
            // Noninheritable job handle makes parent death/finalization kill descendants.
            if(job!=IntPtr.Zero)CloseHandle(job);
            if(thread!=IntPtr.Zero)CloseHandle(thread);
            if(process!=IntPtr.Zero)CloseHandle(process);
        }
    }
}
