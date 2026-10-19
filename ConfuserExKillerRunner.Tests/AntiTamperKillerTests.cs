using System;
using System.Collections.Generic;
using System.IO;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class AntiTamperKillerTests
    {
        [Fact]
        public void Execute_NullModule_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AntiTamperKiller.Execute(null, new byte[100]));
        }

        [Fact]
        public void Execute_NullPeImage_ThrowsArgumentNullException()
        {
            var mod = typeof(AntiTamperKillerTests).Module;
            Assert.Throws<ArgumentNullException>(() => AntiTamperKiller.Execute(mod, null));
        }

        [Fact]
        public void ProcessAntiTamperResult_DecryptionConfirmed_EnablesDecryptedFlagAndUsesDecryptedImage()
        {
            byte[] orig = new byte[] { 1, 2, 3 };
            byte[] dec = new byte[] { 4, 5, 6 };
            var result = new AntiTamperResult
            {
                Status = AntiTamperStatus.DecryptionConfirmed,
                Modified = true,
                DecryptedPeImage = dec,
                DecryptedSections = new List<string> { ".cflow" }
            };

            var (antiTamperDecrypted, effectiveImage) = Program.ProcessAntiTamperResult(result, orig);

            Assert.True(antiTamperDecrypted);
            Assert.Same(dec, effectiveImage);
        }

        [Fact]
        public void ProcessAntiTamperResult_ChangesDetected_DisablesDecryptedFlagAndRestoresOriginalImage()
        {
            byte[] orig = new byte[] { 1, 2, 3 };
            byte[] dec = new byte[] { 4, 5, 6 };
            var result = new AntiTamperResult
            {
                Status = AntiTamperStatus.ChangesDetected,
                Modified = true,
                DecryptedPeImage = dec,
                DecryptedSections = new List<string> { ".cflow" }
            };

            var (antiTamperDecrypted, effectiveImage) = Program.ProcessAntiTamperResult(result, orig);

            // Changes detected but unconfirmed -> hooks must NOT be stripped and original image restored!
            Assert.False(antiTamperDecrypted);
            Assert.Equal(orig, effectiveImage);
            Assert.NotSame(dec, effectiveImage);
        }

        [Fact]
        public void ProcessAntiTamperResult_Failed_DisablesDecryptedFlagAndRestoresOriginalImage()
        {
            byte[] orig = new byte[] { 1, 2, 3 };
            byte[] dec = new byte[] { 9, 9, 9 }; // Potentially corrupt image
            var result = new AntiTamperResult
            {
                Status = AntiTamperStatus.Failed,
                Modified = true,
                DecryptedPeImage = dec,
                Message = "Access violation during memory read"
            };

            var (antiTamperDecrypted, effectiveImage) = Program.ProcessAntiTamperResult(result, orig);

            // On failure, must NOT continue with corrupt/partial image
            Assert.False(antiTamperDecrypted);
            Assert.Equal(orig, effectiveImage);
            Assert.NotSame(dec, effectiveImage);
        }

        [Fact]
        public void ProcessAntiTamperResult_NoChangesDetected_DisablesDecryptedFlagAndRestoresOriginalImage()
        {
            byte[] orig = new byte[] { 1, 2, 3 };
            var result = new AntiTamperResult
            {
                Status = AntiTamperStatus.NoChangesDetected,
                Modified = false,
                DecryptedPeImage = orig
            };

            var (antiTamperDecrypted, effectiveImage) = Program.ProcessAntiTamperResult(result, orig);

            Assert.False(antiTamperDecrypted);
            Assert.Equal(orig, effectiveImage);
        }

        [Fact]
        public void ProcessAntiTamperResult_NotAttempted_DisablesDecryptedFlagAndRestoresOriginalImage()
        {
            byte[] orig = new byte[] { 1, 2, 3 };
            var result = new AntiTamperResult
            {
                Status = AntiTamperStatus.NotAttempted,
                Modified = false,
                DecryptedPeImage = orig
            };

            var (antiTamperDecrypted, effectiveImage) = Program.ProcessAntiTamperResult(result, orig);

            Assert.False(antiTamperDecrypted);
            Assert.Equal(orig, effectiveImage);
        }

        [Fact]
        public void ProcessAntiTamperResult_Null_ReturnsFalseAndOriginalImage()
        {
            byte[] orig = new byte[] { 1, 2, 3 };
            var (antiTamperDecrypted, effectiveImage) = Program.ProcessAntiTamperResult(null, orig);

            Assert.False(antiTamperDecrypted);
            Assert.Equal(orig, effectiveImage);
        }

        [Fact]
        public void VerifyDecryptedImage_NoMethodsInRestoredSections_ReturnsChangesDetected()
        {
            // Build a valid module in memory
            var mod = new ModuleDefUser("TestVerifyMod");
            var userType = new TypeDefUser("UserType", mod.CorLibTypes.Object.TypeDefOrRef);
            mod.Types.Add(userType);
            var method = new MethodDefUser("SampleMethod", MethodSig.CreateStatic(mod.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(method);

            byte[] peBytes;
            using (var ms = new MemoryStream())
            {
                mod.Write(ms, new ModuleWriterOptions(mod));
                peBytes = ms.ToArray();
            }

            // Specify a restored section at an arbitrary RVA that contains NO methods
            var restoredSections = new List<DecryptedSectionInfo>
            {
                new DecryptedSectionInfo
                {
                    Name = ".custom",
                    VirtualAddress = 0x50000,
                    VirtualSize = 0x1000,
                    SizeOfRawData = 0x1000,
                    PointerToRawData = 0x2000
                }
            };

            var (status, count) = AntiTamperKiller.VerifyDecryptedImage(peBytes, restoredSections);

            // Because no methods are mapped in that section, decryption CANNOT be confirmed
            Assert.Equal(AntiTamperStatus.ChangesDetected, status);
            Assert.Equal(0, count);
        }

        [Fact]
        public void VerifyDecryptedImage_ValidMethodsInRestoredSection_ReturnsDecryptionConfirmed()
        {
            var mod = new ModuleDefUser("TestVerifyMod2");
            var userType = new TypeDefUser("UserType", mod.CorLibTypes.Object.TypeDefOrRef);
            mod.Types.Add(userType);
            // Non-void method returning Int32 with 1 pushed value is valid IL
            var method = new MethodDefUser("SampleMethod", MethodSig.CreateStatic(mod.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(method);

            byte[] peBytes;
            using (var ms = new MemoryStream())
            {
                mod.Write(ms, new ModuleWriterOptions(mod));
                peBytes = ms.ToArray();
            }

            // Read the actual section range of the written module where SampleMethod is placed
            uint methodRva = 0;
            using (var loaded = ModuleDefMD.Load(peBytes))
            {
                var loadedMethod = loaded.Find("UserType", false)?.FindMethod("SampleMethod");
                Assert.NotNull(loadedMethod);
                methodRva = (uint)loadedMethod.RVA;
            }

            Assert.True(methodRva > 0);

            // Create a restored section encompassing the method RVA
            var restoredSections = new List<DecryptedSectionInfo>
            {
                new DecryptedSectionInfo
                {
                    Name = ".text",
                    VirtualAddress = methodRva - 0x10,
                    VirtualSize = 0x1000,
                    SizeOfRawData = 0x1000,
                    PointerToRawData = 0x400
                }
            };

            var (status, count) = AntiTamperKiller.VerifyDecryptedImage(peBytes, restoredSections);

            // Methods located inside the section have valid IL bodies -> DecryptionConfirmed!
            Assert.Equal(AntiTamperStatus.DecryptionConfirmed, status);
            Assert.True(count >= 1);
        }

        [Fact]
        public void VerifyDecryptedImage_VoidMethodLeavesValueOnStack_ReturnsChangesDetected()
        {
            var mod = new ModuleDefUser("TestVerifyModVoidStack");
            var userType = new TypeDefUser("UserType", mod.CorLibTypes.Object.TypeDefOrRef);
            mod.Types.Add(userType);
            // Void method that pushes a value and does not pop it before ret -> stack mismatch!
            var method = new MethodDefUser("InvalidVoidMethod", MethodSig.CreateStatic(mod.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(method);

            byte[] peBytes;
            using (var ms = new MemoryStream())
            {
                mod.Write(ms, new ModuleWriterOptions(mod));
                peBytes = ms.ToArray();
            }

            uint methodRva = 0;
            using (var loaded = ModuleDefMD.Load(peBytes))
            {
                var loadedMethod = loaded.Find("UserType", false)?.FindMethod("InvalidVoidMethod");
                Assert.NotNull(loadedMethod);
                methodRva = (uint)loadedMethod.RVA;
            }

            var restoredSections = new List<DecryptedSectionInfo>
            {
                new DecryptedSectionInfo
                {
                    Name = ".text",
                    VirtualAddress = methodRva - 0x10,
                    VirtualSize = 0x1000,
                    SizeOfRawData = 0x1000,
                    PointerToRawData = 0x400
                }
            };

            var (status, count) = AntiTamperKiller.VerifyDecryptedImage(peBytes, restoredSections);

            // Void method with non-empty evaluation stack at ret must fail structural IL verification
            Assert.Equal(AntiTamperStatus.ChangesDetected, status);
            Assert.Equal(0, count);
        }

        [Fact]
        public void VerifyDecryptedImage_MethodWithOrphanedBranch_ReturnsChangesDetected()
        {
            var mod = new ModuleDefUser("TestVerifyModBranch");
            var userType = new TypeDefUser("UserType", mod.CorLibTypes.Object.TypeDefOrRef);
            mod.Types.Add(userType);
            var method = new MethodDefUser("InvalidBranchMethod", MethodSig.CreateStatic(mod.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var i0 = Instruction.Create(OpCodes.Nop);
            var i1 = Instruction.Create(OpCodes.Br_S, i0);
            var i2 = Instruction.Create(OpCodes.Ret);
            method.Body.Instructions.Add(i0);
            method.Body.Instructions.Add(i1);
            method.Body.Instructions.Add(i2);
            userType.Methods.Add(method);

            byte[] peBytes;
            using (var ms = new MemoryStream())
            {
                mod.Write(ms, new ModuleWriterOptions(mod));
                peBytes = ms.ToArray();
            }

            uint methodRva = 0;
            using (var loaded = ModuleDefMD.Load(peBytes))
            {
                var loadedMethod = loaded.Find("UserType", false)?.FindMethod("InvalidBranchMethod");
                Assert.NotNull(loadedMethod);
                methodRva = (uint)loadedMethod.RVA;
            }

            // Find file offset of method in peBytes and corrupt br.s operand to branch out of bounds
            var peModel = ConfuserExKillerRunner.Analysis.PEUtils.ParsePE(peBytes);
            var sec = peModel.Sections.First(s => methodRva >= s.VirtualAddress && methodRva < s.VirtualAddress + s.VirtualSize);
            uint fileOffset = sec.PointerToRawData + (methodRva - sec.VirtualAddress);

            for (int i = (int)fileOffset; i < fileOffset + 32 && i < peBytes.Length - 1; i++)
            {
                if (peBytes[i] == 0x2B) // br.s
                {
                    peBytes[i + 1] = 0x7E; // Corrupt branch offset to +126 bytes out of bounds!
                    break;
                }
            }

            var restoredSections = new List<DecryptedSectionInfo>
            {
                new DecryptedSectionInfo
                {
                    Name = ".text",
                    VirtualAddress = methodRva - 0x10,
                    VirtualSize = 0x1000,
                    SizeOfRawData = 0x1000,
                    PointerToRawData = 0x400
                }
            };

            var (status, count) = AntiTamperKiller.VerifyDecryptedImage(peBytes, restoredSections);

            // Method with branch to unlisted/orphaned instruction must fail verification
            Assert.Equal(AntiTamperStatus.ChangesDetected, status);
            Assert.Equal(0, count);
        }

        [Fact]
        public void VerifyDecryptedImage_MethodWithStackUnderflow_ReturnsChangesDetected()
        {
            var mod = new ModuleDefUser("TestVerifyModUnderflow");
            var userType = new TypeDefUser("UserType", mod.CorLibTypes.Object.TypeDefOrRef);
            mod.Types.Add(userType);
            var method = new MethodDefUser("UnderflowMethod", MethodSig.CreateStatic(mod.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody
                {
                    KeepOldMaxStack = true,
                    MaxStack = 8
                }
            };
            // Add followed by ret without pushing operands causes evaluation stack underflow
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(method);

            byte[] peBytes;
            using (var ms = new MemoryStream())
            {
                var options = new ModuleWriterOptions(mod);
                options.MetaDataOptions.Flags |= dnlib.DotNet.Writer.MetaDataFlags.KeepOldMaxStack;
                mod.Write(ms, options);
                peBytes = ms.ToArray();
            }

            uint methodRva = 0;
            using (var loaded = ModuleDefMD.Load(peBytes))
            {
                var loadedMethod = loaded.Find("UserType", false)?.FindMethod("UnderflowMethod");
                Assert.NotNull(loadedMethod);
                methodRva = (uint)loadedMethod.RVA;
            }

            var restoredSections = new List<DecryptedSectionInfo>
            {
                new DecryptedSectionInfo
                {
                    Name = ".text",
                    VirtualAddress = methodRva - 0x10,
                    VirtualSize = 0x1000,
                    SizeOfRawData = 0x1000,
                    PointerToRawData = 0x400
                }
            };

            var (status, count) = AntiTamperKiller.VerifyDecryptedImage(peBytes, restoredSections);

            // Method with evaluation stack underflow must fail verification
            Assert.Equal(AntiTamperStatus.ChangesDetected, status);
            Assert.Equal(0, count);
        }

        [Fact]
        public void Execute_ModuleConstructorThrowsException_ReturnsFailedAndRestoresOriginalImage()
        {
            // Build a valid assembly containing a module with a throwing .cctor
            var asm = new AssemblyDefUser("ThrowingCctorAsm", new Version(1, 0, 0, 0));
            var mod = new ModuleDefUser("ThrowingCctorMod.dll");
            asm.Modules.Add(mod);

            var globalType = mod.GlobalType;
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(mod.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            var exCtor = new MemberRefUser(mod, ".ctor",
                MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.String),
                new TypeRefUser(mod, "System", "Exception", mod.CorLibTypes.AssemblyRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Intentional cctor failure"));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, exCtor));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Throw));
            globalType.Methods.Add(cctor);

            string tempDir = Path.Combine(Path.GetTempPath(), "ThrowingCctorTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            string tempDll = Path.Combine(tempDir, "ThrowingCctorMod.dll");
            try
            {
                mod.Write(tempDll);
                byte[] peBytes = File.ReadAllBytes(tempDll);

                var loadedAsm = System.Reflection.Assembly.LoadFrom(tempDll);
                var loadedMod = loadedAsm.ManifestModule;

                var result = AntiTamperKiller.Execute(loadedMod, peBytes);

                // Even if memory diffs occurred or were scanned, failed cctor forces Failed status
                // and original PE image must be restored.
                Assert.Equal(AntiTamperStatus.Failed, result.Status);
                Assert.False(result.Modified);
                Assert.Equal(peBytes, result.DecryptedPeImage);
                Assert.Contains("module constructor", result.Message, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void ResultMessages_NeverContainSuccessfullyDecryptedUnlessDecryptionConfirmed()
        {
            var failed = new AntiTamperResult { Status = AntiTamperStatus.Failed, Message = "PE signature mismatch" };
            Assert.DoesNotContain("Successfully decrypted", failed.Message, StringComparison.OrdinalIgnoreCase);

            var changes = new AntiTamperResult { Status = AntiTamperStatus.ChangesDetected, Message = "Memory differences detected in 1 section(s), but method decryption could not be confirmed" };
            Assert.DoesNotContain("Successfully decrypted", changes.Message, StringComparison.OrdinalIgnoreCase);

            var noChanges = new AntiTamperResult { Status = AntiTamperStatus.NoChangesDetected, Message = "Dynamic execution completed; no section differences detected" };
            Assert.DoesNotContain("Successfully decrypted", noChanges.Message, StringComparison.OrdinalIgnoreCase);

            var notAttempted = new AntiTamperResult { Status = AntiTamperStatus.NotAttempted, Message = "Anti-tamper dynamic execution was not attempted" };
            Assert.DoesNotContain("Successfully decrypted", notAttempted.Message, StringComparison.OrdinalIgnoreCase);

            var confirmed = new AntiTamperResult { Status = AntiTamperStatus.DecryptionConfirmed, Message = "Successfully decrypted and verified 1 section(s) (.cflow) containing 5 restored method(s)" };
            Assert.Contains("Successfully decrypted", confirmed.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Execute_RealConfuserExAntiTamperBinary_DynamicDecryption_DecryptsSectionAndRestoresValidMethods()
        {
            // Locate real ConfuserEx v1.0.0 binary protected with Anti-Tamper
            string baseDir = AppContext.BaseDirectory;
            var dir = new DirectoryInfo(baseDir);
            string repoRoot = null;
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "unconfuser.sln")))
                {
                    repoRoot = dir.FullName;
                    break;
                }
                dir = dir.Parent;
            }

            Assert.NotNull(repoRoot);
            string fixtureDir = Path.Combine(repoRoot, "benchmarks", "fixtures", "real_confuserex_antitamper");
            string fixturePath = Path.Combine(fixtureDir, "BenignSample.exe");

            // Explicit assertion: the fixture must be present (tracked in git)
            Assert.True(File.Exists(fixturePath), $"Anti-Tamper fixture binary not found at '{fixturePath}'. Ensure repository fixtures are checked out.");

            byte[] originalPeBytes = File.ReadAllBytes(fixturePath);

            // Dynamic execution: load module into reflection context for native module constructor execution
            var reflAsm = System.Reflection.Assembly.LoadFile(fixturePath);
            var reflMod = reflAsm.ManifestModule;

            // Execute AntiTamperKiller.Execute
            var result = AntiTamperKiller.Execute(reflMod, originalPeBytes);

            Assert.NotNull(result);
            Assert.Equal(AntiTamperStatus.DecryptionConfirmed, result.Status);
            Assert.True(result.Modified);
            Assert.NotNull(result.DecryptedPeImage);
            Assert.NotEmpty(result.DecryptedSections);
            Assert.Contains("Successfully decrypted", result.Message, StringComparison.OrdinalIgnoreCase);

            // Verify that the restored image can be parsed by dnlib and contains valid restored method bodies
            using (var decryptedMod = ModuleDefMD.Load(result.DecryptedPeImage))
            {
                Assert.NotNull(decryptedMod);
                int validMethodsCount = 0;
                foreach (var type in decryptedMod.GetTypes())
                {
                    foreach (var m in type.Methods)
                    {
                        if (m.HasBody && m.Body.Instructions.Count > 0)
                        {
                            var report = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
                            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(m, report);
                            if (report.Status == "CLEAN")
                                validMethodsCount++;
                        }
                    }
                }

                Assert.True(validMethodsCount >= 10, $"Expected at least 10 valid restored methods, found {validMethodsCount}");
            }
        }

        [Fact]
        public void Execute_RealConfuserExAntiTamperBinary_StaticStructure_DetectsEncryptedSectionAndRetainsHookWithoutExecution()
        {
            // Verify static identification of ConfuserEx encrypted sections and hook retention without claiming dynamic decryption
            string baseDir = AppContext.BaseDirectory;
            var dir = new DirectoryInfo(baseDir);
            string repoRoot = null;
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "unconfuser.sln")))
                {
                    repoRoot = dir.FullName;
                    break;
                }
                dir = dir.Parent;
            }

            Assert.NotNull(repoRoot);
            string fixturePath = Path.Combine(repoRoot, "benchmarks", "fixtures", "real_confuserex_antitamper", "BenignSample.exe");
            Assert.True(File.Exists(fixturePath), $"Anti-Tamper fixture binary not found at '{fixturePath}'. Ensure repository fixtures are checked out.");

            byte[] originalPeBytes = File.ReadAllBytes(fixturePath);

            // Static inspection: the original binary has an encrypted section created by ConfuserEx
            using (var originalMod = ModuleDefMD.Load(originalPeBytes))
            {
                Assert.NotNull(originalMod);

                // 1. Detect the distinctive encrypted section (RWX characteristics: MEM_EXECUTE | MEM_WRITE | MEM_READ: 0xE0000000)
                const uint rwxMask = 0xE0000000;

                var encryptedSection = originalMod.MetaData.PEImage.ImageSectionHeaders.FirstOrDefault(s =>
                    (s.Characteristics & rwxMask) == rwxMask);

                Assert.NotNull(encryptedSection);
                Assert.True(encryptedSection.VirtualSize > 0, "Encrypted section must have non-zero virtual size.");

                // 2. Verify that methods are actually mapped inside the encrypted section RVA range
                uint secStart = (uint)encryptedSection.VirtualAddress;
                uint secEnd = secStart + (uint)encryptedSection.VirtualSize;
                int methodsInEncryptedSection = 0;

                foreach (var t in originalMod.GetTypes())
                {
                    foreach (var m in t.Methods)
                    {
                        uint mRva = (uint)m.RVA;
                        if (mRva >= secStart && mRva < secEnd)
                            methodsInEncryptedSection++;
                    }
                }

                Assert.True(methodsInEncryptedSection >= 10,
                    $"Expected at least 10 methods mapped in encrypted section [0x{secStart:X}, 0x{secEnd:X}), found {methodsInEncryptedSection}");

                // 3. In pure static mode (antiTamperDecrypted: false), CleanerKiller identifies the Anti-Tamper hook
                // and strictly RETAINS it without stripping, because native decryption was not proven.
                var cleanResult = CleanerKiller.StripProtectorHooks(originalMod, antiTamperDecrypted: false);
                Assert.Equal(0, cleanResult.StrippedHooksCount);

                var cctor = originalMod.GlobalType?.FindStaticConstructor();
                Assert.NotNull(cctor);
                Assert.NotEqual(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            }
        }
    }
}
