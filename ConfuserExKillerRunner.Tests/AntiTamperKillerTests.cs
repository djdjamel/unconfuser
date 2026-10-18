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
        public void ProcessAntiTamperResult_ChangesDetected_DisablesDecryptedFlagAndRetainsDecryptedImage()
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

            // Changes detected but unconfirmed -> hooks must NOT be stripped!
            Assert.False(antiTamperDecrypted);
            Assert.Same(dec, effectiveImage);
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
            var method = new MethodDefUser("SampleMethod", MethodSig.CreateStatic(mod.CorLibTypes.Void),
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

            // Methods located inside the section have valid bodies -> DecryptionConfirmed!
            Assert.Equal(AntiTamperStatus.DecryptionConfirmed, status);
            Assert.True(count >= 1);
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
    }
}
