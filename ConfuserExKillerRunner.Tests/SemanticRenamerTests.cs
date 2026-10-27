using System.IO;
using System.Linq;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class SemanticRenamerTests
    {
        [Fact]
        public void Execute_RenamesFormBasedOnSetName()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("", "Class123", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(formType);

            // Create a method with: ldarg.0, ldstr "MyCustomerForm", call set_Name
            var initMethod = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var setNameRef = new MemberRefUser(module, "set_Name",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                new TypeRefUser(module, "System.Windows.Forms", "Control", module.CorLibTypes.AssemblyRef));

            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "MyCustomerForm"));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, setNameRef));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            formType.Methods.Add(initMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.True(result.TypesRenamed >= 1);
            Assert.Equal("MyCustomerForm", formType.Name.String);
        }

        [Fact]
        public void Execute_NormalizesUnprintableUnicodeMethod()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var someType = new TypeDefUser("TestApp", "NormalClass", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(someType);

            // Method with zero-width characters in name
            string mangledName = "\u200D\u200C\u200E\u202BTest";
            var mangledMethod = new MethodDefUser(mangledName, MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            mangledMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            someType.Methods.Add(mangledMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.True(result.UnprintableNormalized >= 1);
            Assert.False(SemanticRenamer.IsMangledIdentifier(mangledMethod.Name.String));
            Assert.StartsWith("Method_", mangledMethod.Name.String);
        }

        [Fact]
        public void Execute_RenamesStronglyTypedResources()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var resClass = new TypeDefUser("", "Class999", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(resClass);

            // Add static ResourceManager field
            var resManField = new FieldDefUser("resMan",
                new FieldSig(new TypeRefUser(module, "System.Resources", "ResourceManager", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                FieldAttributes.Private | FieldAttributes.Static);
            resClass.Fields.Add(resManField);

            // Add property with getter calling GetObject("AppLogo")
            var propGetter = new MethodDefUser("get_Item", MethodSig.CreateStatic(module.CorLibTypes.Object))
            {
                Body = new CilBody()
            };
            propGetter.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "AppLogo"));
            propGetter.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            resClass.Methods.Add(propGetter);

            var prop = new PropertyDefUser("Item", new PropertySig(true, module.CorLibTypes.Object));
            prop.GetMethod = propGetter;
            resClass.Properties.Add(prop);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("Resources", resClass.Name.String);
            Assert.Equal("AppLogo", prop.Name.String);
            Assert.Equal("get_AppLogo", propGetter.Name.String);
        }

        [Fact]
        public void Execute_HandlesMultipleStronglyTypedResourcesWithoutDuplicates()
        {
            var module = new ModuleDefUser("TestApp.dll");

            // Resource Class 1: Bitmaps (primary Resources)
            var resClass1 = new TypeDefUser("", "Class999", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(resClass1);
            resClass1.Fields.Add(new FieldDefUser("resMan",
                new FieldSig(new TypeRefUser(module, "System.Resources", "ResourceManager", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                FieldAttributes.Private | FieldAttributes.Static));
            var getter1 = new MethodDefUser("get_Logo", MethodSig.CreateStatic(new TypeRefUser(module, "System.Drawing", "Bitmap", module.CorLibTypes.AssemblyRef).ToTypeSig()))
            {
                Body = new CilBody()
            };
            getter1.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Logo"));
            getter1.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            resClass1.Methods.Add(getter1);
            var prop1 = new PropertyDefUser("Logo", new PropertySig(true, getter1.ReturnType));
            prop1.GetMethod = getter1;
            resClass1.Properties.Add(prop1);

            // Resource Class 2: Strings (Messages)
            var resClass2 = new TypeDefUser("", "Class888", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(resClass2);
            resClass2.Fields.Add(new FieldDefUser("resMan",
                new FieldSig(new TypeRefUser(module, "System.Resources", "ResourceManager", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                FieldAttributes.Private | FieldAttributes.Static));
            var getter2 = new MethodDefUser("get_Alert", MethodSig.CreateStatic(module.CorLibTypes.String))
            {
                Body = new CilBody()
            };
            getter2.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "AlertMsg"));
            getter2.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            resClass2.Methods.Add(getter2);
            var prop2 = new PropertyDefUser("Alert", new PropertySig(true, module.CorLibTypes.String));
            prop2.GetMethod = getter2;
            resClass2.Properties.Add(prop2);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.NotEqual(resClass1.FullName, resClass2.FullName);
            Assert.Equal("Resources", resClass1.Name.String);
            Assert.Equal("Messages", resClass2.Name.String);
            Assert.Equal(resClass1.Namespace, resClass2.Namespace);
        }

        [Fact]
        public void Execute_SyncsResourceManagerLdstrAndManifestResource()
        {
            var module = new ModuleDefUser("TestApp.dll");

            var resClass = new TypeDefUser("", "Class451", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(resClass);

            // Add static ResourceManager field
            var rmTypeRef = new TypeRefUser(module, "System.Resources", "ResourceManager", module.CorLibTypes.AssemblyRef);
            resClass.Fields.Add(new FieldDefUser("resourceMan",
                new FieldSig(rmTypeRef.ToTypeSig()),
                FieldAttributes.Private | FieldAttributes.Static));

            // Add get_ResourceManager method with ldstr "MangledResName" and newobj ResourceManager::.ctor
            var rmGetter = new MethodDefUser("get_ResourceManager", MethodSig.CreateStatic(rmTypeRef.ToTypeSig()))
            {
                Body = new CilBody()
            };
            var rmCtorRef = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String,
                    new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                rmTypeRef);

            var ldstrIns = Instruction.Create(OpCodes.Ldstr, "MangledResName");
            rmGetter.Body.Instructions.Add(ldstrIns);
            rmGetter.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull)); // dummy assembly
            rmGetter.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, rmCtorRef));
            rmGetter.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            resClass.Methods.Add(rmGetter);

            // Add property getter for a Bitmap
            var getter = new MethodDefUser("get_AppLogo", MethodSig.CreateStatic(new TypeRefUser(module, "System.Drawing", "Bitmap", module.CorLibTypes.AssemblyRef).ToTypeSig()))
            {
                Body = new CilBody()
            };
            getter.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "AppLogo"));
            getter.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            resClass.Methods.Add(getter);
            var prop = new PropertyDefUser("AppLogo", new PropertySig(true, getter.ReturnType));
            prop.GetMethod = getter;
            resClass.Properties.Add(prop);

            // Add EmbeddedResource with the mangled name
            var embRes = new EmbeddedResource("MangledResName.resources", new byte[] { 1, 2, 3 });
            module.Resources.Add(embRes);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("Resources", resClass.Name.String);
            Assert.Equal(resClass.FullName, (string)ldstrIns.Operand);
            Assert.Equal(resClass.FullName + ".resources", embRes.Name.String);
        }

        [Fact]
        public void Execute_MatchesMangledResourceWithControlPrefix_ToForm()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("TestApp", "CreanceForm", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(formType);

            // Add control field: btnSaveAndClose
            var btnField = new FieldDefUser("btnSaveAndClose",
                new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Private);
            formType.Fields.Add(btnField);

            // Generate resource with key "btnSaveAndClose.ImageOptions.Image"
            byte[] resBytes;
            using (var ms = new MemoryStream())
            {
                using (var rw = new System.Resources.ResourceWriter(ms))
                {
                    rw.AddResource("btnSaveAndClose.ImageOptions.Image", new byte[] { 0x89, 0x50, 0x4E, 0x47 });
                    rw.Generate();
                }
                resBytes = ms.ToArray();
            }

            var mangledRes = new EmbeddedResource("z1|y3Z5?#ZF4Hj9&r\\e=gbi|!.resources", resBytes);
            module.Resources.Add(mangledRes);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("TestApp.CreanceForm.resources", mangledRes.Name.String);
            Assert.True(result.ResourcesRenamed >= 1);
        }

        [Fact]
        public void Execute_AssociatesEmptyResource_ToFormCallingComponentResourceManager()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("", "CVM_FACTURE_LIST", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(formType);

            // Add InitializeComponent with: ldtoken CVM_FACTURE_LIST, call GetTypeFromHandle, newobj ComponentResourceManager
            var initMethod = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var crmTypeRef = new TypeRefUser(module, "System.ComponentModel", "ComponentResourceManager", module.CorLibTypes.AssemblyRef);
            var crmCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void,
                    new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                crmTypeRef);
            var getTypeFromHandle = new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef).ToTypeSig(),
                    new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef));

            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, formType));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getTypeFromHandle));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, crmCtor));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            formType.Methods.Add(initMethod);

            // Generate empty resource stream
            byte[] emptyResBytes;
            using (var ms = new MemoryStream())
            {
                using (var rw = new System.Resources.ResourceWriter(ms))
                {
                    rw.Generate();
                }
                emptyResBytes = ms.ToArray();
            }

            var mangledRes = new EmbeddedResource("empty#mangled#123.resources", emptyResBytes);
            module.Resources.Add(mangledRes);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("CVM_FACTURE_LIST.resources", mangledRes.Name.String);
            Assert.True(result.ResourcesRenamed >= 1);
        }

        [Fact]
        public void Execute_FormWithAmbiguousMangledResources_PreservedWithoutRenaming()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("TestApp", "Form123", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(formType);

            // Add fields: btnA, btnB
            formType.Fields.Add(new FieldDefUser("btnA", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private));
            formType.Fields.Add(new FieldDefUser("btnB", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private));

            // Create two distinct mangled resources with equal matches
            byte[] res1Bytes, res2Bytes;
            using (var ms = new MemoryStream())
            {
                using (var rw = new System.Resources.ResourceWriter(ms))
                {
                    rw.AddResource("btnA.Text", "Save");
                    rw.AddResource("btnB.Text", "Close");
                    rw.Generate();
                }
                res1Bytes = ms.ToArray();
            }
            using (var ms = new MemoryStream())
            {
                using (var rw = new System.Resources.ResourceWriter(ms))
                {
                    rw.AddResource("btnA.Image", new byte[] { 1 });
                    rw.AddResource("btnB.Image", new byte[] { 2 });
                    rw.Generate();
                }
                res2Bytes = ms.ToArray();
            }

            var res1 = new EmbeddedResource("mangled#res#1.resources", res1Bytes);
            var res2 = new EmbeddedResource("mangled#res#2.resources", res2Bytes);
            module.Resources.Add(res1);
            module.Resources.Add(res2);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Both tie with 2 matches on formType -> AMBIGUOUS, neither should be renamed
            Assert.Equal("mangled#res#1.resources", res1.Name.String);
            Assert.Equal("mangled#res#2.resources", res2.Name.String);
            Assert.Contains(result.Decisions, d => d.Confidence == RenameConfidence.Ambiguous && !d.Applied);
        }

        [Fact]
        public void Execute_TwoFormsWithAmbiguousResource_PreservedWithoutRenaming()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var form1 = new TypeDefUser("TestApp", "Form1", module.CorLibTypes.Object.TypeDefOrRef);
            var form2 = new TypeDefUser("TestApp", "Form2", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(form1);
            module.Types.Add(form2);

            // Both forms have identical control fields
            form1.Fields.Add(new FieldDefUser("btnOK", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private));
            form1.Fields.Add(new FieldDefUser("btnCancel", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private));
            form2.Fields.Add(new FieldDefUser("btnOK", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private));
            form2.Fields.Add(new FieldDefUser("btnCancel", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private));

            byte[] resBytes;
            using (var ms = new MemoryStream())
            {
                using (var rw = new System.Resources.ResourceWriter(ms))
                {
                    rw.AddResource("btnOK.Text", "OK");
                    rw.AddResource("btnCancel.Text", "Cancel");
                    rw.Generate();
                }
                resBytes = ms.ToArray();
            }

            var res = new EmbeddedResource("mangled#shared#res.resources", resBytes);
            module.Resources.Add(res);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Resource ties for both Form1 and Form2 -> AMBIGUOUS, preserved without renaming
            Assert.Equal("mangled#shared#res.resources", res.Name.String);
            Assert.Contains(result.Decisions, d => d.Confidence == RenameConfidence.Ambiguous && !d.Applied);
        }

        [Fact]
        public void Execute_PublicMethodAndVirtualMethod_PreservedFromRenaming()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("TestApp", "MyForm", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(formType);

            // Add public event handler: must be preserved because it's public
            var publicHandler = new MethodDefUser("method_10", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object),
                MethodAttributes.Public | MethodAttributes.HideBySig);
            publicHandler.Body = new CilBody();
            publicHandler.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            formType.Methods.Add(publicHandler);

            // Add virtual event handler: must be preserved because it's virtual
            var virtualHandler = new MethodDefUser("method_20", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object),
                MethodAttributes.Private | MethodAttributes.Virtual | MethodAttributes.HideBySig);
            virtualHandler.Body = new CilBody();
            virtualHandler.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            formType.Methods.Add(virtualHandler);

            // Add private non-virtual handler: can be renamed
            var privateHandler = new MethodDefUser("method_30", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object),
                MethodAttributes.Private | MethodAttributes.HideBySig);
            privateHandler.Body = new CilBody();
            privateHandler.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            formType.Methods.Add(privateHandler);

            // Field btnSave
            var btnField = new FieldDefUser("btnSave", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private);
            formType.Fields.Add(btnField);

            // Wire up event subscriptions in InitializeComponent
            var init = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            var addClick = new MemberRefUser(module, "add_Click",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object),
                new TypeRefUser(module, "System.Windows.Forms", "Control", module.CorLibTypes.AssemblyRef));
            var ehCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System", "EventHandler", module.CorLibTypes.AssemblyRef));

            // Wire publicHandler
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldfld, btnField));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, publicHandler));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, ehCtor));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, addClick));

            // Wire virtualHandler
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldfld, btnField));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, virtualHandler));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, ehCtor));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, addClick));

            // Wire privateHandler
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldfld, btnField));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, privateHandler));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, ehCtor));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, addClick));
            init.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            formType.Methods.Add(init);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("method_10", publicHandler.Name.String);
            Assert.Equal("method_20", virtualHandler.Name.String);
            Assert.Equal("btnSave_Click", privateHandler.Name.String);
        }

        [Fact]
        public void Execute_PropertyAccessedByReflection_PreservedFromRenaming()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var resClass = new TypeDefUser("", "Class999", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(resClass);

            resClass.Fields.Add(new FieldDefUser("resMan",
                new FieldSig(new TypeRefUser(module, "System.Resources", "ResourceManager", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                FieldAttributes.Private | FieldAttributes.Static));

            // Property that matches reflection GetProperty("MangledKey")
            var getter = new MethodDefUser("get_Item", MethodSig.CreateStatic(module.CorLibTypes.Object)) { Body = new CilBody() };
            getter.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "MangledKey"));
            getter.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            resClass.Methods.Add(getter);
            var prop = new PropertyDefUser("MangledKey", new PropertySig(true, module.CorLibTypes.Object)) { GetMethod = getter };
            resClass.Properties.Add(prop);

            // Another class invokes typeof(Class999).GetProperty("MangledKey")
            var callerType = new TypeDefUser("TestApp", "ReflectionCaller", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var callMethod = new MethodDefUser("InvokeReflect", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Body = new CilBody() };
            var getPropertyRef = new MemberRefUser(module, "GetProperty",
                MethodSig.CreateInstance(new TypeRefUser(module, "System.Reflection", "PropertyInfo", module.CorLibTypes.AssemblyRef).ToTypeSig(), module.CorLibTypes.String),
                new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, resClass));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "MangledKey"));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getPropertyRef));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(callMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("MangledKey", prop.Name.String);
            Assert.Contains(result.Decisions, d => d.SymbolType == "Property" && d.OriginalName == "MangledKey" && !d.Applied);
        }

        [Fact]
        public void Execute_TypeLoadedViaTypeGetType_UpdatesLdstrOperand()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("TestApp", "Class123", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(formType);

            // Form InitializeComponent has set_Name("InvoiceReportForm")
            var initMethod = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            var setNameRef = new MemberRefUser(module, "set_Name",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                new TypeRefUser(module, "System.Windows.Forms", "Control", module.CorLibTypes.AssemblyRef));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "InvoiceReportForm"));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, setNameRef));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            formType.Methods.Add(initMethod);

            // Another class calls Type.GetType("TestApp.Class123")
            var callerType = new TypeDefUser("TestApp", "ActivatorCaller", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var callMethod = new MethodDefUser("CreateDynamic", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Body = new CilBody() };
            var getTypeRef = new MemberRefUser(module, "GetType",
                MethodSig.CreateStatic(new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef).ToTypeSig(), module.CorLibTypes.String),
                new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef));
            var ldstrIns = Instruction.Create(OpCodes.Ldstr, "TestApp.Class123");
            callMethod.Body.Instructions.Add(ldstrIns);
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getTypeRef));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(callMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("InvoiceReportForm", formType.Name.String);
            Assert.Equal("TestApp.InvoiceReportForm", (string)ldstrIns.Operand);
        }

        [Fact]
        public void Execute_PublicTypeWithReflectionStringLiteral_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            // Public type with name referenced in generic string literal (e.g. config/serialization)
            var publicType = new TypeDefUser("TestApp", "Class555", module.CorLibTypes.Object.TypeDefOrRef);
            publicType.Attributes = TypeAttributes.Public;
            module.Types.Add(publicType);

            var initMethod = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            var setNameRef = new MemberRefUser(module, "set_Name",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                new TypeRefUser(module, "System.Windows.Forms", "Control", module.CorLibTypes.AssemblyRef));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "MismatchedForm"));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, setNameRef));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            publicType.Methods.Add(initMethod);

            // A string literal in another method loads "Class555" (e.g. for serialization/factory)
            var otherType = new TypeDefUser("TestApp", "Factory", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(otherType);
            var m = new MethodDefUser("GetModel", MethodSig.CreateStatic(module.CorLibTypes.String)) { Body = new CilBody() };
            m.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Class555"));
            m.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            otherType.Methods.Add(m);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Since Class555 is public and referenced by string literal in unknown context, it must be preserved
            Assert.Equal("Class555", publicType.Name.String);
            Assert.Contains(result.Decisions, d => d.OriginalName.Contains("Class555") && !d.Applied);
        }
    }
}

