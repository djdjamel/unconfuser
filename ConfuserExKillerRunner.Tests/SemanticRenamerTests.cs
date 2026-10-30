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
            var formType = new TypeDefUser("", "Class123", new TypeRefUser(module, "System.Windows.Forms", "Form", module.CorLibTypes.AssemblyRef));
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
            var formType = new TypeDefUser("TestApp", "Class123", new TypeRefUser(module, "System.Windows.Forms", "Form", module.CorLibTypes.AssemblyRef));
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
            var publicType = new TypeDefUser("TestApp", "Class555", new TypeRefUser(module, "System.Windows.Forms", "Form", module.CorLibTypes.AssemblyRef));
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

        #region C10 Comprehensive Test Matrix

        [Fact]
        public void C10_01_CompilerGenerated_AngleBracketNames_Preserved()
        {
            Assert.False(SemanticRenamer.IsMangledIdentifier("<>c"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("<>c__DisplayClass0_0"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("<Main>d__0"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("<CustomerName>k__BackingField"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("<PrivateImplementationDetails>"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("<>b__0_1"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("CS$<>8__locals1"));
        }

        [Fact]
        public void C10_02_CompilerGenerated_AsyncStateMachineClass_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var asyncType = new TypeDefUser("TestApp", "<DoWorkAsync>d__1", module.CorLibTypes.Object.TypeDefOrRef);
            asyncType.Attributes = TypeAttributes.NotPublic | TypeAttributes.BeforeFieldInit;
            module.Types.Add(asyncType);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("<DoWorkAsync>d__1", asyncType.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_03_CompilerGenerated_IteratorStateMachineClass_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var iterType = new TypeDefUser("TestApp", "<GetEnumerator>d__0", module.CorLibTypes.Object.TypeDefOrRef);
            iterType.Attributes = TypeAttributes.NotPublic | TypeAttributes.BeforeFieldInit;
            module.Types.Add(iterType);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("<GetEnumerator>d__0", iterType.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_04_CompilerGenerated_BackingFields_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var hostType = new TypeDefUser("TestApp", "CustomerModel", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(hostType);

            var backingField = new FieldDefUser("<Age>k__BackingField", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Private);
            hostType.Fields.Add(backingField);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("<Age>k__BackingField", backingField.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_05_APIProtection_PublicTypes_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var pubType = new TypeDefUser("TestApp", "\u200B\u200CPublicClass", module.CorLibTypes.Object.TypeDefOrRef);
            pubType.Attributes = TypeAttributes.Public;
            module.Types.Add(pubType);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CPublicClass", pubType.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_06_APIProtection_PublicMethods_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var hostType = new TypeDefUser("TestApp", "MyService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(hostType);

            var pubMethod = new MethodDefUser("\u200B\u200CDoPublicAction", MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodAttributes.Public | MethodAttributes.HideBySig);
            pubMethod.Body = new CilBody();
            pubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            hostType.Methods.Add(pubMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CDoPublicAction", pubMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_07_APIProtection_OverridesAndInterfaceImplementations_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var hostType = new TypeDefUser("TestApp", "Repository", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(hostType);

            // Method with explicit override
            var explicitMethod = new MethodDefUser("\u200B\u200CInterfaceMethod", MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodAttributes.Private | MethodAttributes.Final | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.HideBySig);
            explicitMethod.Body = new CilBody();
            explicitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var ifaceMethodRef = new MemberRefUser(module, "Save", MethodSig.CreateInstance(module.CorLibTypes.Void),
                new TypeRefUser(module, "TestApp", "IRepository", module.CorLibTypes.AssemblyRef));
            explicitMethod.Overrides.Add(new MethodOverride(explicitMethod, ifaceMethodRef));
            hostType.Methods.Add(explicitMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CInterfaceMethod", explicitMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_08_WinForms_LegitimateControlSetName_Renamed()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("TestApp", "Class101", new TypeRefUser(module, "System.Windows.Forms", "Form", module.CorLibTypes.AssemblyRef));
            module.Types.Add(formType);

            var initM = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            var setNameRef = new MemberRefUser(module, "set_Name",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                new TypeRefUser(module, "System.Windows.Forms", "Control", module.CorLibTypes.AssemblyRef));

            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "PurchaseOrderForm"));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, setNameRef));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            formType.Methods.Add(initM);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal(1, result.TypesRenamed);
            Assert.Equal("PurchaseOrderForm", formType.Name.String);
        }

        [Fact]
        public void C10_09_WinForms_OrdinaryClassWithSetName_NegativeTest_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            // Ordinary class deriving from Object, not a Form or Control!
            var personType = new TypeDefUser("TestApp", "Person", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(personType);

            var setPropMethod = new MethodDefUser("set_Name", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String))
            {
                Body = new CilBody()
            };
            setPropMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            personType.Methods.Add(setPropMethod);

            var initMethod = new MethodDefUser("Init", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "JohnDoe"));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, setPropMethod));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            personType.Methods.Add(initMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Person must NOT be renamed to JohnDoe!
            Assert.Equal("Person", personType.Name.String);
            Assert.Equal(0, result.TypesRenamed);
        }

        [Fact]
        public void C10_10_ReflectionProtection_TypeGetMethodWithBindingFlags_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var targetType = new TypeDefUser("TestApp", "WorkerService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(targetType);

            var secretMethod = new MethodDefUser("\u200B\u200CExecuteInternal", MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodAttributes.Private | MethodAttributes.HideBySig);
            secretMethod.Body = new CilBody();
            secretMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            targetType.Methods.Add(secretMethod);

            // Caller invokes typeof(WorkerService).GetMethod("\u200B\u200CExecuteInternal", BindingFlags.NonPublic | BindingFlags.Instance)
            var callerType = new TypeDefUser("TestApp", "Caller", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var callerMethod = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Body = new CilBody() };
            var getMethodRef = new MemberRefUser(module, "GetMethod",
                MethodSig.CreateInstance(new TypeRefUser(module, "System.Reflection", "MethodInfo", module.CorLibTypes.AssemblyRef).ToTypeSig(),
                    module.CorLibTypes.String, module.CorLibTypes.Int32),
                new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef));

            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetType));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200CExecuteInternal"));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)60)); // BindingFlags
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(callerMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CExecuteInternal", secretMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_11_ReflectionProtection_EnumParse_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var enumType = new TypeDefUser("TestApp", "UserRole", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(enumType);

            var adminField = new FieldDefUser("\u200B\u200CAdministrator", new FieldSig(module.CorLibTypes.Int32),
                FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal);
            enumType.Fields.Add(adminField);

            var callerType = new TypeDefUser("TestApp", "Parser", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var parseM = new MethodDefUser("ParseRole", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Body = new CilBody() };
            var enumParseRef = new MemberRefUser(module, "Parse",
                MethodSig.CreateStatic(module.CorLibTypes.Object,
                    new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef).ToTypeSig(),
                    module.CorLibTypes.String),
                new TypeRefUser(module, "System", "Enum", module.CorLibTypes.AssemblyRef));

            parseM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, enumType));
            parseM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200CAdministrator"));
            parseM.Body.Instructions.Add(Instruction.Create(OpCodes.Call, enumParseRef));
            parseM.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            parseM.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(parseM);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CAdministrator", adminField.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_12_ReflectionProtection_DataBindingsAdd_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var modelType = new TypeDefUser("TestApp", "CustomerInfo", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(modelType);

            var getter = new MethodDefUser("get_\u200B\u200CPostalCode", MethodSig.CreateInstance(module.CorLibTypes.String)) { Body = new CilBody() };
            getter.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            getter.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            modelType.Methods.Add(getter);
            var prop = new PropertyDefUser("\u200B\u200CPostalCode", new PropertySig(true, module.CorLibTypes.String)) { GetMethod = getter };
            modelType.Properties.Add(prop);

            var callerType = new TypeDefUser("TestApp", "FormBinding", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var bindM = new MethodDefUser("BindControls", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            var bindingsAddRef = new MemberRefUser(module, "Add",
                MethodSig.CreateInstance(module.CorLibTypes.Void,
                    module.CorLibTypes.String, module.CorLibTypes.Object, module.CorLibTypes.String),
                new TypeRefUser(module, "System.Windows.Forms", "ControlBindingsCollection", module.CorLibTypes.AssemblyRef));

            bindM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            bindM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Text"));
            bindM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            bindM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200CPostalCode"));
            bindM.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, bindingsAddRef));
            bindM.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(bindM);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CPostalCode", prop.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_13_ReflectionProtection_DynamicUnresolvedNames_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var dynType = new TypeDefUser("TestApp", "Class999", new TypeRefUser(module, "System.Windows.Forms", "Form", module.CorLibTypes.AssemblyRef));
            dynType.Attributes = TypeAttributes.Public;
            module.Types.Add(dynType);

            var initM = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            var setNameRef = new MemberRefUser(module, "set_Name",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                new TypeRefUser(module, "System.Windows.Forms", "Control", module.CorLibTypes.AssemblyRef));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "PluginWindow"));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, setNameRef));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            dynType.Methods.Add(initM);

            // App contains a string literal "Class999" without explicit Type.GetType (e.g. factory or dynamic lookup)
            var hostType = new TypeDefUser("TestApp", "Host", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(hostType);
            var m = new MethodDefUser("GetPluginName", MethodSig.CreateStatic(module.CorLibTypes.String)) { Body = new CilBody() };
            m.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Class999"));
            m.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            hostType.Methods.Add(m);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("Class999", dynType.Name.String);
            Assert.Contains(result.Decisions, d => d.Confidence == RenameConfidence.Ambiguous && !d.Applied);
        }

        [Fact]
        public void C10_14_ResourceDisambiguation_NoSubstringCollision_ExactMatch()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var userForm = new TypeDefUser("TestApp", "ClassUser", new TypeRefUser(module, "System.Windows.Forms", "Form", module.CorLibTypes.AssemblyRef));
            module.Types.Add(userForm);

            var initM = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            var setNameRef = new MemberRefUser(module, "set_Name",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                new TypeRefUser(module, "System.Windows.Forms", "Control", module.CorLibTypes.AssemblyRef));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "UserForm"));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, setNameRef));
            initM.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userForm.Methods.Add(initM);

            // Existing resource has substring "User" but belongs to UserProfileForm:
            // "TestApp.UserProfileForm.resources"
            var otherRes = new EmbeddedResource("TestApp.UserProfileForm.resources", new byte[] { 1, 2, 3 });
            module.Resources.Add(otherRes);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // otherRes must NOT be renamed to UserForm.resources on a substring match!
            Assert.Equal("TestApp.UserProfileForm.resources", otherRes.Name.String);
            Assert.Equal(0, result.ResourcesRenamed);
        }

        [Fact]
        public void C10_15_ResourceDisambiguation_AmbiguousResources_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("TestApp", "FormA", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(formType);
            formType.Fields.Add(new FieldDefUser("btn1", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private));

            byte[] b1;
            using (var ms = new MemoryStream())
            {
                using (var rw = new System.Resources.ResourceWriter(ms))
                {
                    rw.AddResource("btn1.Text", "OK");
                    rw.Generate();
                }
                b1 = ms.ToArray();
            }

            var r1 = new EmbeddedResource("mangled#1.resources", b1);
            var r2 = new EmbeddedResource("mangled#2.resources", b1);
            module.Resources.Add(r1);
            module.Resources.Add(r2);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("mangled#1.resources", r1.Name.String);
            Assert.Equal("mangled#2.resources", r2.Name.String);
            Assert.Contains(result.Decisions, d => d.Confidence == RenameConfidence.Ambiguous && !d.Applied);
        }

        [Fact]
        public void C10_16_Detection_ASCIIControlChars_Detected()
        {
            // ASCII control character \u0001 or \u001F
            string asciiMangled = "Test\u0001\u001FIdentifier";
            Assert.True(SemanticRenamer.IsMangledIdentifier(asciiMangled));
        }

        [Fact]
        public void C10_17_Detection_UnicodeZeroWidthAndFormatChars_Detected()
        {
            // Zero-width space \u200B and joiner \u200D
            string unicodeMangled = "\u200B\u200DSubRoutine";
            Assert.True(SemanticRenamer.IsMangledIdentifier(unicodeMangled));
        }

        [Fact]
        public void C10_18_Metrics_NormalizedSymbolsNotAnnouncedAsRestored()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var type = new TypeDefUser("TestApp", "SafeContainer", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            // Add private method with mangled unicode
            var m = new MethodDefUser("\u200B\u200CInternalHelper", MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodAttributes.Private | MethodAttributes.HideBySig);
            m.Body = new CilBody();
            m.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(m);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Normalized symbols MUST be in UnprintableNormalized, NOT MethodsRenamed (which represents semantic restoration)
            Assert.Equal(0, result.MethodsRenamed);
            Assert.True(result.UnprintableNormalized >= 1);
            Assert.Contains("0 methods", result.Message);
            Assert.Contains("normalized", result.Message);
        }

        [Fact]
        public void C10_19_MappingReport_GeneratesExportableEvidence()
        {
            var result = new SemanticRenamerResult
            {
                TypesRenamed = 1,
                UnprintableNormalized = 1
            };
            result.Decisions.Add(new RenameDecision
            {
                OriginalName = "Class123",
                NewName = "MainForm",
                SymbolType = "Type",
                Confidence = RenameConfidence.StrongReference,
                Justification = "Control.set_Name evidence",
                Applied = true
            });
            result.Decisions.Add(new RenameDecision
            {
                OriginalName = "PublicApiType",
                NewName = "PublicApiType",
                SymbolType = "Type",
                Confidence = RenameConfidence.Ambiguous,
                Justification = "Public API preserved",
                Applied = false
            });

            string report = result.GenerateMappingReport();

            Assert.Contains("SEMANTIC RENAMING MAPPING REPORT", report);
            Assert.Contains("[StrongReference]", report);
            Assert.Contains("MainForm", report);
            Assert.Contains("[Ambiguous]", report);
            Assert.Contains("Public API preserved", report);
        }

        [Fact]
        public void C10_20_APIProtection_PInvokeAndSerialization_Preserved()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var nativeHost = new TypeDefUser("TestApp", "NativeHost", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(nativeHost);

            // P/Invoke method
            var pinvokeMethod = new MethodDefUser("\u200B\u200CGetLastError", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodAttributes.Private | MethodAttributes.PinvokeImpl | MethodAttributes.HideBySig);
            nativeHost.Methods.Add(pinvokeMethod);

            // Field with DataMemberAttribute
            var serialField = new FieldDefUser("\u200B\u200CPayload", new FieldSig(module.CorLibTypes.String), FieldAttributes.Private);
            var dataMemberCtor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
                new TypeRefUser(module, "System.Runtime.Serialization", "DataMemberAttribute", module.CorLibTypes.AssemblyRef));
            serialField.CustomAttributes.Add(new CustomAttribute(dataMemberCtor));
            nativeHost.Fields.Add(serialField);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CGetLastError", pinvokeMethod.Name.String);
            Assert.Equal("\u200B\u200CPayload", serialField.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        public void C10_21_Detection_ConfuserExAsciiLetters_HighEntropy_Detected()
        {
            // ConfuserEx letters mode generates random sequences of letters with high entropy and consonant clusters
            Assert.True(SemanticRenamer.IsMangledIdentifier("kPxQtzLjW"));
            Assert.True(SemanticRenamer.IsMangledIdentifier("zXbVnQtr"));
            Assert.True(SemanticRenamer.IsMangledIdentifier("rTmWvKpx"));
            Assert.True(SemanticRenamer.IsMangledIdentifier("aBcDeFgHiJkL"));
        }

        [Fact]
        public void C10_22_Detection_ConfuserExMD5Hash_Detected()
        {
            // ConfuserEx hash mode produces 32-character hexadecimal MD5 hashes
            Assert.True(SemanticRenamer.IsMangledIdentifier("d41d8cd98f00b204e9800998ecf8427e"));
            Assert.True(SemanticRenamer.IsMangledIdentifier("5ebe2294ecd0e0f08eab7690d2a6ee69"));
        }

        [Fact]
        public void C10_23_Detection_ConfuserExDecodable_Detected()
        {
            // ConfuserEx decodable mode produces _0001, _00a4, etc.
            Assert.True(SemanticRenamer.IsMangledIdentifier("_0001"));
            Assert.True(SemanticRenamer.IsMangledIdentifier("_00a4f"));
        }

        [Fact]
        public void C10_24_Detection_LegitimateCodeIdentifiers_NotMangled()
        {
            // Legitimate business and framework code identifiers must NEVER be classified as mangled
            Assert.False(SemanticRenamer.IsMangledIdentifier("CustomerRepository"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("GetCustomerById"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("ComponentResourceManager"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("InitializeComponent"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("OnPropertyChanged"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("DataBindings"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("FormMain"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("ButtonSubmit"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("OrderProcessingService"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("ProcessCommandLineArguments"));
        }

        [Fact]
        public void C10_25_Detection_TechnicalAcronyms_NotMangled()
        {
            // Technical identifiers containing uppercase acronyms followed by words must NEVER be flagged as mangled
            Assert.False(SemanticRenamer.IsMangledIdentifier("HTMLParser"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("HTMLDocument"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("XMLHttpRequest"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("JSONSerializer"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("HTTPServer"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("UTF8Encoding"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("IOHelper"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("SQLStatement"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("WCFServiceClient"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("ColorRGB"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("RGBColor"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("AsyncCallback"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("XPathNavigator"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("GZipStream"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("RijndaelManaged"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("SHA256Managed"));
        }

        #endregion
    }
}

