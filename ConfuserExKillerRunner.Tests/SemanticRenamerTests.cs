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
            // Mandatory audit test cases: technical compound identifiers composed of multiple acronyms and domain words
            Assert.False(SemanticRenamer.IsMangledIdentifier("SctpRtpRtcpProcessor"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("SctpRtpRtcpHandler"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("SftpScpNtpBridge"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("SmtpTlsHandler"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("HTMLParser"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("CustomerRepository"));

            // Network and security handlers with consonant-rich acronym boundaries (e.g. Smtp + Tls + Handler)
            Assert.False(SemanticRenamer.IsMangledIdentifier("SmtpSslHandler"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("SmtpTlsClient"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("HttpTlsClient"));

            // Technical identifiers containing uppercase acronyms followed by words must NEVER be flagged as mangled
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

            // Additional representative technical/domain identifiers
            Assert.False(SemanticRenamer.IsMangledIdentifier("AesGcmEncryption"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("TcpIpStreamHandler"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("DbConnectionPool"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("JwtTokenValidator"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("DnsPacketParser"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("HmacSha256Provider"));
            Assert.False(SemanticRenamer.IsMangledIdentifier("SshSessionManager"));
        }

        [Fact]
        public void C10_26_Execute_PreservesLegitimateNamesAndNormalizesObfuscated()
        {
            var module = new ModuleDefUser("IntegrationApp.dll");

            // 1. Legitimate technical class with acronyms
            var smtpType = new TypeDefUser("MailApp.Network", "SmtpTlsHandler", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(smtpType);
            var sendMethod = new MethodDefUser("SendSecureMessage", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            sendMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            smtpType.Methods.Add(sendMethod);

            // 2. Legitimate technical compound classes with multiple acronyms
            var sctpProcessorType = new TypeDefUser("MailApp.Network", "SctpRtpRtcpProcessor", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(sctpProcessorType);

            var bridgeType = new TypeDefUser("MailApp.Bridge", "SftpScpNtpBridge", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(bridgeType);

            // 3. Legitimate acronym class
            var htmlType = new TypeDefUser("MailApp.Parsing", "HTMLParser", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(htmlType);

            // 4. Legitimate business class with fields and methods
            var repoType = new TypeDefUser("MailApp.Data", "CustomerRepository", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(repoType);

            var getCustMethod = new MethodDefUser("GetCustomerById", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Int32)) { Body = new CilBody() };
            getCustMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            getCustMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            repoType.Methods.Add(getCustMethod);

            var processMethod = new MethodDefUser("ProcessOrder", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            processMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            repoType.Methods.Add(processMethod);

            var colorField = new FieldDefUser("RGBColor", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Private);
            repoType.Fields.Add(colorField);

            var ioField = new FieldDefUser("IOHelper", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private);
            repoType.Fields.Add(ioField);

            // 5. Truly obfuscated members (unprintable and decodable ConfuserEx patterns)
            var unprintableType = new TypeDefUser("MailApp.Obfuscated", "\u200B\u200CType99", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(unprintableType);

            var unprintableMethod = new MethodDefUser("\u200D\u200EmethodSecret", MethodSig.CreateInstance(module.CorLibTypes.Void)) { Body = new CilBody() };
            unprintableMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            smtpType.Methods.Add(unprintableMethod);

            var decodableType = new TypeDefUser("MailApp.Obfuscated", "_0001", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(decodableType);

            var unprintableField = new FieldDefUser("\uFEFF\u200BsecretKey", new FieldSig(module.CorLibTypes.String), FieldAttributes.Private);
            repoType.Fields.Add(unprintableField);

            // 6. Random TitleCase consonant prefix with domain suffix (must be normalized)
            var pseudoLegitType = new TypeDefUser("MailApp.Obfuscated", "KpxQtzVrmProcessor", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(pseudoLegitType);

            // Execute SemanticRenamer pass
            var result = SemanticRenamer.Execute(module, verbose: false);

            // Verify legitimate names are 100% PRESERVED
            Assert.Equal("SmtpTlsHandler", smtpType.Name.String);
            Assert.Equal("SctpRtpRtcpProcessor", sctpProcessorType.Name.String);
            Assert.Equal("SftpScpNtpBridge", bridgeType.Name.String);
            Assert.Equal("SendSecureMessage", sendMethod.Name.String);
            Assert.Equal("HTMLParser", htmlType.Name.String);
            Assert.Equal("CustomerRepository", repoType.Name.String);
            Assert.Equal("GetCustomerById", getCustMethod.Name.String);
            Assert.Equal("ProcessOrder", processMethod.Name.String);
            Assert.Equal("RGBColor", colorField.Name.String);
            Assert.Equal("IOHelper", ioField.Name.String);

            // Verify truly mangled items WERE normalized
            Assert.NotEqual("\u200B\u200CType99", unprintableType.Name.String);
            Assert.NotEqual("\u200D\u200EmethodSecret", unprintableMethod.Name.String);
            Assert.NotEqual("_0001", decodableType.Name.String);
            Assert.NotEqual("\uFEFF\u200BsecretKey", unprintableField.Name.String);
            Assert.NotEqual("KpxQtzVrmProcessor", pseudoLegitType.Name.String);

            Assert.True(result.UnprintableNormalized >= 4);
        }

        [Theory]
        [InlineData("KPXProcessor", true)]
        [InlineData("QXZProcessor", true)]
        [InlineData("ZQXHandler", true)]
        [InlineData("KPXQTZVRMProcessor", true)]
        [InlineData("KPXQTZVRMHandler", true)]
        [InlineData("ABCDWXYZHandler", true)]
        [InlineData("HTMLParser", false)]
        [InlineData("HTTPServer", false)]
        [InlineData("XMLHttpRequest", false)]
        [InlineData("JSONSerializer", false)]
        [InlineData("UTF8Encoding", false)]
        [InlineData("SctpRtpRtcpProcessor", false)]
        [InlineData("SftpScpNtpBridge", false)]
        [InlineData("BgpMqttGateway", false)]
        [InlineData("AESGCMEncryption", false)]
        [InlineData("TCPUDPStreamHandler", false)]
        [InlineData("CustomerRepository", false)]
        [InlineData("RGBColor", false)]
        [InlineData("IOHelper", false)]
        [InlineData("AES256KeyGenerator", false)]
        [InlineData("IPv6AddressValidator", false)]
        [Trait("Category", "Unit")]
        public void C10_28_Detection_AllCapsRandomSequencesAndLegitimateAcronyms(string identifier, bool shouldBeMangled)
        {
            bool isMangled = SemanticRenamer.IsMangledIdentifier(identifier);
            Assert.Equal(shouldBeMangled, isMangled);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29A_ReflectionProtection_GetMethod_BindingFlags_Preserved()
        {
            var module = new ModuleDefUser("ReflectionBindingTest.dll");
            var serviceType = new TypeDefUser("MyApp.Services", "InternalService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(serviceType);

            // Private method with mangled name targeted via Type.GetMethod(string, BindingFlags)
            var targetMethod = new MethodDefUser("\u200B\u200CExecuteInternalAction", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Private)
            {
                Body = new CilBody()
            };
            targetMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            serviceType.Methods.Add(targetMethod);

            // Caller calling Type.GetMethod with BindingFlags.NonPublic | BindingFlags.Instance
            var callerType = new TypeDefUser("MyApp.Services", "Invoker", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var invokeMethod = new MethodDefUser("InvokePrivate", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var bindingFlagsRef = new TypeRefUser(module, "System.Reflection", "BindingFlags", module.CorLibTypes.AssemblyRef);
            var getMethodRef = new MemberRefUser(
                module,
                "GetMethod",
                MethodSig.CreateInstance(typeRef.ToTypeSig(), module.CorLibTypes.String, bindingFlagsRef.ToTypeSig()),
                typeRef);

            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, serviceType));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200CExecuteInternalAction"));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 36)); // NonPublic (32) | Instance (4)
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(invokeMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CExecuteInternalAction", targetMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29B_ReflectionProtection_GetMethod_TypeArrayOverload_Preserved()
        {
            var module = new ModuleDefUser("ReflectionTypeArrayTest.dll");
            var serviceType = new TypeDefUser("MyApp.Services", "CalculationService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(serviceType);

            var targetMethod = new MethodDefUser("\u200B\u200CComputeSum", MethodSig.CreateInstance(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32), MethodAttributes.Private)
            {
                Body = new CilBody()
            };
            targetMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            targetMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            serviceType.Methods.Add(targetMethod);

            // Caller calling Type.GetMethod("ComputeSum", new Type[] { typeof(int), typeof(int) })
            var callerType = new TypeDefUser("MyApp.Services", "Invoker", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var invokeMethod = new MethodDefUser("InvokeOverload", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var typeArrayRef = new SZArraySig(typeRef.ToTypeSig());
            var getMethodRef = new MemberRefUser(
                module,
                "GetMethod",
                MethodSig.CreateInstance(typeRef.ToTypeSig(), module.CorLibTypes.String, typeArrayRef),
                typeRef);

            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, serviceType));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200CComputeSum"));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Newarr, typeRef));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(invokeMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CComputeSum", targetMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29C_ReflectionProtection_GetProperty_GetField_GetEvent_Preserved()
        {
            var module = new ModuleDefUser("ReflectionMembersTest.dll");
            var targetType = new TypeDefUser("MyApp.Data", "EntityData", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(targetType);

            var field = new FieldDefUser("\u200B\u200C_entitySecret", new FieldSig(module.CorLibTypes.String), FieldAttributes.Private);
            targetType.Fields.Add(field);

            var callerType = new TypeDefUser("MyApp.Data", "Accessor", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var accessorMethod = new MethodDefUser("AccessField", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var fieldInfoRef = new TypeRefUser(module, "System.Reflection", "FieldInfo", module.CorLibTypes.AssemblyRef);
            var getFieldRef = new MemberRefUser(
                module,
                "GetField",
                MethodSig.CreateInstance(fieldInfoRef.ToTypeSig(), module.CorLibTypes.String),
                typeRef);

            accessorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetType));
            accessorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            accessorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200C_entitySecret"));
            accessorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getFieldRef));
            accessorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            accessorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(accessorMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200C_entitySecret", field.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29D_ReflectionProtection_StringConcatenation_Preserved()
        {
            var module = new ModuleDefUser("ConcatReflectionTest.dll");
            var serviceType = new TypeDefUser("MyApp.Services", "DataService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(serviceType);

            var targetMethod = new MethodDefUser("\u200B\u200CFetchPayload", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Private)
            {
                Body = new CilBody()
            };
            targetMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            serviceType.Methods.Add(targetMethod);

            var callerType = new TypeDefUser("MyApp.Services", "Caller", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var callMethod = new MethodDefUser("CallDynamic", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var stringRef = module.CorLibTypes.String.TypeDefOrRef;
            var concatRef = new MemberRefUser(
                module,
                "Concat",
                MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.String),
                stringRef);

            var getMethodRef = new MemberRefUser(
                module,
                "GetMethod",
                MethodSig.CreateInstance(typeRef.ToTypeSig(), module.CorLibTypes.String),
                typeRef);

            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, serviceType));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            // Concatenation: "\u200B\u200CFetch" + "Payload" -> "\u200B\u200CFetchPayload"
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200CFetch"));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Payload"));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, concatRef));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(callMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CFetchPayload", targetMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29E_ReflectionProtection_LocalVariable_Preserved()
        {
            var module = new ModuleDefUser("LocalVarReflectionTest.dll");
            var serviceType = new TypeDefUser("MyApp.Services", "ProcessorService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(serviceType);

            var targetMethod = new MethodDefUser("\u200B\u200CRunTask", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Private)
            {
                Body = new CilBody()
            };
            targetMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            serviceType.Methods.Add(targetMethod);

            var callerType = new TypeDefUser("MyApp.Services", "Caller", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var callMethod = new MethodDefUser("CallViaLocal", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            callMethod.Body.InitLocals = true;
            callMethod.Body.Variables.Add(new Local(module.CorLibTypes.String));

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var getMethodRef = new MemberRefUser(
                module,
                "GetMethod",
                MethodSig.CreateInstance(typeRef.ToTypeSig(), module.CorLibTypes.String),
                typeRef);

            // Store string in local 0, then load local 0 into GetMethod
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200CRunTask"));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, serviceType));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(callMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CRunTask", targetMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29F_ReflectionProtection_StaticField_Preserved()
        {
            var module = new ModuleDefUser("FieldConstantReflectionTest.dll");
            var serviceType = new TypeDefUser("MyApp.Services", "WorkerService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(serviceType);

            var targetMethod = new MethodDefUser("\u200B\u200CProcessBatch", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Private)
            {
                Body = new CilBody()
            };
            targetMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            serviceType.Methods.Add(targetMethod);

            var configType = new TypeDefUser("MyApp.Config", "ServiceConfig", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(configType);
            var constField = new FieldDefUser("TargetActionName", new FieldSig(module.CorLibTypes.String), FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal | FieldAttributes.HasDefault)
            {
                Constant = new ConstantUser("\u200B\u200CProcessBatch")
            };
            configType.Fields.Add(constField);

            var callerType = new TypeDefUser("MyApp.Services", "Caller", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var callMethod = new MethodDefUser("CallViaField", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var getMethodRef = new MemberRefUser(
                module,
                "GetMethod",
                MethodSig.CreateInstance(typeRef.ToTypeSig(), module.CorLibTypes.String),
                typeRef);

            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, serviceType));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, constField));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(callMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CProcessBatch", targetMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29G_ReflectionProtection_UnresolvableDynamicCase_PreservedConservatively()
        {
            var module = new ModuleDefUser("DynamicUnresolvableTest.dll");
            var dynamicTargetType = new TypeDefUser("MyApp.Dynamic", "\u200B\u200CDynamicService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(dynamicTargetType);

            var methodToPreserve = new MethodDefUser("\u200B\u200CUnknownMethod", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Private)
            {
                Body = new CilBody()
            };
            methodToPreserve.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            dynamicTargetType.Methods.Add(methodToPreserve);

            // A method calling Type.GetMethod with a parameter (completely dynamic, impossible to resolve statically)
            var callerMethod = new MethodDefUser("InvokeDynamically", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var getMethodRef = new MemberRefUser(
                module,
                "GetMethod",
                MethodSig.CreateInstance(typeRef.ToTypeSig(), module.CorLibTypes.String),
                typeRef);

            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, dynamicTargetType));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1)); // string method name passed as parameter!
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            dynamicTargetType.Methods.Add(callerMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Type with unresolvable dynamic reflection must have its symbols preserved conservatively
            Assert.Equal("\u200B\u200CUnknownMethod", methodToPreserve.Name.String);
            Assert.Contains(result.Decisions, d => d.Confidence == RenameConfidence.Ambiguous && d.Justification.Contains("unresolvable dynamic reflection"));
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29H_ReflectionProtection_CallerDistinctFromTarget_TargetPreserved()
        {
            var module = new ModuleDefUser("CallerTargetDistinctTest.dll");

            // Target type with mangled method
            var targetType = new TypeDefUser("MyApp.Domain", "TargetType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(targetType);

            var secretMethod = new MethodDefUser("\u200B\u200CSecretMethod", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Private)
            {
                Body = new CilBody()
            };
            secretMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            targetType.Methods.Add(secretMethod);

            // Caller type distinct from target type
            var callerType = new TypeDefUser("MyApp.Services", "CallerType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);

            // Caller method: void InvokeTarget(TargetType target, string dynamicName) -> target.GetType().GetMethod(dynamicName)
            var callerMethod = new MethodDefUser("InvokeTarget",
                MethodSig.CreateInstance(module.CorLibTypes.Void, targetType.ToTypeSig(), module.CorLibTypes.String))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var objectRef = module.CorLibTypes.Object.TypeDefOrRef;
            var objGetTypeRef = new MemberRefUser(
                module,
                "GetType",
                MethodSig.CreateInstance(typeRef.ToTypeSig()),
                objectRef);
            var getMethodRef = new MemberRefUser(
                module,
                "GetMethod",
                MethodSig.CreateInstance(typeRef.ToTypeSig(), module.CorLibTypes.String),
                typeRef);

            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, objGetTypeRef));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_2));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(callerMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // TargetType's secret method must remain intact
            Assert.Equal("\u200B\u200CSecretMethod", secretMethod.Name.String);

            // Decision for TargetType must be Ambiguous
            var targetDecision = result.Decisions.FirstOrDefault(d => d.OriginalName == targetType.FullName && d.Confidence == RenameConfidence.Ambiguous);
            Assert.NotNull(targetDecision);
            Assert.Contains("dynamic reflection", targetDecision.Justification, StringComparison.OrdinalIgnoreCase);

            // CallerType must not be falsely marked as containing unresolvable reflection
            Assert.DoesNotContain(result.Decisions, d => d.OriginalName == callerType.FullName && d.Confidence == RenameConfidence.Ambiguous);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29I_ReflectionProtection_UnrelatedLogString_ClassifiedAmbiguous()
        {
            var module = new ModuleDefUser("UnrelatedStringTest.dll");

            var targetType = new TypeDefUser("MyApp.Domain", "WorkerTarget", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(targetType);

            var targetMethod = new MethodDefUser("\u200B\u200CDoWork", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Private)
            {
                Body = new CilBody()
            };
            targetMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            targetType.Methods.Add(targetMethod);

            var callerType = new TypeDefUser("MyApp.Services", "WorkerInvoker", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);

            var invokeMethod = new MethodDefUser("InvokeWithLog",
                MethodSig.CreateInstance(module.CorLibTypes.Void, targetType.ToTypeSig(), module.CorLibTypes.String))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var getMethodRef = new MemberRefUser(
                module,
                "GetMethod",
                MethodSig.CreateInstance(typeRef.ToTypeSig(), module.CorLibTypes.String),
                typeRef);

            var logMethod = new MethodDefUser("LogMessage", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String))
            {
                Body = new CilBody()
            };
            logMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(logMethod);

            // 1. Unrelated string literal passed to diagnostic logger
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Diagnostics: preparing reflection dispatch"));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, logMethod));

            // 2. Dynamic reflection call using parameter dynamicName (ldarg.2)
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetType));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_2));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(invokeMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Scanner must NOT confuse the unrelated log string with the member name
            Assert.DoesNotContain("Diagnostics: preparing reflection dispatch", result.Decisions.Select(d => d.OriginalName));

            // Case must be classified as Ambiguous and target method preserved
            Assert.Equal("\u200B\u200CDoWork", targetMethod.Name.String);
            Assert.Contains(result.Decisions, d => d.Confidence == RenameConfidence.Ambiguous && d.Justification.Contains("dynamic reflection"));
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29J_ReflectionProtection_LocalVariable_MultipleAssignments_ClassifiedAmbiguous()
        {
            var module = new ModuleDefUser("MultiAssignLocalTest.dll");

            var targetType = new TypeDefUser("MyApp.Domain", "DynamicService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(targetType);

            var secretMethod = new MethodDefUser("\u200B\u200CExecuteTask", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Private)
            {
                Body = new CilBody()
            };
            secretMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            targetType.Methods.Add(secretMethod);

            var callerType = new TypeDefUser("MyApp.Services", "MultiAssignCaller", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);

            var callMethod = new MethodDefUser("CallMultiAssign", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Boolean))
            {
                Body = new CilBody { InitLocals = true }
            };
            callMethod.Body.Variables.Add(new Local(module.CorLibTypes.String));

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var getMethodRef = new MemberRefUser(
                module,
                "GetMethod",
                MethodSig.CreateInstance(typeRef.ToTypeSig(), module.CorLibTypes.String),
                typeRef);

            var branchTarget = Instruction.Create(OpCodes.Ldstr, "MethodB");
            var callBlock = Instruction.Create(OpCodes.Ldtoken, targetType);

            // if (arg0) name = "MethodA"; else name = "MethodB";
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Brfalse, branchTarget));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "MethodA"));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Br, callBlock));

            callMethod.Body.Instructions.Add(branchTarget);
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            callMethod.Body.Instructions.Add(callBlock);
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            callMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(callMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Scanner must detect multiple assignments to local and not resolve to a single constant
            Assert.Equal("\u200B\u200CExecuteTask", secretMethod.Name.String);
            Assert.Contains(result.Decisions, d => d.Confidence == RenameConfidence.Ambiguous && d.Justification.Contains("dynamic reflection"));
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29K_ReflectionProtection_GetEvent_Preserved()
        {
            var module = new ModuleDefUser("GetEventTest.dll");

            var targetType = new TypeDefUser("MyApp.Events", "EventPublisher", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(targetType);

            var eventHandlerType = new TypeRefUser(module, "System", "EventHandler", module.CorLibTypes.AssemblyRef);
            var targetEvent = new EventDefUser("\u200B\u200COnPayloadReceived", eventHandlerType);
            targetType.Events.Add(targetEvent);

            var callerType = new TypeDefUser("MyApp.Events", "EventSubscriber", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);

            var subMethod = new MethodDefUser("SubscribeDynamically", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var eventInfoRef = new TypeRefUser(module, "System.Reflection", "EventInfo", module.CorLibTypes.AssemblyRef);
            var getEventRef = new MemberRefUser(
                module,
                "GetEvent",
                MethodSig.CreateInstance(eventInfoRef.ToTypeSig(), module.CorLibTypes.String),
                typeRef);

            subMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetType));
            subMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            subMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200COnPayloadReceived"));
            subMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getEventRef));
            subMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            subMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(subMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Target event name must be preserved intact
            Assert.Equal("\u200B\u200COnPayloadReceived", targetEvent.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29L_ExtensibleTypeReflection_DerivedClassPreserved()
        {
            var module = new ModuleDefUser("DerivedClassTest.dll");

            // BaseService (extensible class)
            var baseServiceType = new TypeDefUser("MyApp.Services", "BaseService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(baseServiceType);

            // InternalService : BaseService with mangled private method
            var internalServiceType = new TypeDefUser("MyApp.Services", "InternalService", baseServiceType);
            module.Types.Add(internalServiceType);
            var secretMethod = new MethodDefUser("\u200B\u200CSecretMethod", MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            secretMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            internalServiceType.Methods.Add(secretMethod);

            // CallerService with Invoke(BaseService service, string dynamicName)
            var callerType = new TypeDefUser("MyApp.Services", "CallerService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var invokeMethod = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void, baseServiceType.ToTypeSig(), module.CorLibTypes.String))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var objRef = new TypeRefUser(module, "System", "Object", module.CorLibTypes.AssemblyRef);
            var methodInfoRef = new TypeRefUser(module, "System.Reflection", "MethodInfo", module.CorLibTypes.AssemblyRef);
            var getTypeRef = new MemberRefUser(module, "GetType", MethodSig.CreateInstance(typeRef.ToTypeSig()), objRef);
            var getMethodRef = new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(methodInfoRef.ToTypeSig(), module.CorLibTypes.String), typeRef);

            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1)); // service (BaseService)
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getTypeRef)); // service.GetType()
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_2)); // dynamicName
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef)); // .GetMethod(dynamicName)
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(invokeMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Derived class method must remain intact because BaseService was extensible and targeted by reflection
            Assert.Equal("\u200B\u200CSecretMethod", secretMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29M_ExtensibleTypeReflection_InterfaceImplementationPreserved()
        {
            var module = new ModuleDefUser("InterfaceTest.dll");

            // IService interface
            var iServiceType = new TypeDefUser("MyApp.Services", "IService", null)
            {
                Attributes = TypeAttributes.NotPublic | TypeAttributes.Interface | TypeAttributes.Abstract
            };
            module.Types.Add(iServiceType);

            // InternalService implementing IService
            var internalServiceType = new TypeDefUser("MyApp.Services", "InternalService", module.CorLibTypes.Object.TypeDefOrRef);
            internalServiceType.Interfaces.Add(new InterfaceImplUser(iServiceType));
            module.Types.Add(internalServiceType);
            var internalMethod = new MethodDefUser("\u200B\u200CExecuteInternal", MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            internalMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            internalServiceType.Methods.Add(internalMethod);

            // CallerService with Invoke(IService service, string dynamicName)
            var callerType = new TypeDefUser("MyApp.Services", "CallerService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var invokeMethod = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void, iServiceType.ToTypeSig(), module.CorLibTypes.String))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var objRef = new TypeRefUser(module, "System", "Object", module.CorLibTypes.AssemblyRef);
            var methodInfoRef = new TypeRefUser(module, "System.Reflection", "MethodInfo", module.CorLibTypes.AssemblyRef);
            var getTypeRef = new MemberRefUser(module, "GetType", MethodSig.CreateInstance(typeRef.ToTypeSig()), objRef);
            var getMethodRef = new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(methodInfoRef.ToTypeSig(), module.CorLibTypes.String), typeRef);

            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1)); // service (IService)
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getTypeRef)); // service.GetType()
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_2)); // dynamicName
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef)); // .GetMethod(dynamicName)
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(invokeMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Concrete implementation method must remain intact
            Assert.Equal("\u200B\u200CExecuteInternal", internalMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29N_ExtensibleTypeReflection_AbstractBaseClassPreserved()
        {
            var module = new ModuleDefUser("AbstractClassTest.dll");

            // AbstractService
            var abstractServiceType = new TypeDefUser("MyApp.Services", "AbstractService", module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NotPublic | TypeAttributes.Abstract
            };
            module.Types.Add(abstractServiceType);

            // InternalService : AbstractService
            var internalServiceType = new TypeDefUser("MyApp.Services", "InternalService", abstractServiceType);
            module.Types.Add(internalServiceType);
            var handleMethod = new MethodDefUser("\u200B\u200CHandleAction", MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            handleMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            internalServiceType.Methods.Add(handleMethod);

            // CallerService with Invoke(AbstractService service, string dynamicName)
            var callerType = new TypeDefUser("MyApp.Services", "CallerService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var invokeMethod = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void, abstractServiceType.ToTypeSig(), module.CorLibTypes.String))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var objRef = new TypeRefUser(module, "System", "Object", module.CorLibTypes.AssemblyRef);
            var methodInfoRef = new TypeRefUser(module, "System.Reflection", "MethodInfo", module.CorLibTypes.AssemblyRef);
            var getTypeRef = new MemberRefUser(module, "GetType", MethodSig.CreateInstance(typeRef.ToTypeSig()), objRef);
            var getMethodRef = new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(methodInfoRef.ToTypeSig(), module.CorLibTypes.String), typeRef);

            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1)); // service (AbstractService)
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getTypeRef)); // service.GetType()
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_2)); // dynamicName
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef)); // .GetMethod(dynamicName)
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(invokeMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // Concrete implementation method must remain intact
            Assert.Equal("\u200B\u200CHandleAction", handleMethod.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_29O_ExactTypeReflection_SealedOrNewobjPreservedWithoutOverprotection()
        {
            var module = new ModuleDefUser("ExactClassTest.dll");

            // Sealed TargetService
            var targetServiceType = new TypeDefUser("MyApp.Services", "TargetService", module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed
            };
            module.Types.Add(targetServiceType);
            var exactMethod = new MethodDefUser("\u200B\u200CExactMethod", MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            exactMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            targetServiceType.Methods.Add(exactMethod);

            // UnrelatedService (unrelated internal class with mangled method)
            var unrelatedServiceType = new TypeDefUser("MyApp.Services", "UnrelatedService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(unrelatedServiceType);
            var unrelatedMethod = new MethodDefUser("\u200B\u200CUnrelatedMethod", MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            unrelatedMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            unrelatedServiceType.Methods.Add(unrelatedMethod);

            // CallerService with typeof(TargetService).GetMethod(dynamicName)
            var callerType = new TypeDefUser("MyApp.Services", "CallerService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(callerType);
            var invokeMethod = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String))
            {
                Body = new CilBody()
            };

            var typeRef = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var methodInfoRef = new TypeRefUser(module, "System.Reflection", "MethodInfo", module.CorLibTypes.AssemblyRef);
            var getMethodRef = new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(methodInfoRef.ToTypeSig(), module.CorLibTypes.String), typeRef);

            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetServiceType));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(typeRef.ToTypeSig(), new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()), typeRef)));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1)); // dynamicName
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getMethodRef));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            invokeMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            callerType.Methods.Add(invokeMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            // TargetService is provably exact: its method is protected
            Assert.Equal("\u200B\u200CExactMethod", exactMethod.Name.String);

            // UnrelatedService is NOT protected: its unprintable method was normalized safely
            Assert.StartsWith("Method_", unrelatedMethod.Name.String);
            Assert.True(result.UnprintableNormalized >= 1);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_30_ReflectionProtection_PropertyChanged_Preserved()
        {
            var module = new ModuleDefUser("NotifyTest.dll");
            var viewModelType = new TypeDefUser("MyApp.ViewModels", "CustomerViewModel", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(viewModelType);

            var prop = new PropertyDefUser("\u200B\u200CCustomerBalance", new PropertySig(true, module.CorLibTypes.Int32));
            viewModelType.Properties.Add(prop);

            var notifyMethod = new MethodDefUser("OnPropertyChanged", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String))
            {
                Body = new CilBody()
            };
            notifyMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            viewModelType.Methods.Add(notifyMethod);

            var setterMethod = new MethodDefUser("set_CustomerBalance", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            setterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            setterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "\u200B\u200CCustomerBalance"));
            setterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, notifyMethod));
            setterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            viewModelType.Methods.Add(setterMethod);

            var result = SemanticRenamer.Execute(module, verbose: false);

            Assert.Equal("\u200B\u200CCustomerBalance", prop.Name.String);
            Assert.Equal(0, result.UnprintableNormalized);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_31_GenericWinForms_VisualControlsVsNonVisualComponents()
        {
            var module = new ModuleDefUser("WinFormsVisualVsNonVisualTest.dll");

            // --- POSITIVE CASES (True visual controls and forms) ---

            // 1. Class inheriting System.Windows.Forms.Control
            var customControlType = new TypeDefUser("Custom.UI", "MyGridControl",
                new TypeRefUser(module, "System.Windows.Forms", "Control", module.CorLibTypes.AssemblyRef));
            module.Types.Add(customControlType);
            Assert.True(SemanticRenamer.IsWinFormsControlOrForm(customControlType));

            // 2. Class inheriting System.Windows.Forms.UserControl
            var userControlType = new TypeDefUser("Custom.UI", "UserEditor",
                new TypeRefUser(module, "System.Windows.Forms", "UserControl", module.CorLibTypes.AssemblyRef));
            module.Types.Add(userControlType);
            Assert.True(SemanticRenamer.IsWinFormsControlOrForm(userControlType));

            // 3. Class inheriting System.Windows.Forms.Form
            var customFormType = new TypeDefUser("Custom.Views", "MainDashboardForm",
                new TypeRefUser(module, "System.Windows.Forms", "Form", module.CorLibTypes.AssemblyRef));
            module.Types.Add(customFormType);
            Assert.True(SemanticRenamer.IsWinFormsControlOrForm(customFormType));

            // Control name setter on true visual control
            var setControlName = new MethodDefUser("set_Name", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String));
            customControlType.Methods.Add(setControlName);
            Assert.True(SemanticRenamer.IsControlSetName(setControlName));

            // --- NEGATIVE CASES (Non-visual components and arbitrary business classes) ---

            // 4. Non-visual class deriving from System.ComponentModel.Component (e.g. Timer, BackgroundWorker)
            var nonVisualComponentType = new TypeDefUser("Custom.Services", "DataWorkerComponent",
                new TypeRefUser(module, "System.ComponentModel", "Component", module.CorLibTypes.AssemblyRef));
            module.Types.Add(nonVisualComponentType);
            Assert.False(SemanticRenamer.IsWinFormsControlOrForm(nonVisualComponentType),
                "Non-visual Component must NOT be classified as a WinForms visual control.");

            // 5. Class implementing IComponent without visual inheritance
            var iComponentServiceType = new TypeDefUser("Custom.Services", "ServiceManager", module.CorLibTypes.Object.TypeDefOrRef);
            iComponentServiceType.Interfaces.Add(new InterfaceImplUser(new TypeRefUser(module, "System.ComponentModel", "IComponent", module.CorLibTypes.AssemblyRef)));
            module.Types.Add(iComponentServiceType);
            Assert.False(SemanticRenamer.IsWinFormsControlOrForm(iComponentServiceType),
                "Class implementing IComponent must NOT be classified as a WinForms visual control.");

            // 6. Business classes whose names end in Item, Bar, Form, Control but have no relation to WinForms
            var orderItemType = new TypeDefUser("Business.Orders", "OrderItem", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(orderItemType);
            Assert.False(SemanticRenamer.IsWinFormsControlOrForm(orderItemType));

            var progressBarBizType = new TypeDefUser("Business.Processing", "ProcessProgressBar", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(progressBarBizType);
            Assert.False(SemanticRenamer.IsWinFormsControlOrForm(progressBarBizType));

            var taxFormType = new TypeDefUser("Business.Finance", "TaxFormReport", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(taxFormType);
            Assert.False(SemanticRenamer.IsWinFormsControlOrForm(taxFormType));

            var accessControlType = new TypeDefUser("Business.Security", "AccessControlPolicy", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(accessControlType);
            Assert.False(SemanticRenamer.IsWinFormsControlOrForm(accessControlType));

            // Non-control set_Name method must NOT be recognized as a WinForms control setter
            var bizSetName = new MethodDefUser("set_Name", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String));
            orderItemType.Methods.Add(bizSetName);
            Assert.False(SemanticRenamer.IsControlSetName(bizSetName));
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_32_EmpiricalFalsePositiveRate_RealCorpusEvaluation()
        {
            string repoRoot = TestPathHelper.GetRepositoryRoot();

            // 1. Pinned Reference Manifest with expected SHA-256 hashes
            var pinnedManifest = new (string Name, string Version, string RelativePath, string ExpectedSha256, string Provenance)[]
            {
                ("dnlib.dll", "1.6.0.0", "ConfuserExKillerRunner/dnlib.dll", "1b9e108e458c30655f98bb681bc6162b39c08e781264f2181e18be297d7b22d2", "Pinned third-party metadata library"),
                ("de4dot.blocks.dll", "3.1.41592.3405", "ConfuserExKillerRunner/de4dot.blocks.dll", "ba197b4b6a19ce6242256639a3f641575c77108a07d5fcd3ac13f1d38bfcf98f", "Pinned third-party deobfuscation library")
            };

            // 2. Dynamic compilation and runtime reference assemblies
            var dynamicSources = new (string Name, string Version, string FilePath, string LogicalPath, string Category, string Provenance)[]
            {
                ("ConfuserExKillerRunner.dll", typeof(SemanticRenamer).Assembly.GetName().Version?.ToString() ?? "1.0.0.0", typeof(SemanticRenamer).Assembly.Location, "ConfuserExKillerRunner/bin/Release/net8.0-windows/ConfuserExKillerRunner.dll", "DynamicCompilation", "Unconfuser deobfuscation engine runner"),
                ("System.Private.CoreLib.dll", typeof(object).Assembly.GetName().Version?.ToString() ?? "8.0.0.0", typeof(object).Assembly.Location, "runtime/System.Private.CoreLib.dll", "RuntimeCoreLib", "Microsoft .NET 8.0 CoreCLR Reference BCL")
            };

            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var assemblyMetadataList = new List<object>();

            // Distinct textual names (metric 1)
            var allTextualNames = new HashSet<string>(StringComparer.Ordinal);
            var publicTextualNames = new HashSet<string>(StringComparer.Ordinal);
            var nonPublicTextualNames = new HashSet<string>(StringComparer.Ordinal);

            // Distinct metadata symbols (metric 2)
            var allSymbols = new Dictionary<string, (string Assembly, string Type, string Kind, string Name, bool IsPublic)>(StringComparer.Ordinal);
            int rawMetadataOccurrences = 0;
            int collisionCount = 0;
            var collisions = new List<string>();

            void AddMetadataSymbol(string key, string asm, string type, string kind, string name, bool isPublic)
            {
                rawMetadataOccurrences++;
                if (allSymbols.ContainsKey(key))
                {
                    collisionCount++;
                    collisions.Add(key);
                    return; // Explicitly reject collision: never overwrite and never count as unique
                }
                allSymbols.Add(key, (asm, type, kind, name, isPublic));
            }

            static bool IsTypeEffectivelyPublic(TypeDef type)
            {
                if (type == null) return false;
                var curr = type;
                while (curr.IsNested)
                {
                    if (!curr.IsNestedPublic)
                        return false;
                    curr = curr.DeclaringType;
                    if (curr == null) return false;
                }
                return curr.IsPublic;
            }

            // Process pinned assemblies first and assert exact hash verification
            foreach (var pinned in pinnedManifest)
            {
                string fullPath = Path.Combine(repoRoot, pinned.RelativePath.Replace('/', Path.DirectorySeparatorChar));
                Assert.True(File.Exists(fullPath), $"Pinned reference assembly not found: {pinned.RelativePath}");

                byte[] fileBytes = File.ReadAllBytes(fullPath);
                string actualHash = BitConverter.ToString(sha256.ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant();

                // Assert: fail if pinned assembly hash does not match expected cryptographic hash
                Assert.Equal(pinned.ExpectedSha256, actualHash);

                assemblyMetadataList.Add(new
                {
                    Name = pinned.Name,
                    Version = pinned.Version,
                    LogicalPath = pinned.RelativePath,
                    Category = "PinnedReference",
                    Sha256 = actualHash,
                    Sha256Verified = true,
                    Provenance = pinned.Provenance,
                    SizeBytes = fileBytes.Length
                });

                IndexAssemblySymbols(fileBytes, pinned.Name);
            }

            // Process dynamic compilation and runtime assemblies
            foreach (var dyn in dynamicSources)
            {
                Assert.True(File.Exists(dyn.FilePath), $"Mandatory dynamic source assembly not found: {dyn.FilePath}");

                byte[] fileBytes = File.ReadAllBytes(dyn.FilePath);
                string actualHash = BitConverter.ToString(sha256.ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant();

                assemblyMetadataList.Add(new
                {
                    Name = dyn.Name,
                    Version = dyn.Version,
                    LogicalPath = dyn.LogicalPath,
                    Category = dyn.Category,
                    Sha256 = actualHash,
                    Sha256Verified = (bool?)null,
                    Provenance = dyn.Provenance,
                    SizeBytes = fileBytes.Length
                });

                IndexAssemblySymbols(fileBytes, dyn.Name);
            }

            void IndexAssemblySymbols(byte[] bytes, string asmName)
            {
                var mod = ModuleDefMD.Load(bytes);
                foreach (var t in mod.GetTypes())
                {
                    if (string.IsNullOrEmpty(t.Name) || SemanticRenamer.IsCompilerGeneratedIdentifier(t.Name))
                        continue;

                    bool isTypePublic = IsTypeEffectivelyPublic(t);

                    allTextualNames.Add(t.Name.String);
                    if (isTypePublic) publicTextualNames.Add(t.Name.String); else nonPublicTextualNames.Add(t.Name.String);

                    string typeKind = t.IsInterface ? "Interface" : (t.IsEnum ? "Enum" : (t.IsValueType ? "Struct" : "Class"));
                    string typeKey = $"{asmName}!{t.FullName}::Type:{typeKind}:{t.Name.String}";
                    AddMetadataSymbol(typeKey, asmName, t.FullName, "Type", t.Name.String, isTypePublic);

                    foreach (var m in t.Methods)
                    {
                        if (string.IsNullOrEmpty(m.Name) || SemanticRenamer.IsCompilerGeneratedIdentifier(m.Name) || m.IsSpecialName)
                            continue;

                        bool isMethodPublic = (m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly) && isTypePublic;

                        allTextualNames.Add(m.Name.String);
                        if (isMethodPublic) publicTextualNames.Add(m.Name.String); else nonPublicTextualNames.Add(m.Name.String);

                        string mSig = m.MethodSig?.ToString() ?? "";
                        string methodKey = $"{asmName}!{t.FullName}::Method:{m.Name.String}({mSig})";
                        AddMetadataSymbol(methodKey, asmName, t.FullName, "Method", m.Name.String, isMethodPublic);

                        foreach (var p in m.Parameters)
                        {
                            if (!string.IsNullOrEmpty(p.Name) && !SemanticRenamer.IsCompilerGeneratedIdentifier(p.Name))
                            {
                                allTextualNames.Add(p.Name);
                                string pType = p.Type?.ToString() ?? "";
                                string paramKey = $"{asmName}!{t.FullName}::{m.Name.String}({mSig}):Param[{p.Index}]:{pType}:{p.Name}";
                                AddMetadataSymbol(paramKey, asmName, t.FullName, "Parameter", p.Name, isMethodPublic);
                            }
                        }
                    }

                    foreach (var f in t.Fields)
                    {
                        if (string.IsNullOrEmpty(f.Name) || SemanticRenamer.IsCompilerGeneratedIdentifier(f.Name) || f.IsSpecialName)
                            continue;

                        // Classify field by its true metadata visibility
                        bool isFieldPublic = (f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly) && isTypePublic;

                        allTextualNames.Add(f.Name.String);
                        if (isFieldPublic) publicTextualNames.Add(f.Name.String); else nonPublicTextualNames.Add(f.Name.String);

                        string fSig = f.FieldSig?.Type?.ToString() ?? f.FieldSig?.ToString() ?? "";
                        string fieldKey = $"{asmName}!{t.FullName}::Field:{f.Name.String}:{fSig}";
                        AddMetadataSymbol(fieldKey, asmName, t.FullName, "Field", f.Name.String, isFieldPublic);
                    }

                    foreach (var prop in t.Properties)
                    {
                        if (string.IsNullOrEmpty(prop.Name) || SemanticRenamer.IsCompilerGeneratedIdentifier(prop.Name))
                            continue;

                        // Classify property by its getter/setter visibility (Public, Family, FamilyOrAssembly; excludes FamilyAndAssembly)
                        bool isPropPublic = ((prop.GetMethod != null && (prop.GetMethod.IsPublic || prop.GetMethod.IsFamily || prop.GetMethod.IsFamilyOrAssembly)) ||
                                             (prop.SetMethod != null && (prop.SetMethod.IsPublic || prop.SetMethod.IsFamily || prop.SetMethod.IsFamilyOrAssembly))) && isTypePublic;

                        allTextualNames.Add(prop.Name.String);
                        if (isPropPublic) publicTextualNames.Add(prop.Name.String); else nonPublicTextualNames.Add(prop.Name.String);

                        string propSig = prop.PropertySig?.ToString() ?? "";
                        string propKey = $"{asmName}!{t.FullName}::Property:{prop.Name.String}({propSig})";
                        AddMetadataSymbol(propKey, asmName, t.FullName, "Property", prop.Name.String, isPropPublic);
                    }

                    foreach (var ev in t.Events)
                    {
                        if (string.IsNullOrEmpty(ev.Name) || SemanticRenamer.IsCompilerGeneratedIdentifier(ev.Name))
                            continue;

                        // Classify event by its add/remove method visibility (Public, Family, FamilyOrAssembly; excludes FamilyAndAssembly)
                        bool isEventPublic = ((ev.AddMethod != null && (ev.AddMethod.IsPublic || ev.AddMethod.IsFamily || ev.AddMethod.IsFamilyOrAssembly)) ||
                                              (ev.RemoveMethod != null && (ev.RemoveMethod.IsPublic || ev.RemoveMethod.IsFamily || ev.RemoveMethod.IsFamilyOrAssembly))) && isTypePublic;

                        allTextualNames.Add(ev.Name.String);
                        if (isEventPublic) publicTextualNames.Add(ev.Name.String); else nonPublicTextualNames.Add(ev.Name.String);

                        string evType = ev.EventType?.FullName ?? "";
                        string eventKey = $"{asmName}!{t.FullName}::Event:{ev.Name.String}:{evType}";
                        AddMetadataSymbol(eventKey, asmName, t.FullName, "Event", ev.Name.String, isEventPublic);
                    }
                }
            }

            // Breakdown calculated strictly from genuinely unique symbols
            int uniquePublicTypes = allSymbols.Values.Count(s => s.Kind == "Type" && s.IsPublic);
            int uniqueNonPublicTypes = allSymbols.Values.Count(s => s.Kind == "Type" && !s.IsPublic);

            int uniquePublicMethods = allSymbols.Values.Count(s => s.Kind == "Method" && s.IsPublic);
            int uniqueNonPublicMethods = allSymbols.Values.Count(s => s.Kind == "Method" && !s.IsPublic);

            int uniquePublicFields = allSymbols.Values.Count(s => s.Kind == "Field" && s.IsPublic);
            int uniqueNonPublicFields = allSymbols.Values.Count(s => s.Kind == "Field" && !s.IsPublic);

            int uniquePublicProps = allSymbols.Values.Count(s => s.Kind == "Property" && s.IsPublic);
            int uniqueNonPublicProps = allSymbols.Values.Count(s => s.Kind == "Property" && !s.IsPublic);

            int uniquePublicEvents = allSymbols.Values.Count(s => s.Kind == "Event" && s.IsPublic);
            int uniqueNonPublicEvents = allSymbols.Values.Count(s => s.Kind == "Event" && !s.IsPublic);

            int uniquePublicParams = allSymbols.Values.Count(s => s.Kind == "Parameter" && s.IsPublic);
            int uniqueNonPublicParams = allSymbols.Values.Count(s => s.Kind == "Parameter" && !s.IsPublic);

            int totalUniqueCategoriesSum = uniquePublicTypes + uniqueNonPublicTypes +
                                           uniquePublicMethods + uniqueNonPublicMethods +
                                           uniquePublicFields + uniqueNonPublicFields +
                                           uniquePublicProps + uniqueNonPublicProps +
                                           uniquePublicEvents + uniqueNonPublicEvents +
                                           uniquePublicParams + uniqueNonPublicParams;

            // Mandatory assertions:
            // 1. Strict equality: total unique metadata symbols equals sum of all unique categories
            Assert.Equal(allSymbols.Count, totalUniqueCategoriesSum);

            // 2. Strict ZERO silent collisions on complete metadata identities across the reference corpus
            Assert.Equal(0, collisionCount);

            // Assert corpus scale: distinct metadata symbols >= 15000 and distinct textual names >= 15000
            Assert.True(allSymbols.Count >= 15000, $"Metadata symbols corpus size too small: {allSymbols.Count}");
            Assert.True(allTextualNames.Count >= 15000, $"Textual names corpus size too small: {allTextualNames.Count}");

            // 1. Textual names metrics
            var allFlaggedNames = allTextualNames.Where(id => SemanticRenamer.IsMangledIdentifier(id)).ToList();
            var publicFlaggedNames = publicTextualNames.Where(id => SemanticRenamer.IsMangledIdentifier(id)).ToList();
            var nonPublicFlaggedNames = nonPublicTextualNames.Where(id => SemanticRenamer.IsMangledIdentifier(id)).ToList();

            double allNamesFpRate = (double)allFlaggedNames.Count / allTextualNames.Count;
            double publicNamesFpRate = publicTextualNames.Count > 0 ? (double)publicFlaggedNames.Count / publicTextualNames.Count : 0.0;
            double nonPublicNamesFpRate = nonPublicTextualNames.Count > 0 ? (double)nonPublicFlaggedNames.Count / nonPublicTextualNames.Count : 0.0;

            // 2. Metadata symbols metrics
            var publicSymbols = allSymbols.Values.Where(s => s.IsPublic).ToList();
            var nonPublicSymbols = allSymbols.Values.Where(s => !s.IsPublic).ToList();

            var allFlaggedSymbols = allSymbols.Where(kvp => SemanticRenamer.IsMangledIdentifier(kvp.Value.Name)).ToList();
            var publicFlaggedSymbols = publicSymbols.Where(s => SemanticRenamer.IsMangledIdentifier(s.Name)).ToList();
            var nonPublicFlaggedSymbols = nonPublicSymbols.Where(s => SemanticRenamer.IsMangledIdentifier(s.Name)).ToList();

            double allSymbolsFpRate = (double)allFlaggedSymbols.Count / allSymbols.Count;
            double publicSymbolsFpRate = publicSymbols.Count > 0 ? (double)publicFlaggedSymbols.Count / publicSymbols.Count : 0.0;
            double nonPublicSymbolsFpRate = nonPublicSymbols.Count > 0 ? (double)nonPublicFlaggedSymbols.Count / nonPublicSymbols.Count : 0.0;

            // Generate clean, neutral JSON evaluation report artifact
            var reportData = new
            {
                EvaluationDate = DateTime.UtcNow.ToString("o"),
                ManifestVerification = new
                {
                    PinnedAssembliesVerified = true,
                    PinnedAssembliesCount = pinnedManifest.Length
                },
                SourceAssemblies = assemblyMetadataList,
                TextualNameMetrics = new
                {
                    TotalUniqueNames = allTextualNames.Count,
                    PublicNamesCount = publicTextualNames.Count,
                    NonPublicNamesCount = nonPublicTextualNames.Count,
                    AllNamesFalsePositiveCount = allFlaggedNames.Count,
                    AllNamesFalsePositiveRate = allNamesFpRate,
                    PublicFalsePositiveCount = publicFlaggedNames.Count,
                    PublicFalsePositiveRate = publicNamesFpRate,
                    NonPublicFalsePositiveCount = nonPublicFlaggedNames.Count,
                    NonPublicFalsePositiveRate = nonPublicNamesFpRate
                },
                MetadataSymbolMetrics = new
                {
                    ScopeDescription = "Analyzed eligible metadata symbols (excluding compiler-generated members, anonymous parameters, and runtime special names; not the raw entirety of ECMA-335 tables)",
                    TotalEligibleMetadataSymbols = allSymbols.Count,
                    TotalMetadataSymbols = allSymbols.Count,
                    RawOccurrences = rawMetadataOccurrences,
                    CollisionCount = collisionCount,
                    PublicSymbolsCount = publicSymbols.Count,
                    NonPublicSymbolsCount = nonPublicSymbols.Count,
                    AllSymbolsFalsePositiveCount = allFlaggedSymbols.Count,
                    AllSymbolsFalsePositiveRate = allSymbolsFpRate,
                    PublicFalsePositiveCount = publicFlaggedSymbols.Count,
                    PublicFalsePositiveRate = publicSymbolsFpRate,
                    NonPublicFalsePositiveCount = nonPublicFlaggedSymbols.Count,
                    NonPublicFalsePositiveRate = nonPublicSymbolsFpRate
                },
                SymbolBreakdown = new
                {
                    Public = new
                    {
                        Types = uniquePublicTypes,
                        Methods = uniquePublicMethods,
                        Fields = uniquePublicFields,
                        Properties = uniquePublicProps,
                        Events = uniquePublicEvents,
                        Parameters = uniquePublicParams
                    },
                    NonPublic = new
                    {
                        Types = uniqueNonPublicTypes,
                        Methods = uniqueNonPublicMethods,
                        Fields = uniqueNonPublicFields,
                        Properties = uniqueNonPublicProps,
                        Events = uniqueNonPublicEvents,
                        Parameters = uniqueNonPublicParams
                    },
                    TotalUniqueSymbols = allSymbols.Count,
                    SumOfCategories = totalUniqueCategoriesSum
                },
                FlaggedSample = allFlaggedSymbols.Take(25).Select(s => $"{s.Key} => {s.Value.Name}").ToList(),
                PublicFlaggedSymbols = publicFlaggedSymbols.Select(s => $"{s.Assembly}!{s.Type}::{s.Kind}:{s.Name}").ToList()
            };

            string benchmarksDir = Path.Combine(repoRoot, "benchmarks");
            if (Directory.Exists(benchmarksDir))
            {
                string reportPath = Path.Combine(benchmarksDir, "corpus_evaluation_report.json");
                var jsonOptions = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
                File.WriteAllText(reportPath, System.Text.Json.JsonSerializer.Serialize(reportData, jsonOptions));
            }

            // Distinct subsets for exact assertions
            var publicTypesAndMethodsNames = allSymbols.Values
                .Where(s => s.IsPublic && (s.Kind == "Type" || s.Kind == "Method"))
                .Select(s => s.Name)
                .Distinct()
                .ToList();
            var publicTypesAndMethodsFlagged = publicTypesAndMethodsNames.Where(SemanticRenamer.IsMangledIdentifier).ToList();

            var pinnedPublicSymbols = allSymbols.Values
                .Where(s => s.IsPublic && (s.Assembly == "dnlib.dll" || s.Assembly == "de4dot.blocks.dll"))
                .ToList();
            var pinnedPublicFlagged = pinnedPublicSymbols.Where(s => SemanticRenamer.IsMangledIdentifier(s.Name)).ToList();

            // Assertions:
            // 1. Strict ZERO false positives on public Types and Methods contract
            Assert.Empty(publicTypesAndMethodsFlagged);

            // 2. Strict ZERO false positives on pinned third-party reference library public symbols
            Assert.Empty(pinnedPublicFlagged);

            // 3. Overall public symbol false positives tightly bounded (e.g. Win32 COM interop struct fields)
            Assert.True(publicFlaggedSymbols.Count <= 5, $"Public symbols FP count exceeded expected threshold: {publicFlaggedSymbols.Count}");
            Assert.True(publicSymbolsFpRate < 0.001, $"Public symbols FP rate {publicSymbolsFpRate:P4} exceeded 0.1% threshold.");

            // 4. Global false positive rate across the entire corpus tightly bounded under 1.0%
            Assert.True(allNamesFpRate < 0.01, $"All names FP rate {allNamesFpRate:P3} ({allFlaggedNames.Count}/{allTextualNames.Count}) exceeded 1.0% threshold.");
            Assert.True(allSymbolsFpRate < 0.01, $"All symbols FP rate {allSymbolsFpRate:P3} ({allFlaggedSymbols.Count}/{allSymbols.Count}) exceeded 1.0% threshold.");
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_33_EmpiricalModuleDeobfuscation_NoFalsePositiveRenaming()
        {
            var module = new ModuleDefUser("RepresentativeCorpusTest.dll");

            // Build a representative module with legitimate classes, methods, properties, and acronyms
            var controllerType = new TypeDefUser("MyApp.Controllers", "CustomerApiController", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(controllerType);

            var getMethod = new MethodDefUser("GetCustomerById", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Int32), MethodAttributes.Public)
            {
                Body = new CilBody()
            };
            getMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            getMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            controllerType.Methods.Add(getMethod);

            var postMethod = new MethodDefUser("PostMqttTelemetry", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), MethodAttributes.Public)
            {
                Body = new CilBody()
            };
            postMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            controllerType.Methods.Add(postMethod);

            var gatewayType = new TypeDefUser("MyApp.Network", "BgpMqttGateway", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(gatewayType);

            var startMethod = new MethodDefUser("StartTcpUdpStream", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Public)
            {
                Body = new CilBody()
            };
            startMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            gatewayType.Methods.Add(startMethod);

            // Run SemanticRenamer on this clean representative module
            var result = SemanticRenamer.Execute(module, verbose: false);

            // Assert zero false positive renames
            Assert.Equal(0, result.UnprintableNormalized);
            Assert.Equal("CustomerApiController", controllerType.Name.String);
            Assert.Equal("GetCustomerById", getMethod.Name.String);
            Assert.Equal("PostMqttTelemetry", postMethod.Name.String);
            Assert.Equal("BgpMqttGateway", gatewayType.Name.String);
            Assert.Equal("StartTcpUdpStream", startMethod.Name.String);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_34_MetadataSymbolIdentity_DisambiguationAndCollisionDetection()
        {
            var module = new ModuleDefUser("DisambiguationTest.dll");

            // 1. Two overloaded methods with a parameter bearing the exact same name
            var workerType = new TypeDefUser("TestApp", "WorkerService", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(workerType);

            var methodInt = new MethodDefUser("Execute", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32));
            var param1 = new ParamDefUser("timeout", 1);
            methodInt.ParamDefs.Add(param1);
            methodInt.Parameters[1].Name = "timeout";
            workerType.Methods.Add(methodInt);

            var methodString = new MethodDefUser("Execute", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String));
            var param2 = new ParamDefUser("timeout", 1);
            methodString.ParamDefs.Add(param2);
            methodString.Parameters[1].Name = "timeout";
            workerType.Methods.Add(methodString);

            // Compute full metadata parameter keys
            string sigInt = methodInt.MethodSig.ToString();
            string sigStr = methodString.MethodSig.ToString();
            string keyParamInt = $"TestAsm!TestApp.WorkerService::Execute({sigInt}):Param[1]:System.Int32:timeout";
            string keyParamStr = $"TestAsm!TestApp.WorkerService::Execute({sigStr}):Param[1]:System.String:timeout";

            Assert.NotEqual(keyParamInt, keyParamStr);

            // 2. Two indexers/properties bearing the same name but distinct signatures
            var indexerInt = new PropertyDefUser("Item", new PropertySig(true, module.CorLibTypes.Int32, module.CorLibTypes.Int32));
            var indexerStr = new PropertyDefUser("Item", new PropertySig(true, module.CorLibTypes.String, module.CorLibTypes.String));
            workerType.Properties.Add(indexerInt);
            workerType.Properties.Add(indexerStr);

            string keyPropInt = $"TestAsm!TestApp.WorkerService::Property:Item({indexerInt.PropertySig})";
            string keyPropStr = $"TestAsm!TestApp.WorkerService::Property:Item({indexerStr.PropertySig})";

            Assert.NotEqual(keyPropInt, keyPropStr);

            // 3. Two events of same name in distinct metadata contexts (different declaring types)
            var publisherType = new TypeDefUser("TestApp", "Publisher", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(publisherType);
            var eventA = new EventDefUser("StatusChanged", new TypeRefUser(module, "System", "EventHandler", module.CorLibTypes.AssemblyRef));
            workerType.Events.Add(eventA);
            var eventB = new EventDefUser("StatusChanged", new TypeRefUser(module, "System", "EventHandler", module.CorLibTypes.AssemblyRef));
            publisherType.Events.Add(eventB);

            string keyEventA = $"TestAsm!TestApp.WorkerService::Event:StatusChanged:{eventA.EventType?.FullName}";
            string keyEventB = $"TestAsm!TestApp.Publisher::Event:StatusChanged:{eventB.EventType?.FullName}";

            Assert.NotEqual(keyEventA, keyEventB);

            // 4. Public type nested inside a non-public container
            var internalOuter = new TypeDefUser("TestApp", "InternalOuter", module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NotPublic | TypeAttributes.Class
            };
            module.Types.Add(internalOuter);

            var nestedPublic = new TypeDefUser("NestedPublic", module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NestedPublic | TypeAttributes.Class
            };
            internalOuter.NestedTypes.Add(nestedPublic);

            // Verify effective visibility logic: nested public within internal outer is NOT effectively public
            static bool IsTypeEffectivelyPublic(TypeDef type)
            {
                if (type == null) return false;
                var curr = type;
                while (curr.IsNested)
                {
                    if (!curr.IsNestedPublic)
                        return false;
                    curr = curr.DeclaringType;
                    if (curr == null) return false;
                }
                return curr.IsPublic;
            }

            Assert.True(nestedPublic.IsNestedPublic);
            Assert.False(internalOuter.IsPublic);
            Assert.False(IsTypeEffectivelyPublic(nestedPublic), "Public type nested in non-public container must NOT be effectively public.");

            // 5 & 6. Verification of equality between total and sum of categories + collision detection
            var testSymbols = new Dictionary<string, (string Asm, string Type, string Kind, string Name, bool IsPublic)>(StringComparer.Ordinal);
            int detectedCollisions = 0;

            void AddTestSymbol(string key, string asm, string type, string kind, string name, bool isPub)
            {
                if (testSymbols.ContainsKey(key))
                {
                    detectedCollisions++;
                    return; // Reject overwrite
                }
                testSymbols.Add(key, (asm, type, kind, name, isPub));
            }

            AddTestSymbol(keyParamInt, "TestAsm", "WorkerService", "Parameter", "timeout", true);
            AddTestSymbol(keyParamStr, "TestAsm", "WorkerService", "Parameter", "timeout", true);
            AddTestSymbol(keyPropInt, "TestAsm", "WorkerService", "Property", "Item", true);
            AddTestSymbol(keyPropStr, "TestAsm", "WorkerService", "Property", "Item", true);
            AddTestSymbol(keyEventA, "TestAsm", "WorkerService", "Event", "StatusChanged", true);
            AddTestSymbol(keyEventB, "TestAsm", "Publisher", "Event", "StatusChanged", true);
            AddTestSymbol("TestAsm!TestApp.WorkerService::Type:Class:WorkerService", "TestAsm", "WorkerService", "Type", "WorkerService", true);
            AddTestSymbol($"TestAsm!TestApp.WorkerService::Method:Execute({sigInt})", "TestAsm", "WorkerService", "Method", "Execute", true);
            AddTestSymbol("TestAsm!TestApp.WorkerService::Field:_count:System.Int32", "TestAsm", "WorkerService", "Field", "_count", true);

            // Verify collision detection by attempting to register duplicate key
            Assert.Equal(0, detectedCollisions);
            AddTestSymbol(keyParamInt, "TestAsm", "WorkerService", "Parameter", "timeout", true); // Duplicate attempt
            Assert.Equal(1, detectedCollisions);

            // Calculate category sum from unique symbols
            int uTypes = testSymbols.Values.Count(s => s.Kind == "Type");
            int uMethods = testSymbols.Values.Count(s => s.Kind == "Method");
            int uFields = testSymbols.Values.Count(s => s.Kind == "Field");
            int uProps = testSymbols.Values.Count(s => s.Kind == "Property");
            int uEvents = testSymbols.Values.Count(s => s.Kind == "Event");
            int uParams = testSymbols.Values.Count(s => s.Kind == "Parameter");

            int sumCategories = uTypes + uMethods + uFields + uProps + uEvents + uParams;

            // Strict equality assertion
            Assert.Equal(testSymbols.Count, sumCategories);
            Assert.Equal(9, testSymbols.Count);
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void C10_35_PropertyAndEvent_FamilyOrAssembly_VisibilityClassification()
        {
            var module = new ModuleDefUser("VisibilityRulesTest.dll");

            static bool IsTypeEffectivelyPublic(TypeDef type)
            {
                if (type == null) return false;
                var curr = type;
                while (curr.IsNested)
                {
                    if (!curr.IsNestedPublic)
                        return false;
                    curr = curr.DeclaringType;
                    if (curr == null) return false;
                }
                return curr.IsPublic;
            }

            // Helper matching the exact visibility rules used in C10_32
            static bool ClassifyProperty(PropertyDef prop, bool isTypePublic)
            {
                return ((prop.GetMethod != null && (prop.GetMethod.IsPublic || prop.GetMethod.IsFamily || prop.GetMethod.IsFamilyOrAssembly)) ||
                        (prop.SetMethod != null && (prop.SetMethod.IsPublic || prop.SetMethod.IsFamily || prop.SetMethod.IsFamilyOrAssembly))) && isTypePublic;
            }

            static bool ClassifyEvent(EventDef ev, bool isTypePublic)
            {
                return ((ev.AddMethod != null && (ev.AddMethod.IsPublic || ev.AddMethod.IsFamily || ev.AddMethod.IsFamilyOrAssembly)) ||
                        (ev.RemoveMethod != null && (ev.RemoveMethod.IsPublic || ev.RemoveMethod.IsFamily || ev.RemoveMethod.IsFamilyOrAssembly))) && isTypePublic;
            }

            // 1. Public enclosing type
            var publicType = new TypeDefUser("TestApp", "PublicEntity", module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.Public | TypeAttributes.Class
            };
            module.Types.Add(publicType);
            bool isPublicTypePublic = IsTypeEffectivelyPublic(publicType);
            Assert.True(isPublicTypePublic);

            // Property with FamORAssem getter (protected internal) -> MUST be Public
            var propFamOrAssem = new PropertyDefUser("ProtectedInternalProp", new PropertySig(true, module.CorLibTypes.Int32));
            var getterFamOrAssem = new MethodDefUser("get_ProtectedInternalProp", MethodSig.CreateInstance(module.CorLibTypes.Int32))
            {
                Attributes = MethodAttributes.FamORAssem | MethodAttributes.HideBySig | MethodAttributes.SpecialName
            };
            publicType.Methods.Add(getterFamOrAssem);
            propFamOrAssem.GetMethod = getterFamOrAssem;
            publicType.Properties.Add(propFamOrAssem);

            Assert.True(getterFamOrAssem.IsFamilyOrAssembly);
            Assert.True(ClassifyProperty(propFamOrAssem, isPublicTypePublic), "Property with FamORAssem getter on public type must be classified as Public.");

            // Property with FamANDAssem getter (private protected) -> MUST NOT be Public (NonPublic)
            var propFamAndAssem = new PropertyDefUser("PrivateProtectedProp", new PropertySig(true, module.CorLibTypes.Int32));
            var getterFamAndAssem = new MethodDefUser("get_PrivateProtectedProp", MethodSig.CreateInstance(module.CorLibTypes.Int32))
            {
                Attributes = MethodAttributes.FamANDAssem | MethodAttributes.HideBySig | MethodAttributes.SpecialName
            };
            publicType.Methods.Add(getterFamAndAssem);
            propFamAndAssem.GetMethod = getterFamAndAssem;
            publicType.Properties.Add(propFamAndAssem);

            Assert.True(getterFamAndAssem.IsFamilyAndAssembly);
            Assert.False(ClassifyProperty(propFamAndAssem, isPublicTypePublic), "Property with FamANDAssem getter must NOT be classified as Public.");

            // Event with FamORAssem add accessor -> MUST be Public
            var eventFamOrAssem = new EventDefUser("ProtectedInternalEvent", new TypeRefUser(module, "System", "EventHandler", module.CorLibTypes.AssemblyRef));
            var adderFamOrAssem = new MethodDefUser("add_ProtectedInternalEvent", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object))
            {
                Attributes = MethodAttributes.FamORAssem | MethodAttributes.HideBySig | MethodAttributes.SpecialName
            };
            publicType.Methods.Add(adderFamOrAssem);
            eventFamOrAssem.AddMethod = adderFamOrAssem;
            publicType.Events.Add(eventFamOrAssem);

            Assert.True(adderFamOrAssem.IsFamilyOrAssembly);
            Assert.True(ClassifyEvent(eventFamOrAssem, isPublicTypePublic), "Event with FamORAssem adder on public type must be classified as Public.");

            // Event with FamANDAssem add accessor -> MUST NOT be Public (NonPublic)
            var eventFamAndAssem = new EventDefUser("PrivateProtectedEvent", new TypeRefUser(module, "System", "EventHandler", module.CorLibTypes.AssemblyRef));
            var adderFamAndAssem = new MethodDefUser("add_PrivateProtectedEvent", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object))
            {
                Attributes = MethodAttributes.FamANDAssem | MethodAttributes.HideBySig | MethodAttributes.SpecialName
            };
            publicType.Methods.Add(adderFamAndAssem);
            eventFamAndAssem.AddMethod = adderFamAndAssem;
            publicType.Events.Add(eventFamAndAssem);

            Assert.True(adderFamAndAssem.IsFamilyAndAssembly);
            Assert.False(ClassifyEvent(eventFamAndAssem, isPublicTypePublic), "Event with FamANDAssem adder must NOT be classified as Public.");

            // 2. Nested public type within internal container: container hierarchy coherence
            var internalContainer = new TypeDefUser("TestApp", "InternalContainer", module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NotPublic | TypeAttributes.Class
            };
            module.Types.Add(internalContainer);

            var nestedInInternal = new TypeDefUser("NestedInInternal", module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NestedPublic | TypeAttributes.Class
            };
            internalContainer.NestedTypes.Add(nestedInInternal);

            bool isNestedEffectivelyPublic = IsTypeEffectivelyPublic(nestedInInternal);
            Assert.False(isNestedEffectivelyPublic, "Nested public type inside internal container is NOT effectively public.");

            // Even if property has FamORAssem getter, its enclosing type is not effectively public
            var propInNested = new PropertyDefUser("NestedProp", new PropertySig(true, module.CorLibTypes.Int32));
            var getterInNested = new MethodDefUser("get_NestedProp", MethodSig.CreateInstance(module.CorLibTypes.Int32))
            {
                Attributes = MethodAttributes.FamORAssem | MethodAttributes.HideBySig | MethodAttributes.SpecialName
            };
            nestedInInternal.Methods.Add(getterInNested);
            propInNested.GetMethod = getterInNested;
            nestedInInternal.Properties.Add(propInNested);

            Assert.False(ClassifyProperty(propInNested, isNestedEffectivelyPublic),
                "Member on a type nested in non-public container must NOT be classified as Public regardless of member attributes.");
        }

        #endregion
    }
}


