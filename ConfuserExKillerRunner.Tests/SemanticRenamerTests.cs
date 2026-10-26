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
    }
}

