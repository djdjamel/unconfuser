using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.MD;

namespace ConfuserExTools.ConstantKiller {
	internal static class ModuleDefExtensions {
		public static IEnumerable<MethodDef> EnumerateMethods(this ModuleDef module) {
			if (module is ModuleDefMD moduleDefMD) {
				uint methodTableLength = moduleDefMD.TablesStream.MethodTable.Rows;
				for (uint rid = 1; rid <= methodTableLength; rid++)
					yield return moduleDefMD.ResolveMethod(rid);
			}
			else {
				foreach (var type in module.GetTypes()) {
					foreach (var method in type.Methods)
						yield return method;
				}
			}
		}
	}
}
