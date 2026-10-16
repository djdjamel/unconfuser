using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Tool;
using ConfuserExTools.ConstantKiller;

namespace ConfuserExTools.ProxyKiller
{
	public static class ProxyKillerImpl
	{
		public static int Execute(ModuleDef module, bool ignoreAccess, bool removeProxyMethods)
		{
			if (module is null)
				throw new ArgumentNullException(nameof(module));

			var proxyMethods = new Dictionary<MethodDef, Instruction>();
			foreach (var method in module.EnumerateMethods())
			{
				if (!method.HasBody)
					continue;
				if (!(ignoreAccess || method.IsPrivateScope))
					continue;

				bool isProxy = true;
				var realInstruction = default(Instruction);
				foreach (var instruction in method.Body.Instructions)
				{
					switch (instruction.OpCode.Code)
					{
					case Code.Nop:
					case Code.Ldarg:
					case Code.Ldarg_0:
					case Code.Ldarg_1:
					case Code.Ldarg_2:
					case Code.Ldarg_3:
					case Code.Ldarg_S:
					case Code.Ldarga:
					case Code.Ldarga_S:
					case Code.Ret:
						continue;
					case Code.Call:
					case Code.Callvirt:
					case Code.Newobj:
						if (realInstruction is null)
						{
							realInstruction = instruction;
							continue;
						}
						break;
					}
					isProxy = false;
					break;
				}

				if (!isProxy || realInstruction == null)
					continue;

				proxyMethods[method] = realInstruction;
			}

			if (proxyMethods.Count == 0)
				return 0;

			// Track rewritten call sites per proxy method for reference counting
			var proxyReferenceCounts = new Dictionary<MethodDef, int>();
			var proxyRewrittenCounts = new Dictionary<MethodDef, int>();
			foreach (var pm in proxyMethods.Keys)
			{
				proxyReferenceCounts[pm] = 0;
				proxyRewrittenCounts[pm] = 0;
			}

			var oldAssemblyResolver = module.Context.AssemblyResolver;
			var oldResolver = module.Context.Resolver;
			try
			{
				module.Context.AssemblyResolver = NullResolver.Instance;
				module.Context.Resolver = new Resolver(NullResolver.Instance);

				// First pass: count all call sites referencing proxy methods
				foreach (var method in module.EnumerateMethods())
				{
					if (!method.HasBody || proxyMethods.ContainsKey(method))
						continue;

					foreach (var instruction in method.Body.Instructions)
					{
						if (instruction.OpCode.Code != Code.Call && instruction.OpCode.Code != Code.Callvirt)
							continue;
						if (instruction.Operand is IMethod operand)
						{
							var def = operand.ResolveMethodDef();
							if (def != null && proxyReferenceCounts.ContainsKey(def))
								proxyReferenceCounts[def]++;
						}
					}
				}

				// Second pass: rewrite call sites with per-method error isolation & rollback
				int totalRestored = 0;
				foreach (var method in module.EnumerateMethods())
				{
					if (!method.HasBody || proxyMethods.ContainsKey(method))
						continue;

					// Snapshot body in case transformation fails
					var originalBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(method.Body);
					try
					{
						for (int i = 0; i < method.Body.Instructions.Count; i++)
						{
							var instruction = method.Body.Instructions[i];
							if (instruction.OpCode.Code != Code.Call && instruction.OpCode.Code != Code.Callvirt)
								continue;

							if (instruction.Operand is IMethod operandMethod)
							{
								var targetDef = operandMethod.ResolveMethodDef();
								if (targetDef != null && proxyMethods.TryGetValue(targetDef, out var realCall))
								{
									instruction.OpCode = realCall.OpCode;
									instruction.Operand = realCall.Operand;
									proxyRewrittenCounts[targetDef]++;
									totalRestored++;
								}
							}
						}
					}
					catch (Exception ex)
					{
						// Atomic rollback method on error
						method.Body = originalBody;
						Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] Proxy inlining failed in {method}: {ex.Message}. Rolled back.");
					}
				}

				// Safely prune proxy methods only if 100% of their references were rewritten
				if (removeProxyMethods)
				{
					int prunedCount = 0;
					foreach (var kvp in proxyMethods)
					{
						var proxyMethod = kvp.Key;
						int totalRefs = proxyReferenceCounts[proxyMethod];
						int rewrittenRefs = proxyRewrittenCounts[proxyMethod];

						if (totalRefs > 0 && rewrittenRefs >= totalRefs)
						{
							if (proxyMethod.DeclaringType != null && proxyMethod.DeclaringType.Methods.Contains(proxyMethod))
							{
								proxyMethod.DeclaringType.Methods.Remove(proxyMethod);
								prunedCount++;
							}
						}
						else if (totalRefs > rewrittenRefs)
						{
							Logger.LogWarning($"[0x{proxyMethod.MDToken.Raw:X8}] Retaining proxy method {proxyMethod.Name} ({totalRefs - rewrittenRefs} unrewritten references remain).");
						}
					}
				}

				int strongCount = InlineStrongDelegateProxies(module);
				if (strongCount > 0)
					Logger.LogInfo($"[ProxyKiller] Inlined {strongCount} strong delegate proxies");
				totalRestored += strongCount;

				return totalRestored;
			}
			finally
			{
				module.Context.AssemblyResolver = oldAssemblyResolver;
				module.Context.Resolver = oldResolver;
			}
		}

		private static int InlineStrongDelegateProxies(ModuleDef module)
		{
			var delegateMap = new Dictionary<FieldDef, (IMethod TargetMethod, OpCode CallOpCode)>();
			var delegateTypes = new HashSet<TypeDef>();

			if (module.GlobalType != null)
			{
				foreach (var method in module.GlobalType.Methods)
				{
					if (!method.HasBody) continue;
					var instrs = method.Body.Instructions;
					for (int i = 0; i < instrs.Count; i++)
					{
						if (instrs[i].OpCode == OpCodes.Stsfld && instrs[i].Operand is IField field)
						{
							var fieldDef = field.ResolveFieldDef();
							if (fieldDef == null || fieldDef.DeclaringType != module.GlobalType)
								continue;

							// Trace backwards for ldtoken IMethod
							IMethod targetMethod = null;
							for (int j = i - 1; j >= 0 && j >= i - 10; j--)
							{
								if (instrs[j].OpCode == OpCodes.Ldtoken && instrs[j].Operand is IMethod target)
								{
									targetMethod = target;
									break;
								}
							}

							if (targetMethod != null)
							{
								var methodDef = targetMethod.ResolveMethodDef();
								bool isVirtual = methodDef != null && methodDef.IsVirtual;
								var opCode = isVirtual ? OpCodes.Callvirt : OpCodes.Call;
								delegateMap[fieldDef] = (targetMethod, opCode);

								var fieldType = fieldDef.FieldSig?.Type?.ToTypeDefOrRef()?.ResolveTypeDef();
								if (fieldType != null && fieldType.BaseType != null &&
									fieldType.BaseType.FullName == "System.MulticastDelegate")
								{
									delegateTypes.Add(fieldType);
								}
							}
						}
					}
				}
			}

			if (delegateMap.Count == 0)
				return 0;

			int inlinedCount = 0;
			foreach (var method in module.EnumerateMethods())
			{
				if (!method.HasBody || method.DeclaringType == module.GlobalType)
					continue;

				var instrs = method.Body.Instructions;
				for (int i = 0; i < instrs.Count; i++)
				{
					if (instrs[i].OpCode == OpCodes.Ldsfld && instrs[i].Operand is IField field)
					{
						var fieldDef = field.ResolveFieldDef();
						if (fieldDef != null && delegateMap.TryGetValue(fieldDef, out var mapping))
						{
							// Scan forward for Invoke call
							for (int j = i + 1; j < instrs.Count; j++)
							{
								if (instrs[j].OpCode == OpCodes.Callvirt && instrs[j].Operand is IMethod called && called.Name == "Invoke")
								{
									instrs[i].OpCode = OpCodes.Nop;
									instrs[i].Operand = null;
									instrs[j].OpCode = mapping.CallOpCode;
									instrs[j].Operand = mapping.TargetMethod;
									inlinedCount++;
									break;
								}
							}
						}
					}
				}
			}

			// Clean up delegate fields and types only if no references remain in the module
			var remainingFieldRefs = new HashSet<FieldDef>();
			foreach (var m in module.EnumerateMethods())
			{
				if (!m.HasBody) continue;
				foreach (var inst in m.Body.Instructions)
				{
					if (inst.Operand is IField f)
					{
						var fDef = f.ResolveFieldDef();
						if (fDef != null) remainingFieldRefs.Add(fDef);
					}
				}
			}

			if (module.GlobalType != null)
			{
				foreach (var field in delegateMap.Keys)
				{
					if (!remainingFieldRefs.Contains(field))
						module.GlobalType.Fields.Remove(field);
				}
			}

			var remainingTypeRefs = new HashSet<TypeDef>();
			if (module.GlobalType != null)
			{
				foreach (var f in module.GlobalType.Fields)
				{
					var td = f.FieldSig?.Type?.ToTypeDefOrRef()?.ResolveTypeDef();
					if (td != null) remainingTypeRefs.Add(td);
				}
			}

			foreach (var delType in delegateTypes)
			{
				if (!remainingTypeRefs.Contains(delType))
				{
					if (delType.DeclaringType != null)
						delType.DeclaringType.NestedTypes.Remove(delType);
					else
						module.Types.Remove(delType);
				}
			}

			return inlinedCount;
		}
	}
}
