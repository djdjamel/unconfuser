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
				if (TryAnalyzeClassicProxy(method, ignoreAccess, out var realInstruction, out var failureReason))
				{
					proxyMethods[method] = realInstruction;
				}
				else if (method.IsPrivateScope && failureReason != null)
				{
					Logger.LogDebugInfo($"[0x{method.MDToken.Raw:X8}] Method {method.Name} not classified as classic proxy: {failureReason}");
				}
			}

			int totalRestored = 0;
			var oldAssemblyResolver = module.Context.AssemblyResolver;
			var oldResolver = module.Context.Resolver;
			try
			{
				module.Context.AssemblyResolver = NullResolver.Instance;
				module.Context.Resolver = new Resolver(NullResolver.Instance);

				if (proxyMethods.Count > 0)
				{
					// Track rewritten call sites per proxy method for reference counting
					var proxyReferenceCounts = new Dictionary<MethodDef, int>();
					var proxyRewrittenCounts = new Dictionary<MethodDef, int>();
					foreach (var pm in proxyMethods.Keys)
					{
						proxyReferenceCounts[pm] = 0;
						proxyRewrittenCounts[pm] = 0;
					}

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
				totalRestored = 0;
				foreach (var method in module.EnumerateMethods())
				{
					if (!method.HasBody || proxyMethods.ContainsKey(method))
						continue;

					// Snapshot body in case transformation fails
					var originalBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(method.Body);
					try
					{
						int methodRestored = 0;
						var methodRewrittenCounts = new Dictionary<MethodDef, int>();

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
									methodRewrittenCounts[targetDef] = methodRewrittenCounts.TryGetValue(targetDef, out int cur) ? cur + 1 : 1;
									methodRestored++;
								}
							}
						}

						// Commit counts only after method transformation successfully completes
						foreach (var kvp in methodRewrittenCounts)
						{
							proxyRewrittenCounts[kvp.Key] += kvp.Value;
						}
						totalRestored += methodRestored;
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

		private class DelegateStackItem
		{
			public Instruction SourceLdsfld { get; set; }
			public FieldDef Field { get; set; }
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
							var fieldDef = (field as FieldDef) ?? field.ResolveFieldDef();
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
								var methodDef = (targetMethod as MethodDef) ?? targetMethod.ResolveMethodDef();
								bool isVirtual = methodDef != null && methodDef.IsVirtual;
								var opCode = isVirtual ? OpCodes.Callvirt : OpCodes.Call;
								delegateMap[fieldDef] = (targetMethod, opCode);

								var fieldType = (fieldDef.FieldSig?.Type?.ToTypeDefOrRef() as TypeDef) ?? fieldDef.FieldSig?.Type?.ToTypeDefOrRef()?.ResolveTypeDef();
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
				var branchTargets = new HashSet<Instruction>();
				foreach (var inst in instrs)
				{
					if (inst.Operand is Instruction t && t != null) branchTargets.Add(t);
					else if (inst.Operand is IList<Instruction> mt) { foreach (var x in mt) if (x != null) branchTargets.Add(x); }
				}
				if (method.Body.HasExceptionHandlers)
				{
					foreach (var eh in method.Body.ExceptionHandlers)
					{
						if (eh.TryStart != null) branchTargets.Add(eh.TryStart);
						if (eh.TryEnd != null) branchTargets.Add(eh.TryEnd);
						if (eh.HandlerStart != null) branchTargets.Add(eh.HandlerStart);
						if (eh.HandlerEnd != null) branchTargets.Add(eh.HandlerEnd);
					}
				}

				// Stack simulation to reliably associate ldsfld with its corresponding callvirt Invoke
				var stack = new List<DelegateStackItem>();
				var rewritePairs = new List<(Instruction Ldsfld, Instruction Invoke, IMethod Target, OpCode OpCode)>();

				for (int i = 0; i < instrs.Count; i++)
				{
					var inst = instrs[i];
					if (inst.OpCode == OpCodes.Nop) continue;

					if (inst.OpCode == OpCodes.Ldsfld && inst.Operand is IField field)
					{
						var fieldDef = (field as FieldDef) ?? field.ResolveFieldDef();
						if (fieldDef != null && delegateMap.ContainsKey(fieldDef))
						{
							stack.Add(new DelegateStackItem
							{
								SourceLdsfld = inst,
								Field = fieldDef
							});
							continue;
						}
					}

					if (inst.OpCode == OpCodes.Callvirt && inst.Operand is IMethod called && called.Name == "Invoke")
					{
						int paramCount = called.MethodSig?.Params?.Count ?? 0;
						int requiredPops = paramCount + 1; // params + this (delegate instance)
						if (stack.Count >= requiredPops)
						{
							int delegateIndex = stack.Count - requiredPops;
							var delegateItem = stack[delegateIndex];
							if (delegateItem != null && delegateItem.Field != null && delegateMap.TryGetValue(delegateItem.Field, out var mapping))
							{
								// Verify declaring type and signature compatibility
								bool typesMatch = called.DeclaringType != null && delegateItem.Field.FieldSig?.Type != null
									&& string.Equals(called.DeclaringType.FullName, delegateItem.Field.FieldSig.Type.FullName, StringComparison.Ordinal);

								bool paramsMatch = mapping.TargetMethod.MethodSig != null && mapping.TargetMethod.MethodSig.Params.Count == paramCount;

								if (typesMatch && paramsMatch)
								{
									rewritePairs.Add((delegateItem.SourceLdsfld, inst, mapping.TargetMethod, mapping.CallOpCode));
								}
							}

							// Pop arguments and this
							stack.RemoveRange(delegateIndex, requiredPops);

							// Push return value if non-void
							if (called.MethodSig != null && called.MethodSig.RetType.ElementType != ElementType.Void)
							{
								stack.Add(new DelegateStackItem());
							}
							continue;
						}
						else
						{
							stack.Clear();
							continue;
						}
					}

					// Generic instruction stack update
					inst.CalculateStackUsage(out int pushes, out int pops);
					if (pops > 0)
					{
						int toPop = Math.Min(pops, stack.Count);
						if (toPop > 0)
							stack.RemoveRange(stack.Count - toPop, toPop);
					}
					for (int p = 0; p < pushes; p++)
					{
						stack.Add(new DelegateStackItem());
					}
				}

				// Apply rewrites if no internal branch targets or EH boundaries intersect
				foreach (var pair in rewritePairs)
				{
					int ldsfldIdx = instrs.IndexOf(pair.Ldsfld);
					int invokeIdx = instrs.IndexOf(pair.Invoke);
					if (ldsfldIdx >= 0 && invokeIdx > ldsfldIdx)
					{
						bool hasInterferingBranch = false;
						for (int k = ldsfldIdx + 1; k < invokeIdx; k++)
						{
							if (branchTargets.Contains(instrs[k]))
							{
								hasInterferingBranch = true;
								break;
							}
						}

						if (!hasInterferingBranch)
						{
							pair.Ldsfld.OpCode = OpCodes.Nop;
							pair.Ldsfld.Operand = null;
							pair.Invoke.OpCode = pair.OpCode;
							pair.Invoke.Operand = pair.Target;
							inlinedCount++;
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

		internal static bool TryAnalyzeClassicProxy(MethodDef method, bool ignoreAccess, out Instruction callInstruction, out string failureReason)
		{
			callInstruction = null;
			failureReason = null;

			if (!method.HasBody)
			{
				failureReason = "No method body";
				return false;
			}

			if (!(ignoreAccess || method.IsPrivateScope))
			{
				failureReason = "Method is not PrivateScope";
				return false;
			}

			// ConfuserEx classic proxies are strictly static methods
			if (!method.IsStatic)
			{
				failureReason = "Instance method cannot be classic proxy";
				return false;
			}

			if (method.Body.HasExceptionHandlers)
			{
				failureReason = "Method contains exception handlers";
				return false;
			}

			var nonNops = method.Body.Instructions.Where(i => i.OpCode != OpCodes.Nop).ToList();
			int paramCount = method.Parameters.Count;
			if (nonNops.Count != paramCount + 2)
			{
				failureReason = $"Instruction count mismatch: expected {paramCount + 2}, got {nonNops.Count}";
				return false;
			}

			// Verify parameter loads in exact sequence: 0, 1, ..., paramCount - 1
			for (int p = 0; p < paramCount; p++)
			{
				var inst = nonNops[p];
				if (!IsExactParameterLoad(inst, p))
				{
					failureReason = $"Instruction at position {p} is not exact load of parameter {p} (order or opcode mismatch): {inst}";
					return false;
				}
			}

			var callInst = nonNops[paramCount];
			if (callInst.OpCode != OpCodes.Call && callInst.OpCode != OpCodes.Callvirt && callInst.OpCode != OpCodes.Newobj)
			{
				failureReason = $"Expected Call, Callvirt, or Newobj at position {paramCount}, got {callInst.OpCode}";
				return false;
			}

			if (nonNops[paramCount + 1].OpCode != OpCodes.Ret)
			{
				failureReason = $"Terminal instruction is not Ret: {nonNops[paramCount + 1].OpCode}";
				return false;
			}

			if (!(callInst.Operand is IMethod targetMethod))
			{
				failureReason = "Call operand is not an IMethod";
				return false;
			}

			var targetSig = targetMethod.MethodSig;
			if (targetSig == null)
			{
				failureReason = "Cannot resolve target method signature";
				return false;
			}

			// Signature verification
			if (callInst.OpCode == OpCodes.Newobj)
			{
				if (targetMethod.Name != ".ctor")
				{
					failureReason = "Newobj operand is not a constructor";
					return false;
				}
				if (targetSig.Params.Count != paramCount)
				{
					failureReason = $"Newobj parameter count mismatch: constructor expects {targetSig.Params.Count}, proxy has {paramCount}";
					return false;
				}
				for (int p = 0; p < paramCount; p++)
				{
					if (!TypesMatch(method.Parameters[p].Type, targetSig.Params[p]))
					{
						failureReason = $"Parameter {p} type mismatch: proxy has {method.Parameters[p].Type}, constructor expects {targetSig.Params[p]}";
						return false;
					}
				}
				var targetType = targetMethod.DeclaringType?.ToTypeSig();
				if (targetType == null || !TypesMatch(method.ReturnType, targetType))
				{
					failureReason = $"Return type mismatch: proxy returns {method.ReturnType}, constructor creates {targetType}";
					return false;
				}
			}
			else if (callInst.OpCode == OpCodes.Call && !targetSig.HasThis)
			{
				// Target is static method
				if (targetSig.Params.Count != paramCount)
				{
					failureReason = $"Static call parameter count mismatch: target expects {targetSig.Params.Count}, proxy has {paramCount}";
					return false;
				}
				for (int p = 0; p < paramCount; p++)
				{
					if (!TypesMatch(method.Parameters[p].Type, targetSig.Params[p]))
					{
						failureReason = $"Parameter {p} type mismatch: proxy has {method.Parameters[p].Type}, target expects {targetSig.Params[p]}";
						return false;
					}
				}
				if (!TypesMatch(method.ReturnType, targetSig.RetType))
				{
					failureReason = $"Return type mismatch: proxy returns {method.ReturnType}, target returns {targetSig.RetType}";
					return false;
				}
			}
			else if (targetSig.HasThis)
			{
				// Target is instance method (requires 'this' as first parameter of the static proxy)
				if (paramCount != targetSig.Params.Count + 1)
				{
					failureReason = $"Instance call parameter count mismatch: target expects 1 + {targetSig.Params.Count}, proxy has {paramCount}";
					return false;
				}
				var declaringTypeSig = targetMethod.DeclaringType?.ToTypeSig();
				if (declaringTypeSig == null || !TypesMatch(method.Parameters[0].Type, declaringTypeSig))
				{
					failureReason = $"Instance 'this' type mismatch: proxy param 0 is {method.Parameters[0].Type}, target declaring type is {declaringTypeSig}";
					return false;
				}
				for (int p = 1; p < paramCount; p++)
				{
					if (!TypesMatch(method.Parameters[p].Type, targetSig.Params[p - 1]))
					{
						failureReason = $"Parameter {p} type mismatch: proxy has {method.Parameters[p].Type}, target expects {targetSig.Params[p - 1]}";
						return false;
					}
				}
				if (!TypesMatch(method.ReturnType, targetSig.RetType))
				{
					failureReason = $"Return type mismatch: proxy returns {method.ReturnType}, target returns {targetSig.RetType}";
					return false;
				}
			}
			else
			{
				failureReason = "Unsupported call opcode and target signature combination";
				return false;
			}

			callInstruction = callInst;
			return true;
		}

		private static bool IsExactParameterLoad(Instruction inst, int paramIndex)
		{
			if (paramIndex == 0 && inst.OpCode == OpCodes.Ldarg_0) return true;
			if (paramIndex == 1 && inst.OpCode == OpCodes.Ldarg_1) return true;
			if (paramIndex == 2 && inst.OpCode == OpCodes.Ldarg_2) return true;
			if (paramIndex == 3 && inst.OpCode == OpCodes.Ldarg_3) return true;
			if (inst.OpCode == OpCodes.Ldarg_S || inst.OpCode == OpCodes.Ldarg)
			{
				if (inst.Operand is Parameter p && p.Index == paramIndex) return true;
				if (inst.Operand is int i && i == paramIndex) return true;
				if (inst.Operand is byte b && b == paramIndex) return true;
				if (inst.Operand is sbyte sb && sb == paramIndex) return true;
			}
			return false;
		}

		private static bool TypesMatch(TypeSig a, TypeSig b)
		{
			if (a == null && b == null) return true;
			if (a == null || b == null) return false;
			return string.Equals(a.FullName, b.FullName, StringComparison.Ordinal);
		}
	}
}
