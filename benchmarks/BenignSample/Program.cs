using System;
using System.IO;
using System.Reflection;

namespace BenignSample
{
    public interface ICalculator
    {
        int Calculate(int a, int b);
    }

    public class StandardCalculator : ICalculator
    {
        public int Calculate(int a, int b) => a + b;
    }

    public class GenericWorker<T>
    {
        public T Data { get; set; }

        public string Process<U>(U tag, int multiplier)
        {
            int localVal = multiplier * 10;
            bool isPositive = localVal > 0;
            string status = isPositive ? "POS" : "ZERO_OR_NEG";
            try
            {
                if (localVal == 0)
                    throw new InvalidOperationException("Zero multiplier encountered");
                return $"GENERIC_WORKER:{Data}:{tag}:{status}:{localVal}";
            }
            catch (Exception ex)
            {
                return $"CAUGHT:{ex.Message}:{status}";
            }
            finally
            {
                localVal = -1;
            }
        }
    }

    public static class Decrypters
    {
        public static T Decrypter<T>(uint key)
        {
            if (key == 0x1001) return (T)(object)"ConfuserEx_Benchmark_Secret_String_2026";
            if (key == 0x1002) return (T)(object)133742;
            if (key == 0x1003) return (T)(object)9223372036854775800L;
            return default;
        }
    }

    public static class BenignFeatures
    {
        // 1. Strings & Numeric Constants
        public static string GetStringConstant() => "ConfuserEx_Benchmark_Secret_String_2026";
        public static int GetNumericConstant1() => 133742;
        public static long GetNumericConstant2() => 9223372036854775800L;

        // 2. Control Flow & Switch Logic
        public static int ComputeSwitch(int state, int x)
        {
            int accum = x;
            switch (state)
            {
                case 1:
                    accum += 10;
                    break;
                case 2:
                    accum *= 2;
                    break;
                case 3:
                    accum -= 5;
                    break;
                default:
                    accum ^= 0x55;
                    break;
            }
            return accum;
        }

        // 3. Proxies (Direct Method & Delegate)
        public static int AddProxyTarget(int a, int b) => a + b;
        public static Func<int, int, int> AddDelegate = AddProxyTarget;

        public static int ExecuteProxy(int a, int b)
        {
            return AddDelegate(a, b);
        }

        // 4. Embedded Resources
        public static string ReadEmbeddedGreeting()
        {
            var asm = Assembly.GetExecutingAssembly();
            using (var stream = asm.GetManifestResourceStream("BenignSample.Greeting.txt"))
            {
                if (stream == null) return "MISSING_RESOURCE";
                using (var reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd().Trim();
                }
            }
        }
    }

    public class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "test")
            {
                Console.WriteLine("BENIGN_START");
                Console.WriteLine($"CONST_STR:{BenignFeatures.GetStringConstant()}");
                Console.WriteLine($"CONST_NUM:{BenignFeatures.GetNumericConstant1()}:{BenignFeatures.GetNumericConstant2()}");
                Console.WriteLine($"CFLOW:{BenignFeatures.ComputeSwitch(2, 50)}:{BenignFeatures.ComputeSwitch(1, 20)}:{BenignFeatures.ComputeSwitch(3, 40)}:{BenignFeatures.ComputeSwitch(99, 10)}");
                Console.WriteLine($"PROXY:{BenignFeatures.ExecuteProxy(30, 12)}");
                Console.WriteLine($"RESOURCE:{BenignFeatures.ReadEmbeddedGreeting()}");

                var worker = new GenericWorker<string> { Data = "ITEM_PAYLOAD" };
                Console.WriteLine(worker.Process("TAG_99", 5));
                Console.WriteLine(worker.Process("TAG_ZERO", 0));
                Console.WriteLine("BENIGN_END");
                return 0;
            }

            Console.WriteLine("BenignSample application ready.");
            return 0;
        }
    }
}
