using System;
using System.Linq;
using ConfuserExKillerRunner.Core;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class SimpleJsonTests
    {
        [Fact]
        public void Parse_PrimitiveLiterals_ParsedCorrectly()
        {
            var bTrue = JsonValue.Parse("true");
            Assert.True(bTrue.IsBoolean);
            Assert.True(bTrue.AsBool());

            var bFalse = JsonValue.Parse("false");
            Assert.True(bFalse.IsBoolean);
            Assert.False(bFalse.AsBool());

            var nNull = JsonValue.Parse("null");
            Assert.True(nNull.IsNull);

            var numInt = JsonValue.Parse("42");
            Assert.True(numInt.IsNumber);
            Assert.Equal(42, numInt.AsInt());

            var numNeg = JsonValue.Parse("-123.45");
            Assert.True(numNeg.IsNumber);
            Assert.Equal(-123.45, numNeg.AsDouble(), 2);

            var numExp = JsonValue.Parse("1.5e3");
            Assert.True(numExp.IsNumber);
            Assert.Equal(1500, numExp.AsInt());
        }

        [Fact]
        public void Parse_StringWithEscapes_DecodedCorrectly()
        {
            string json = "\"Hello \\\"World\\\" \\n \\t \\\\ \\u0041\"";
            var val = JsonValue.Parse(json);
            Assert.True(val.IsString);
            Assert.Equal("Hello \"World\" \n \t \\ A", val.AsString());
        }

        [Fact]
        public void Parse_ArrayAndObjects_ParsedCorrectly()
        {
            string json = @"
            {
                ""name"": ""TestApp"",
                ""version"": 1,
                ""active"": true,
                ""items"": [1, 2, ""three"", null],
                ""nested"": {
                    ""innerKey"": ""innerVal""
                }
            }";

            var root = JsonValue.Parse(json);
            Assert.True(root.IsObject);
            Assert.Equal("TestApp", root["name"].AsString());
            Assert.Equal(1, root["version"].AsInt());
            Assert.True(root["active"].AsBool());

            var items = root["items"];
            Assert.True(items.IsArray);
            Assert.Equal(4, items.Count);
            Assert.Equal(1, items[0].AsInt());
            Assert.Equal(2, items[1].AsInt());
            Assert.Equal("three", items[2].AsString());
            Assert.True(items[3].IsNull);

            var nested = root["nested"];
            Assert.True(nested.IsObject);
            Assert.Equal("innerVal", nested["innerKey"].AsString());
        }

        [Fact]
        public void Parse_MalformedJson_ThrowsJsonParseException()
        {
            Assert.Throws<JsonParseException>(() => JsonValue.Parse("{ unquotedKey: 123 }"));
            Assert.Throws<JsonParseException>(() => JsonValue.Parse("{ \"unterminated\": \"string }"));
            Assert.Throws<JsonParseException>(() => JsonValue.Parse("[ 1, 2, "));
        }

        [Fact]
        public void Serialize_RoundTrip_PreservesValues()
        {
            var obj = JsonValue.NewObject();
            obj["title"] = JsonValue.From("Deobfuscator");
            obj["exitCode"] = JsonValue.From(0);
            obj["complete"] = JsonValue.From(true);

            var arr = JsonValue.NewArray();
            arr.Add(JsonValue.From("AntiTamper"));
            arr.Add(JsonValue.From("Constants"));
            obj["tags"] = arr;

            string json = obj.ToString(pretty: true);
            var parsed = JsonValue.Parse(json);

            Assert.Equal("Deobfuscator", parsed["title"].AsString());
            Assert.Equal(0, parsed["exitCode"].AsInt());
            Assert.True(parsed["complete"].AsBool());
            Assert.Equal(2, parsed["tags"].Count);
            Assert.Equal("AntiTamper", parsed["tags"][0].AsString());
            Assert.Equal("Constants", parsed["tags"][1].AsString());
        }
    }
}
