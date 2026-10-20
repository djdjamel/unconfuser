using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace ConfuserExKillerRunner.Core
{
    public enum JsonType
    {
        Null,
        Boolean,
        Number,
        String,
        Array,
        Object
    }

    public sealed class JsonParseException : Exception
    {
        public int Line { get; }
        public int Column { get; }

        public JsonParseException(string message, int line, int column)
            : base($"{message} at line {line}, col {column}")
        {
            Line = line;
            Column = column;
        }
    }

    public sealed class JsonValue
    {
        public JsonType Type { get; private set; }
        private bool _boolVal;
        private double _numVal;
        private string _strVal;
        private List<JsonValue> _arrVal;
        private Dictionary<string, JsonValue> _objVal;

        public static JsonValue Null => new JsonValue { Type = JsonType.Null };

        public static JsonValue From(bool value) => new JsonValue { Type = JsonType.Boolean, _boolVal = value };
        public static JsonValue From(int value) => new JsonValue { Type = JsonType.Number, _numVal = value };
        public static JsonValue From(long value) => new JsonValue { Type = JsonType.Number, _numVal = value };
        public static JsonValue From(double value) => new JsonValue { Type = JsonType.Number, _numVal = value };
        public static JsonValue From(string value) => value == null ? Null : new JsonValue { Type = JsonType.String, _strVal = value };
        public static JsonValue NewObject() => new JsonValue { Type = JsonType.Object, _objVal = new Dictionary<string, JsonValue>(StringComparer.Ordinal) };
        public static JsonValue NewArray() => new JsonValue { Type = JsonType.Array, _arrVal = new List<JsonValue>() };

        public bool IsNull => Type == JsonType.Null;
        public bool IsBoolean => Type == JsonType.Boolean;
        public bool IsNumber => Type == JsonType.Number;
        public bool IsString => Type == JsonType.String;
        public bool IsArray => Type == JsonType.Array;
        public bool IsObject => Type == JsonType.Object;

        public bool AsBool(bool defaultValue = false) => Type == JsonType.Boolean ? _boolVal : defaultValue;
        public int AsInt(int defaultValue = 0) => Type == JsonType.Number ? (int)_numVal : defaultValue;
        public long AsLong(long defaultValue = 0) => Type == JsonType.Number ? (long)_numVal : defaultValue;
        public double AsDouble(double defaultValue = 0) => Type == JsonType.Number ? _numVal : defaultValue;
        public string AsString(string defaultValue = null) => Type == JsonType.String ? _strVal : defaultValue;

        public int Count
        {
            get
            {
                if (Type == JsonType.Array) return _arrVal.Count;
                if (Type == JsonType.Object) return _objVal.Count;
                return 0;
            }
        }

        public JsonValue this[int index]
        {
            get
            {
                if (Type == JsonType.Array && index >= 0 && index < _arrVal.Count)
                    return _arrVal[index];
                return Null;
            }
            set
            {
                if (Type == JsonType.Array && index >= 0 && index < _arrVal.Count)
                    _arrVal[index] = value ?? Null;
            }
        }

        public JsonValue this[string key]
        {
            get
            {
                if (Type == JsonType.Object && _objVal != null && _objVal.TryGetValue(key, out var val))
                    return val;
                return Null;
            }
            set
            {
                if (Type != JsonType.Object)
                {
                    Type = JsonType.Object;
                    _objVal = new Dictionary<string, JsonValue>(StringComparer.Ordinal);
                }
                _objVal[key] = value ?? Null;
            }
        }

        public bool ContainsKey(string key)
        {
            return Type == JsonType.Object && _objVal != null && _objVal.ContainsKey(key);
        }

        public IEnumerable<string> Keys => Type == JsonType.Object && _objVal != null ? _objVal.Keys : (IEnumerable<string>)Array.Empty<string>();

        public void Add(JsonValue item)
        {
            if (Type != JsonType.Array)
            {
                Type = JsonType.Array;
                _arrVal = new List<JsonValue>();
            }
            _arrVal.Add(item ?? Null);
        }

        public void Add(string key, JsonValue value)
        {
            this[key] = value;
        }

        public IEnumerable<JsonValue> AsArray()
        {
            if (Type == JsonType.Array && _arrVal != null)
                return _arrVal;
            return Array.Empty<JsonValue>();
        }

        public override string ToString()
        {
            return ToString(pretty: false);
        }

        public string ToString(bool pretty)
        {
            var sb = new StringBuilder();
            WriteJson(this, sb, pretty, 0);
            return sb.ToString();
        }

        private static void WriteJson(JsonValue val, StringBuilder sb, bool pretty, int indent)
        {
            if (val == null || val.Type == JsonType.Null)
            {
                sb.Append("null");
                return;
            }

            switch (val.Type)
            {
                case JsonType.Boolean:
                    sb.Append(val._boolVal ? "true" : "false");
                    break;
                case JsonType.Number:
                    sb.Append(val._numVal.ToString("G17", CultureInfo.InvariantCulture));
                    break;
                case JsonType.String:
                    WriteString(val._strVal, sb);
                    break;
                case JsonType.Array:
                    sb.Append('[');
                    if (val._arrVal != null && val._arrVal.Count > 0)
                    {
                        if (pretty) sb.AppendLine();
                        for (int i = 0; i < val._arrVal.Count; i++)
                        {
                            if (pretty) sb.Append(new string(' ', (indent + 1) * 2));
                            WriteJson(val._arrVal[i], sb, pretty, indent + 1);
                            if (i < val._arrVal.Count - 1) sb.Append(',');
                            if (pretty) sb.AppendLine();
                        }
                        if (pretty) sb.Append(new string(' ', indent * 2));
                    }
                    sb.Append(']');
                    break;
                case JsonType.Object:
                    sb.Append('{');
                    if (val._objVal != null && val._objVal.Count > 0)
                    {
                        if (pretty) sb.AppendLine();
                        int idx = 0;
                        int count = val._objVal.Count;
                        foreach (var kvp in val._objVal)
                        {
                            if (pretty) sb.Append(new string(' ', (indent + 1) * 2));
                            WriteString(kvp.Key, sb);
                            sb.Append(pretty ? ": " : ":");
                            WriteJson(kvp.Value, sb, pretty, indent + 1);
                            if (idx < count - 1) sb.Append(',');
                            if (pretty) sb.AppendLine();
                            idx++;
                        }
                        if (pretty) sb.Append(new string(' ', indent * 2));
                    }
                    sb.Append('}');
                    break;
            }
        }

        private static void WriteString(string s, StringBuilder sb)
        {
            if (s == null)
            {
                sb.Append("null");
                return;
            }
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 32)
                            sb.AppendFormat(CultureInfo.InvariantCulture, "\\u{0:X4}", (int)c);
                        else
                            sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        public static JsonValue Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return Null;

            var parser = new JsonParser(json);
            return parser.Parse();
        }
    }

    internal sealed class JsonParser
    {
        private readonly string _src;
        private int _idx;
        private int _line = 1;
        private int _col = 1;

        public JsonParser(string source)
        {
            _src = source ?? string.Empty;
        }

        public JsonValue Parse()
        {
            SkipWhitespace();
            if (_idx >= _src.Length)
                return JsonValue.Null;

            var val = ParseValue();
            SkipWhitespace();
            return val;
        }

        private JsonValue ParseValue()
        {
            SkipWhitespace();
            if (_idx >= _src.Length)
                throw Error("Unexpected end of JSON input");

            char c = _src[_idx];
            if (c == '{') return ParseObject();
            if (c == '[') return ParseArray();
            if (c == '"') return ParseString();
            if (c == 't' || c == 'f') return ParseBool();
            if (c == 'n') return ParseNull();
            if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber();

            throw Error($"Unexpected character '{c}'");
        }

        private JsonValue ParseObject()
        {
            Advance(); // skip '{'
            var obj = JsonValue.NewObject();
            SkipWhitespace();

            if (_idx < _src.Length && _src[_idx] == '}')
            {
                Advance();
                return obj;
            }

            while (_idx < _src.Length)
            {
                SkipWhitespace();
                if (_idx >= _src.Length || _src[_idx] != '"')
                    throw Error("Expected property key string");

                string key = ParseRawString();
                SkipWhitespace();

                if (_idx >= _src.Length || _src[_idx] != ':')
                    throw Error("Expected ':' after property key");
                Advance(); // skip ':'

                var val = ParseValue();
                obj[key] = val;

                SkipWhitespace();
                if (_idx >= _src.Length)
                    throw Error("Unterminated object");

                if (_src[_idx] == '}')
                {
                    Advance();
                    return obj;
                }
                if (_src[_idx] == ',')
                {
                    Advance();
                    SkipWhitespace();
                    if (_idx < _src.Length && _src[_idx] == '}')
                    {
                        // Allow trailing comma gracefully
                        Advance();
                        return obj;
                    }
                    continue;
                }

                throw Error($"Expected ',' or '}}' in object but found '{_src[_idx]}'");
            }

            throw Error("Unterminated object");
        }

        private JsonValue ParseArray()
        {
            Advance(); // skip '['
            var arr = JsonValue.NewArray();
            SkipWhitespace();

            if (_idx < _src.Length && _src[_idx] == ']')
            {
                Advance();
                return arr;
            }

            while (_idx < _src.Length)
            {
                var val = ParseValue();
                arr.Add(val);

                SkipWhitespace();
                if (_idx >= _src.Length)
                    throw Error("Unterminated array");

                if (_src[_idx] == ']')
                {
                    Advance();
                    return arr;
                }
                if (_src[_idx] == ',')
                {
                    Advance();
                    SkipWhitespace();
                    if (_idx < _src.Length && _src[_idx] == ']')
                    {
                        // Allow trailing comma gracefully
                        Advance();
                        return arr;
                    }
                    continue;
                }

                throw Error($"Expected ',' or ']' in array but found '{_src[_idx]}'");
            }

            throw Error("Unterminated array");
        }

        private JsonValue ParseString()
        {
            return JsonValue.From(ParseRawString());
        }

        private string ParseRawString()
        {
            Advance(); // skip opening '"'
            var sb = new StringBuilder();

            while (_idx < _src.Length)
            {
                char c = _src[_idx];
                if (c == '"')
                {
                    Advance();
                    return sb.ToString();
                }
                if (c == '\\')
                {
                    Advance();
                    if (_idx >= _src.Length) throw Error("Unterminated escape sequence");
                    char esc = _src[_idx];
                    Advance();
                    switch (esc)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            if (_idx + 4 > _src.Length) throw Error("Invalid unicode escape");
                            string hex = _src.Substring(_idx, 4);
                            _idx += 4;
                            _col += 4;
                            if (int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int codePoint))
                                sb.Append((char)codePoint);
                            else
                                throw Error($"Invalid unicode escape '\\u{hex}'");
                            break;
                        default:
                            sb.Append(esc);
                            break;
                    }
                    continue;
                }

                sb.Append(c);
                Advance();
            }

            throw Error("Unterminated string");
        }

        private JsonValue ParseNumber()
        {
            int start = _idx;
            if (_idx < _src.Length && _src[_idx] == '-')
                Advance();

            while (_idx < _src.Length && _src[_idx] >= '0' && _src[_idx] <= '9')
                Advance();

            if (_idx < _src.Length && _src[_idx] == '.')
            {
                Advance();
                while (_idx < _src.Length && _src[_idx] >= '0' && _src[_idx] <= '9')
                    Advance();
            }

            if (_idx < _src.Length && (_src[_idx] == 'e' || _src[_idx] == 'E'))
            {
                Advance();
                if (_idx < _src.Length && (_src[_idx] == '+' || _src[_idx] == '-'))
                    Advance();
                while (_idx < _src.Length && _src[_idx] >= '0' && _src[_idx] <= '9')
                    Advance();
            }

            string numStr = _src.Substring(start, _idx - start);
            if (double.TryParse(numStr, NumberStyles.Float, CultureInfo.InvariantCulture, out double val))
                return JsonValue.From(val);

            throw Error($"Invalid number format: '{numStr}'");
        }

        private JsonValue ParseBool()
        {
            if (_src.Substring(_idx).StartsWith("true", StringComparison.Ordinal))
            {
                _idx += 4;
                _col += 4;
                return JsonValue.From(true);
            }
            if (_src.Substring(_idx).StartsWith("false", StringComparison.Ordinal))
            {
                _idx += 5;
                _col += 5;
                return JsonValue.From(false);
            }
            throw Error("Invalid boolean value");
        }

        private JsonValue ParseNull()
        {
            if (_src.Substring(_idx).StartsWith("null", StringComparison.Ordinal))
            {
                _idx += 4;
                _col += 4;
                return JsonValue.Null;
            }
            throw Error("Invalid null literal");
        }

        private void SkipWhitespace()
        {
            while (_idx < _src.Length)
            {
                char c = _src[_idx];
                if (c == ' ' || c == '\t' || c == '\r')
                {
                    Advance();
                }
                else if (c == '\n')
                {
                    _idx++;
                    _line++;
                    _col = 1;
                }
                else if (c == '/' && _idx + 1 < _src.Length && _src[_idx + 1] == '/')
                {
                    // Skip single-line comment
                    _idx += 2;
                    while (_idx < _src.Length && _src[_idx] != '\n')
                        _idx++;
                }
                else
                {
                    break;
                }
            }
        }

        private void Advance()
        {
            _idx++;
            _col++;
        }

        private JsonParseException Error(string msg)
        {
            return new JsonParseException(msg, _line, _col);
        }
    }
}
