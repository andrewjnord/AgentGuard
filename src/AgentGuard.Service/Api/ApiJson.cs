using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using AgentGuard.Core;

namespace AgentGuard.Service.Api;

/// <summary>JSON for the HTTP API and the event stream: the core options plus ISO-8601 UTC timestamps ("2026-10-08T22:31:04.123Z").</summary>
public static class ApiJson
{
    public static readonly JsonSerializerOptions Options = Create();

    public static void Apply(JsonSerializerOptions o)
    {
        o.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        o.DictionaryKeyPolicy = null;
        o.PropertyNameCaseInsensitive = true;
        o.NumberHandling = JsonNumberHandling.AllowReadingFromString;
        o.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        o.Converters.Add(new UtcTimestampConverter());
        o.Converters.Add(new NullableUtcTimestampConverter());
    }

    private static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        Apply(o);
        return o;
    }

    public static string Serialize(object? value) => JsonSerializer.Serialize(value, value?.GetType() ?? typeof(object), Options);

    public static string Format(DateTimeOffset ts) => ts.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    private sealed class UtcTimestampConverter : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            DateTimeOffset.Parse(reader.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) => writer.WriteStringValue(Format(value));
    }

    private sealed class NullableUtcTimestampConverter : JsonConverter<DateTimeOffset?>
    {
        public override DateTimeOffset? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            reader.TokenType == JsonTokenType.Null ? null : DateTimeOffset.Parse(reader.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        public override void Write(Utf8JsonWriter writer, DateTimeOffset? value, JsonSerializerOptions options)
        {
            if (value is null) writer.WriteNullValue();
            else writer.WriteStringValue(Format(value.Value));
        }
    }
}
