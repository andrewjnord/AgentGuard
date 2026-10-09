using System.Collections.Concurrent;
using System.Threading.Channels;

namespace AgentGuard.Service.Services;

/// <summary>A message for live subscribers (dashboard SSE, tray app, exporters).</summary>
public sealed record BusMessage(string Type, object Data);

/// <summary>In-process fan-out of live updates. Slow subscribers drop their oldest messages rather than blocking the service.</summary>
public sealed class EventBus
{
    private readonly ConcurrentDictionary<Guid, Channel<BusMessage>> _subscribers = new();

    public int SubscriberCount => _subscribers.Count;

    public Subscription Subscribe(int capacity = 2000)
    {
        var id = Guid.NewGuid();
        var channel = Channel.CreateBounded<BusMessage>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });
        _subscribers[id] = channel;
        return new Subscription(channel.Reader, () => _subscribers.TryRemove(id, out _));
    }

    public void Publish(string type, object data)
    {
        var msg = new BusMessage(type, data);
        foreach (var ch in _subscribers.Values) ch.Writer.TryWrite(msg);
    }

    public sealed class Subscription : IDisposable
    {
        private readonly Action _dispose;
        public ChannelReader<BusMessage> Reader { get; }

        public Subscription(ChannelReader<BusMessage> reader, Action dispose)
        {
            Reader = reader;
            _dispose = dispose;
        }

        public void Dispose() => _dispose();
    }
}
