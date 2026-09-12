using System.Collections.Concurrent;

using Microsoft.Extensions.Time.Testing;

using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

// The exactly-once guarantee is the whole product, so it is stressed under real simultaneity: dedicated
// threads released together by a barrier, rather than pooled tasks the scheduler would quietly serialise.
[Trait("Threat", "T2")]
public sealed class ConcurrencyStressTests
{
    private const int Rounds = 1_000;
    private const int Workers = 64;

    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void SixtyFourSimultaneousConsumers_AcrossAThousandSecrets_YieldExactlyOneWinnerEachTime()
    {
        var clock = new FakeTimeProvider(Now);
        var store = new InMemorySecretStore(clock);
        var ids = Enumerable.Range(0, Rounds).Select(_ => Create(store)).ToArray();
        var outcomes = new ConsumeOutcome[Rounds, Workers];
        var failures = new ConcurrentBag<Exception>();

        RunRounds(Workers, Rounds, (worker, round) =>
        {
            var result = store.TryConsume(ids[round]);
            outcomes[round, worker] = result.Outcome;
            result.Secret?.Dispose();
        }, failures);

        Assert.Empty(failures);
        for (var round = 0; round < Rounds; round++)
        {
            var winners = 0;
            var tombstones = 0;
            for (var worker = 0; worker < Workers; worker++)
            {
                switch (outcomes[round, worker])
                {
                    case ConsumeOutcome.Consumed:
                        winners++;
                        break;
                    case ConsumeOutcome.AlreadyConsumed:
                        tombstones++;
                        break;
                    default:
                        Assert.Fail($"round {round}: a consumer saw {outcomes[round, worker]}, so the Id briefly vanished");
                        break;
                }
            }

            Assert.Equal(1, winners);
            Assert.Equal(Workers - 1, tombstones);
        }

        // Every secret left exactly one tombstone, and consuming released every byte it reserved.
        Assert.Equal(Rounds, store.Count);
        Assert.Equal(0, store.CiphertextBytes);
    }

    [Fact]
    [Trait("Threat", "T6")]
    public void InterleavedCreatesConsumesAndSweeps_LeaveNoLeakedEntryOrByte()
    {
        const int Creators = 4;
        const int Consumers = 4;
        const int PerCreator = 1_500;
        const long ByteCap = 4L * 1024 * 1024;

        var clock = new FakeTimeProvider(Now);
        var store = new InMemorySecretStore(clock, new SecretStoreOptions { MaxEntries = 20_000, MaxTotalCiphertextBytes = ByteCap });
        var live = new ConcurrentQueue<string>();
        var consumedCounts = new ConcurrentDictionary<string, int>();
        var failures = new ConcurrentBag<Exception>();
        var created = 0;
        var sampledOverCap = 0;
        var sampledNegative = 0;
        using var done = new CancellationTokenSource();

        var threads = new List<Thread>();

        for (var c = 0; c < Creators; c++)
        {
            threads.Add(Worker(() =>
            {
                for (var i = 0; i < PerCreator; i++)
                {
                    if (store.Create(Ciphertext(), Nonce(), TimeSpan.FromMinutes(2)) is Created created_)
                    {
                        live.Enqueue(created_.Id);
                        Interlocked.Increment(ref created);
                    }
                }
            }, failures));
        }

        for (var c = 0; c < Consumers; c++)
        {
            threads.Add(Worker(() =>
            {
                while (!done.IsCancellationRequested)
                {
                    if (!live.TryDequeue(out var id))
                    {
                        Thread.SpinWait(50);
                        continue;
                    }

                    var result = store.TryConsume(id);
                    if (result.Outcome == ConsumeOutcome.Consumed)
                    {
                        consumedCounts.AddOrUpdate(id, 1, (_, count) => count + 1);
                        result.Secret!.Dispose();
                    }
                }
            }, failures));
        }

        // The sweeper runs against the same entries the others are creating and consuming, while the clock
        // jumps forward underneath all of them.
        threads.Add(Worker(() =>
        {
            while (!done.IsCancellationRequested)
            {
                store.SweepExpired(256);
                clock.Advance(TimeSpan.FromMilliseconds(200));
            }
        }, failures));

        threads.Add(Worker(() =>
        {
            while (!done.IsCancellationRequested)
            {
                var bytes = store.CiphertextBytes;
                if (bytes < 0)
                {
                    Interlocked.Increment(ref sampledNegative);
                }

                if (bytes > ByteCap)
                {
                    Interlocked.Increment(ref sampledOverCap);
                }
            }
        }, failures));

        foreach (var thread in threads)
        {
            thread.Start();
        }

        // Creators finish on their own; everyone else is told to stop once they have.
        foreach (var thread in threads.Take(Creators))
        {
            thread.Join();
        }

        done.Cancel();
        foreach (var thread in threads.Skip(Creators))
        {
            thread.Join();
        }

        Assert.Empty(failures);
        Assert.Equal(Creators * PerCreator, created);
        Assert.Equal(0, sampledNegative);
        Assert.Equal(0, sampledOverCap);
        Assert.DoesNotContain(consumedCounts, pair => pair.Value != 1);

        // Nothing outlives its TTL: after the clock passes it, sweeping drains the store completely and the
        // byte account returns to zero, so no entry leaked and no byte was counted twice.
        clock.Advance(TimeSpan.FromMinutes(10));
        while (store.SweepExpired(4_096) > 0)
        {
        }

        Assert.Equal(0, store.Count);
        Assert.Equal(0, store.CiphertextBytes);
    }

    private static void RunRounds(int workers, int rounds, Action<int, int> work, ConcurrentBag<Exception> failures)
    {
        using var barrier = new Barrier(workers);
        var threads = Enumerable.Range(0, workers).Select(worker => Worker(() =>
        {
            for (var round = 0; round < rounds; round++)
            {
                // Every worker waits here, so the round starts for all of them at once.
                barrier.SignalAndWait();
                try
                {
                    work(worker, round);
                }
                catch (Exception exception)
                {
                    // Recorded rather than thrown: leaving the barrier would hang every other worker.
                    failures.Add(exception);
                }
            }
        }, failures)).ToList();

        foreach (var thread in threads)
        {
            thread.Start();
        }

        foreach (var thread in threads)
        {
            thread.Join();
        }
    }

    private static Thread Worker(Action body, ConcurrentBag<Exception> failures)
    {
        return new Thread(() =>
        {
            try
            {
                body();
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        })
        { IsBackground = true };
    }

    private static string Create(InMemorySecretStore store)
    {
        return Assert.IsType<Created>(store.Create(Ciphertext(), Nonce(), TimeSpan.FromHours(1))).Id;
    }

    private static byte[] Ciphertext() => new byte[32];

    private static byte[] Nonce() => new byte[12];
}
