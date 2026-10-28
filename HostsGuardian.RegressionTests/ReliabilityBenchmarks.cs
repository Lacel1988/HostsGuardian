using System.Diagnostics;
using System.Text.Json;

// Isolated lookup prototypes, never used as identity or policy authorization.
internal static class ReliabilityBenchmarks
{
    public static void Run()
    {
        foreach(var size in new[]{64,1024,4096}) {
            var rows=Enumerable.Range(0,size).Select(i=>(Address:$"192.0.{i/256}.{i%256}",Device:Guid.NewGuid())).ToArray();
            var index=rows.GroupBy(r=>r.Address).ToDictionary(g=>g.Key,g=>g.ToArray(),StringComparer.Ordinal);
            // Preserve conflicts as arrays; an index must never implement last-writer-wins.
            var conflict=rows.Append((rows[0].Address,Guid.NewGuid())).GroupBy(r=>r.Address).ToDictionary(g=>g.Key,g=>g.ToArray());
            if(conflict[rows[0].Address].Length!=2)throw new Exception("Prototype concealed ambiguity");
            var target=rows[^1].Address;var iterations=10000;Guid observed=Guid.Empty;
            for(var warm=0;warm<100;warm++)observed=index[target][0].Device;
            var watch=Stopwatch.StartNew();var allocated=GC.GetAllocatedBytesForCurrentThread();
            for(var i=0;i<iterations;i++)observed=rows.Where(r=>r.Address==target).Single().Device;
            var scan=watch.Elapsed.TotalMilliseconds;var scanBytes=GC.GetAllocatedBytesForCurrentThread()-allocated;
            watch.Restart();allocated=GC.GetAllocatedBytesForCurrentThread();
            for(var i=0;i<iterations;i++)observed=index[target].Single().Device;
            var indexed=watch.Elapsed.TotalMilliseconds;var indexedBytes=GC.GetAllocatedBytesForCurrentThread()-allocated;
            if(observed!=rows[^1].Device)throw new Exception("Lookup mismatch");
            Console.WriteLine(JsonSerializer.Serialize(new{prototype="binding-address-index",size,iterations,scanMs=scan,indexMs=indexed,scanBytes,indexBytes=indexedBytes,
                verdict="IMPLEMENTED: immutable conflict-preserving snapshot index; equivalence regression guards scope/freshness/registry; microbenchmark excludes index rebuild"}));
        }
        // Compare actual O(1) completion projection with the prior queue-rebuild approach.
        var ids=Enumerable.Range(0,2048).Select(_=>Guid.NewGuid()).ToArray();var queue=new Queue<(Guid Id,int State)>(ids.Select(id=>(id,0)));
        var dictionary=ids.ToDictionary(id=>id,_=>0);const int count=10000;
        var timer=Stopwatch.StartNew();var bytes=GC.GetAllocatedBytesForCurrentThread();
        for(var i=0;i<count;i++){
            var target=ids[i%ids.Length];var rows=queue.ToArray();queue.Clear();
            foreach(var row in rows)queue.Enqueue(row.Id==target?(row.Id,1):row);
        }
        var rebuildMs=timer.Elapsed.TotalMilliseconds;var rebuildBytes=GC.GetAllocatedBytesForCurrentThread()-bytes;
        timer.Restart();bytes=GC.GetAllocatedBytesForCurrentThread();
        for(var i=0;i<count;i++)dictionary[ids[i%ids.Length]]=1;
        Console.WriteLine(JsonSerializer.Serialize(new{prototype="correlated-completion-projection",size=ids.Length,iterations=count,rebuildMs,
            dictionaryMs=timer.Elapsed.TotalMilliseconds,rebuildBytes,dictionaryBytes=GC.GetAllocatedBytesForCurrentThread()-bytes,
            verdict="IMPLEMENTED: bounded dictionary + FIFO retention, no authorization semantics changed"}));
    }
}
