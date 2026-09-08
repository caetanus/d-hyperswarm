/// Kademlia routing table, ported from holepunchto/kademlia-routing-table. Nodes
/// are bucketed by the XOR-distance prefix from the local id; each bucket (row)
/// keeps up to k nodes sorted by id. `closest(target, k)` returns the table's best
/// guess at the k nodes nearest a target — the seed for an iterative query.
module hyperswarm.dht.table;

struct Node
{
    ubyte[32] id;
    string host;
    ushort port;
}

private final class Row
{
    int byteOffset;
    Node[] nodes;

    this(int index)
    {
        byteOffset = index >> 3;
    }

    // Compare two ids from byteOffset onward (they share the bucket prefix).
    private int cmp(const(ubyte)[] a, const(ubyte)[] b) const
    {
        for (size_t i = byteOffset; i < a.length; i++)
        {
            if (a[i] == b[i])
                continue;
            return a[i] < b[i] ? -1 : 1;
        }
        return 0;
    }

    bool add(Node node, int k)
    {
        int l = 0, r = cast(int) nodes.length - 1;
        while (l <= r)
        {
            immutable m = (l + r) >> 1;
            immutable c = cmp(node.id[], nodes[m].id[]);
            if (c == 0)
            {
                nodes[m] = node;
                return true;
            }
            if (c < 0)
                r = m - 1;
            else
                l = m + 1;
        }
        if (nodes.length >= k)
            return false;
        nodes.length++;
        for (int j = cast(int) nodes.length - 1; j > l; j--)
            nodes[j] = nodes[j - 1];
        nodes[l] = node;
        return true;
    }

    Node* get(const(ubyte)[] id)
    {
        int l = 0, r = cast(int) nodes.length - 1;
        while (l <= r)
        {
            immutable m = (l + r) >> 1;
            immutable c = cmp(id, nodes[m].id[]);
            if (c == 0)
                return &nodes[m];
            if (c < 0)
                r = m - 1;
            else
                l = m + 1;
        }
        return null;
    }

    bool remove(const(ubyte)[] id)
    {
        foreach (i, ref n; nodes)
            if (cmp(id, n.id[]) == 0)
            {
                foreach (j; i .. nodes.length - 1)
                    nodes[j] = nodes[j + 1];
                nodes.length--;
                return true;
            }
        return false;
    }
}

final class RoutingTable
{
    ubyte[32] id;
    int k;
    size_t size;
    private Row[256] rows;

    this(ubyte[32] id, int k = 20)
    {
        this.id = id;
        this.k = k;
    }

    // Index of the first bit where `id` differs from the local id (0 = MSB).
    private int diff(const(ubyte)[] other) const
    {
        foreach (i; 0 .. id.length)
        {
            immutable a = other[i], b = id[i];
            if (a != b)
                return cast(int)(i * 8 + clz8(cast(ubyte)(a ^ b)));
        }
        return cast(int) rows.length - 1;
    }

    bool add(Node node)
    {
        immutable i = diff(node.id[]);
        if (rows[i] is null)
            rows[i] = new Row(i);
        immutable before = rows[i].nodes.length;
        if (!rows[i].add(node, k))
            return false;
        size += rows[i].nodes.length - before;
        return true;
    }

    bool remove(const(ubyte)[] id)
    {
        immutable i = diff(id);
        if (rows[i] is null || !rows[i].remove(id))
            return false;
        size--;
        return true;
    }

    Node* get(const(ubyte)[] id)
    {
        immutable i = diff(id);
        return rows[i] is null ? null : rows[i].get(id);
    }

    /// The k nodes the table believes are closest to `target`: from the target's
    /// bucket outward (nearer buckets first, then farther), per the Kademlia paper.
    Node[] closest(const(ubyte)[] target, int want = 0)
    {
        if (want <= 0)
            want = k;
        Node[] result;
        immutable d = diff(target);
        for (int i = d; i >= 0 && result.length < want; i--)
            pushRow(i, want, result);
        for (int i = d + 1; i < cast(int) rows.length && result.length < want; i++)
            pushRow(i, want, result);
        return result;
    }

    private void pushRow(int i, int want, ref Node[] result)
    {
        if (rows[i] is null)
            return;
        immutable missing = want - cast(int) result.length;
        immutable n = missing < cast(int) rows[i].nodes.length ? missing : cast(int) rows[i].nodes.length;
        foreach (j; 0 .. n)
            result ~= rows[i].nodes[j];
    }
}

/// Count leading zero bits of a nonzero byte (matches clz32(v)-24 for v in 1..255).
private int clz8(ubyte v)
{
    int n = 0;
    foreach_reverse (b; 0 .. 8)
    {
        if (v & (1 << b))
            break;
        n++;
    }
    return n;
}

/// XOR-distance comparison to a target: -1 if a is closer, 1 if b is closer, 0 equal.
/// The precise metric the iterative query sorts replies by.
int compareDistance(const(ubyte)[] a, const(ubyte)[] b, const(ubyte)[] target)
{
    foreach (i; 0 .. target.length)
    {
        immutable da = a[i] ^ target[i];
        immutable db = b[i] ^ target[i];
        if (da != db)
            return da < db ? -1 : 1;
    }
    return 0;
}
