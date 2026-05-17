import java.util.List;

/**
 * Estatísticas de desempenho para um servidor DNS.
 */
public class PerformanceStats {

    public final String serverIp;
    public final String serverLabel;
    public final String protocol;
    public final int sent;
    public final int received;
    public final long minMs;
    public final long maxMs;
    public final double avgMs;

    public PerformanceStats(String serverIp, String serverLabel, String protocol,
                            List<Long> times, int sent) {
        this.serverIp = serverIp;
        this.serverLabel = serverLabel;
        this.protocol = protocol;
        this.sent = sent;
        this.received = times.size();

        long min = Long.MAX_VALUE, max = Long.MIN_VALUE, sum = 0;
        for (long t : times) {
            if (t < min) min = t;
            if (t > max) max = t;
            sum += t;
        }
        this.minMs = times.isEmpty() ? 0 : min;
        this.maxMs = times.isEmpty() ? 0 : max;
        this.avgMs = times.isEmpty() ? 0.0 : (double) sum / times.size();
    }

    public double lossRate() {
        return sent == 0 ? 100.0 : (double)(sent - received) / sent * 100.0;
    }
}

