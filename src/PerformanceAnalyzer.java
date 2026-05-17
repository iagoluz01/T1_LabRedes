import java.util.ArrayList;
import java.util.List;

/**
 * Executa testes de desempenho: 10 consultas por servidor e calcula estatísticas.
 */
public class PerformanceAnalyzer {

    public static final int NUM_QUERIES = 10;

    /**
     * Testa desempenho UDP para um domínio em um servidor específico.
     */
    public static PerformanceStats testUDP(String domain, String serverIp, String label) {
        List<Long> times = new ArrayList<>();
        int sent = NUM_QUERIES;

        for (int i = 0; i < NUM_QUERIES; i++) {
            try {
                byte[] query = DnsQueryBuilder.buildQuery(domain);
                long start = System.currentTimeMillis();
                DnsClient.sendQuery(query, serverIp);
                long end = System.currentTimeMillis();
                times.add(end - start);
            } catch (Exception ignored) {
                // conta como perda
            }
        }

        return new PerformanceStats(serverIp, label, "UDP", times, sent);
    }

    /**
     * Testa desempenho DoT para um domínio.
     */
    public static PerformanceStats testDoT(String domain, String serverIp,
                                           String hostname, String label) {
        List<Long> times = new ArrayList<>();
        int sent = NUM_QUERIES;

        for (int i = 0; i < NUM_QUERIES; i++) {
            try {
                byte[] query = DnsQueryBuilder.buildQuery(domain);
                DnsResult r = DnsClientDoT.sendQuery(query, serverIp, hostname, label, domain);
                if (!r.timeout && r.responseTimeMs >= 0) {
                    times.add(r.responseTimeMs);
                }
            } catch (Exception ignored) {
                // conta como perda
            }
        }

        return new PerformanceStats(serverIp, label, "DoT", times, sent);
    }
}

