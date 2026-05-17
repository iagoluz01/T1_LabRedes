import java.util.*;
import java.util.stream.*;

/**
 * Detecta bloqueios e manipulações nas respostas DNS.
 */
public class BlockDetector {

    // Servidores considerados "sem filtragem" para o cálculo de consenso
    private static final Set<String> BASELINE_SERVERS = new HashSet<>(Arrays.asList(
            "8.8.8.8", "1.1.1.1", "64.6.64.6", "9.9.9.10", "8.8.4.4", "1.0.0.1"
    ));

    /**
     * Determina o IP de consenso baseado nos servidores sem filtragem.
     */
    public static String getConsensusIP(List<DnsResult> results) {
        Map<String, Long> counts = results.stream()
                .filter(r -> BASELINE_SERVERS.contains(r.serverIp))
                .filter(r -> !r.ips.isEmpty() && r.rcode == 0)
                .flatMap(r -> r.ips.stream())
                .collect(Collectors.groupingBy(ip -> ip, Collectors.counting()));

        // fallback: use todos os servidores se baseline não retornar
        if (counts.isEmpty()) {
            counts = results.stream()
                    .filter(r -> !r.ips.isEmpty() && r.rcode == 0)
                    .flatMap(r -> r.ips.stream())
                    .collect(Collectors.groupingBy(ip -> ip, Collectors.counting()));
        }

        return counts.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(null);
    }

    /**
     * Analisa o motivo de bloqueio de um resultado individual.
     */
    public static String detectBlock(DnsResult result, String consensusIP) {
        if (result.timeout)       return "TIMEOUT";
        if (result.rcode == 5)    return "REFUSED";
        if (result.rcode == 3)    return "NXDOMAIN";
        if (result.rcode == 2)    return "SERVFAIL";
        if (result.rcode != 0)    return "RCODE_ERR";

        if (!result.ips.isEmpty()) {
            String ip = result.ips.get(0);
            if ("0.0.0.0".equals(ip) || "127.0.0.1".equals(ip)) {
                return "NULL_IP";
            }
            if (consensusIP != null && !result.ips.contains(consensusIP)) {
                return "IP_DIVERGENTE";
            }
        }

        if (result.rcode == 0 && result.ips.isEmpty()) {
            return "SEM_REGISTROS";
        }

        return null; // sem bloqueio
    }

    /**
     * Anota blockReason em cada resultado de uma lista para o mesmo domínio.
     */
    public static void annotate(List<DnsResult> results) {
        String consensus = getConsensusIP(results);
        for (DnsResult r : results) {
            r.blockReason = detectBlock(r, consensus);
        }
    }
}

