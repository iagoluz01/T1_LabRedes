import java.util.*;
import java.io.*;

/**
 * Ferramenta de análise DNS — Trabalho 1 (Lab de Redes)
 *
 * Parte 1: Scanner DNS multi-servidor (UDP) + detecção de bloqueio + desempenho
 * Parte 3: DNS over TLS (DoT) e comparação com UDP
 */
public class App {

    // =========================================================================
    // Servidores DNS
    // =========================================================================

    static class Server {
        final String ip;
        final String label;
        final String hostname; // para DoT (SNI); null = não suporta DoT
        Server(String ip, String label, String hostname) {
            this.ip = ip; this.label = label; this.hostname = hostname;
        }
        Server(String ip, String label) { this(ip, label, null); }
    }

    static final Server[] SERVERS = {
        // --- Sem filtragem ---
        new Server("8.8.8.8",          "Google",              "dns.google"),
        new Server("8.8.4.4",          "Google (sec)",        "dns.google"),
        new Server("1.1.1.1",          "Cloudflare",          "one.one.one.one"),
        new Server("1.0.0.1",          "Cloudflare (sec)",    "one.one.one.one"),
        new Server("9.9.9.10",         "Quad9 (sem filtro)",  "dns.quad9.net"),
        new Server("64.6.64.6",        "Verisign"),
        // --- Com filtragem de segurança ---
        new Server("9.9.9.9",          "Quad9",               "dns.quad9.net"),
        new Server("208.67.222.222",   "OpenDNS"),
        new Server("185.228.168.9",    "CleanBrowsing Sec"),
        new Server("94.140.14.14",     "AdGuard DNS"),
        // --- Com filtragem familiar ---
        new Server("1.1.1.3",          "Cloudflare Family"),
        new Server("208.67.222.123",   "OpenDNS Family"),
        new Server("185.228.168.168",  "CleanBrowsing Family"),
        new Server("94.140.14.15",     "AdGuard Family"),
        // --- Adicionais (5+) ---
        new Server("8.26.56.26",       "Comodo Secure"),
        new Server("76.76.2.0",        "Control D"),
        new Server("189.40.100.100",   "TIM Brasil"),
        new Server("200.248.178.54",   "Claro Brasil"),
        new Server("186.224.0.18",     "Oi Brasil"),
    };

    // Servidores com suporte DoT para a Parte 3
    static final Server[] DOT_SERVERS = {
        new Server("8.8.8.8",   "Google",     "dns.google"),
        new Server("1.1.1.1",   "Cloudflare", "one.one.one.one"),
        new Server("9.9.9.9",   "Quad9",      "dns.quad9.net"),
    };

    // =========================================================================
    // Domínios de teste
    // =========================================================================

    static final String[] DOMAINS = {
        "www.example.com",       // controle — nenhum servidor deve bloquear
        "www.pucrs.br",          // controle regional
        "internetbadguys.com",   // teste OpenDNS — bloqueado por filtros de segurança
        "reddit.com",            // rede social — potencialmente bloqueado (filtros familiares)
        "tinder.com",            // app de encontros — bloqueado em filtros familiares
        "polymarket.com",        // bloqueado no Brasil por determinação judicial (Anatel)
        "www.piratebay.org",     // compartilhamento — bloqueado em vários países
        "bet365.com",            // apostas — potencialmente bloqueado no Brasil
        "xvideos.com",           // conteúdo adulto — bloqueado por filtros familiares
    };

    static final String PERF_DOMAIN = "www.example.com"; // domínio de controle para performance

    // =========================================================================
    // Utilitários de formatação
    // =========================================================================

    static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }

    static void sep(char c, int n) { System.out.println(repeat(String.valueOf(c), n)); }
    static void header(String title) {
        System.out.println();
        sep('=', 80);
        System.out.println("  " + title);
        sep('=', 80);
    }
    static void subheader(String title) {
        System.out.println("\n  >>> " + title);
        sep('-', 80);
    }

    static String pad(String s, int len) {
        if (s == null) s = "";
        if (s.length() >= len) return s.substring(0, len);
        return s + repeat(" ", len - s.length());
    }

    // =========================================================================
    // Parte 1-A: Scanner multi-servidor
    // =========================================================================

    static void runScanner() {
        header("PARTE 1-A — SCANNER DNS MULTI-SERVIDOR (UDP)");

        for (String domain : DOMAINS) {
            subheader("Domínio: " + domain);

            List<DnsResult> results = new ArrayList<>();
            for (Server srv : SERVERS) {
                System.out.print("  Consultando " + pad(srv.label, 22) + " (" + pad(srv.ip, 17) + ") ... ");
                DnsResult r = DnsClient.query(domain, srv.ip, srv.label);
                results.add(r);
                String status = r.timeout ? "TIMEOUT" : r.getRcodeName();
                System.out.println(status + (r.responseTimeMs >= 0 ? "  [" + r.responseTimeMs + " ms]" : ""));
            }

            // Anota bloqueios
            BlockDetector.annotate(results);
            String consensus = BlockDetector.getConsensusIP(results);

            System.out.println();
            System.out.printf("  %-22s  %-17s  %-10s  %-8s  %-20s  %s%n",
                    "Servidor", "IP Servidor", "RCODE", "Tempo", "IPs Retornados", "Bloqueio?");
            sep('-', 110);

            for (DnsResult r : results) {
                String ips = r.ips.isEmpty() ? "-" : String.join(", ", r.ips);
                if (ips.length() > 40) ips = ips.substring(0, 37) + "...";
                String block = r.blockReason != null ? ("⚠ " + r.blockReason) : "OK";
                String tempo = r.responseTimeMs >= 0 ? r.responseTimeMs + " ms" : "-";
                System.out.printf("  %-22s  %-17s  %-10s  %-8s  %-40s  %s%n",
                        pad(r.serverLabel, 22), pad(r.serverIp, 17),
                        r.getRcodeName(), tempo, ips, block);
            }

            // Resumo de consenso
            System.out.println();
            System.out.println("  IP de Consenso (servidores sem filtro): " + (consensus != null ? consensus : "(nenhum)"));
            long blocked = results.stream().filter(r -> r.blockReason != null).count();
            System.out.println("  Servidores com bloqueio/anomalia detectada: " + blocked + " / " + results.size());
        }
    }

    // =========================================================================
    // Parte 1-B: Avaliação de desempenho
    // =========================================================================

    static void runPerformance() {
        header("PARTE 1-B — AVALIAÇÃO DE DESEMPENHO (" + PerformanceAnalyzer.NUM_QUERIES + " consultas — " + PERF_DOMAIN + ")");

        List<PerformanceStats> stats = new ArrayList<>();
        for (Server srv : SERVERS) {
            System.out.println("  Testando " + srv.label + " (" + srv.ip + ") ...");
            stats.add(PerformanceAnalyzer.testUDP(PERF_DOMAIN, srv.ip, srv.label));
        }

        // Ordena por tempo médio
        stats.sort(Comparator.comparingDouble(s -> (s.received == 0 ? Double.MAX_VALUE : s.avgMs)));

        System.out.println();
        System.out.printf("  %-3s  %-22s  %-17s  %8s  %8s  %8s  %8s  %7s%n",
                "#", "Servidor", "IP", "Mín(ms)", "Méd(ms)", "Máx(ms)", "Receb.", "Perda%");
        sep('-', 95);

        for (int i = 0; i < stats.size(); i++) {
            PerformanceStats s = stats.get(i);
            System.out.printf("  %-3d  %-22s  %-17s  %8.0f  %8.1f  %8.0f  %8s  %6.1f%%%n",
                    i + 1, pad(s.serverLabel, 22), pad(s.serverIp, 17),
                    (double) s.minMs, s.avgMs, (double) s.maxMs,
                    s.received + "/" + s.sent, s.lossRate());
        }
    }

    // =========================================================================
    // Parte 3: DNS over TLS
    // =========================================================================

    static void runDoT() {
        header("PARTE 3 — DNS OVER TLS (DoT) — RFC 7858, Porta 853");

        // 3-A: Scanner DoT para todos os domínios
        subheader("3-A: Consultas DoT para todos os domínios");

        for (String domain : DOMAINS) {
            System.out.println("\n  Domínio: " + domain);
            System.out.printf("  %-22s  %-17s  %-10s  %-8s  %-30s  %s%n",
                    "Servidor", "IP", "RCODE", "Tempo", "IPs Retornados", "Bloqueio?");
            sep('-', 100);

            List<DnsResult> dotResults = new ArrayList<>();
            for (Server srv : DOT_SERVERS) {
                try {
                    byte[] query = DnsQueryBuilder.buildQuery(domain);
                    DnsResult r = DnsClientDoT.sendQuery(query, srv.ip, srv.hostname, srv.label, domain);
                    dotResults.add(r);
                    String ips = r.ips.isEmpty() ? "-" : String.join(", ", r.ips);
                    String tempo = r.responseTimeMs >= 0 ? r.responseTimeMs + " ms" : "-";
                    BlockDetector.annotate(dotResults);
                    String block = r.blockReason != null ? ("⚠ " + r.blockReason) : "OK";
                    System.out.printf("  %-22s  %-17s  %-10s  %-8s  %-30s  %s%n",
                            pad(r.serverLabel, 22), pad(srv.ip, 17),
                            r.getRcodeName(), tempo, ips, block);
                } catch (Exception e) {
                    System.out.printf("  %-22s  ERRO: %s%n", srv.label, e.getMessage());
                }
            }
        }

        // 3-B: Comparação de desempenho UDP vs DoT
        subheader("3-B: Comparação de Desempenho UDP vs DoT — " + PerformanceAnalyzer.NUM_QUERIES + " consultas — " + PERF_DOMAIN);

        System.out.printf("  %-22s  %-8s  %8s  %8s  %8s  %7s%n",
                "Servidor", "Protocolo", "Mín(ms)", "Méd(ms)", "Máx(ms)", "Perda%");
        sep('-', 80);

        for (Server srv : DOT_SERVERS) {
            // UDP
            PerformanceStats udp = PerformanceAnalyzer.testUDP(PERF_DOMAIN, srv.ip, srv.label);
            System.out.printf("  %-22s  %-8s  %8.0f  %8.1f  %8.0f  %6.1f%%%n",
                    pad(srv.label, 22), "UDP",
                    (double) udp.minMs, udp.avgMs, (double) udp.maxMs, udp.lossRate());

            // DoT
            PerformanceStats dot = PerformanceAnalyzer.testDoT(PERF_DOMAIN, srv.ip, srv.hostname, srv.label);
            System.out.printf("  %-22s  %-8s  %8.0f  %8.1f  %8.0f  %6.1f%%%n",
                    pad(srv.label, 22), "DoT",
                    (double) dot.minMs, dot.avgMs, (double) dot.maxMs, dot.lossRate());
            sep('-', 80);
        }

        System.out.println();
        System.out.println("  NOTA: O DoT envolve handshake TLS (~1-3 RTTs extras), resultando em latência");
        System.out.println("  maior que o UDP, mas as consultas são completamente cifradas (inobserváveis");
        System.out.println("  por ISPs/intermediários). O conteúdo trafegado na porta 853 é opaco ao");
        System.out.println("  Wireshark, ao contrário das consultas UDP na porta 53.");
    }

    // =========================================================================
    // main
    // =========================================================================

    public static void main(String[] args) throws Exception {
        // Redireciona output para arquivo e console
        DualOutput dualOutput = new DualOutput(System.out, "resultado.txt");
        System.setOut(new PrintStream(dualOutput, true));

        try {
            System.out.println();
            sep('*', 80);
            System.out.println("  ANÁLISE DE DNS: Censura, Desempenho e Privacidade");
            System.out.println("  Trabalho 1 — Lab de Redes de Computadores");
            sep('*', 80);
            System.out.println("  Servidores configurados : " + SERVERS.length);
            System.out.println("  Domínios de teste       : " + DOMAINS.length);
            System.out.println("  Consultas de desempenho : " + PerformanceAnalyzer.NUM_QUERIES + " por servidor");

            // Parte 1
            runScanner();
            runPerformance();

            // Parte 3 (Extra)
            runDoT();

            header("FIM DA ANÁLISE");
        } finally {
            System.out.flush();
            dualOutput.close();
        }
    }
}
