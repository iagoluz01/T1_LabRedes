public class App {

    public static void main(String[] args) throws Exception {

        String domain = "www.google.com";

        // Lista de servidores DNS para comparação
        String[] servers = {
            "8.8.8.8",       // Google
            "1.1.1.1",       // Cloudflare
            "9.9.9.9",       // Quad9
            "208.67.222.222" // OpenDNS
        };

        // Monta a query uma única vez
        byte[] query = DnsQueryBuilder.buildQuery(domain);

        for (String server : servers) {
            try {
                // Envia query e recebe resposta
                byte[] response = DnsClient.sendQuery(query, server);

                int rcode = DnsParser.getRcode(response);
                String ip = DnsParser.parseFirstIP(response);

                System.out.println("Servidor: " + server);
                System.out.println("RCODE: " + rcode);
                System.out.println("IP: " + ip);

                // Detecta possíveis bloqueios simples
                if ("0.0.0.0".equals(ip) || "127.0.0.1".equals(ip)) {
                    System.out.println("⚠ Possível bloqueio detectado");
                }

                System.out.println("-----------------------");

            } catch (Exception e) {
                // Timeout ou erro de comunicação
                System.out.println("Servidor: " + server + " -> TIMEOUT/ERRO");
            }
        }
    }
}