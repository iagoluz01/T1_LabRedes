import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class App {

    public static void main(String[] args) throws Exception {

        // Lista de servidores DNS para comparação
        String[] servers = {
            "8.8.8.8",       // Google
            "1.1.1.1",       // Cloudflare
            "9.9.9.9",       // Quad9
            "208.67.222.222" // OpenDNS
        };

        // Lê até 10 domínios do arquivo dominios.txt
        List<String> domains = lerDominios("dominios.txt", 10);

        if (domains.isEmpty()) {
            System.out.println("❌ Nenhum domínio encontrado no arquivo dominios.txt");
            return;
        }

        System.out.println("📋 Testando " + domains.size() + " domínio(s)\n");

        // Testa cada domínio
        for (String domain : domains) {
            System.out.println("🔍 Testando domínio: " + domain);
            System.out.println("=".repeat(50));

            // Monta a query para o domínio
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

                    System.out.println("-".repeat(50));

                } catch (Exception e) {
                    // Timeout ou erro de comunicação
                    System.out.println("Servidor: " + server + " -> TIMEOUT/ERRO");
                    System.out.println("-".repeat(50));
                }
            }
            System.out.println();
        }
    }

    /**
     * Lê domínios de um arquivo txt, limitado a um máximo
     * @param arquivo Path do arquivo
     * @param maximo Número máximo de domínios a ler
     * @return Lista com os domínios lidos
     */
    private static List<String> lerDominios(String arquivo, int maximo) {
        List<String> domains = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(arquivo))) {
            String linha;
            int contador = 0;

            while ((linha = reader.readLine()) != null && contador < maximo) {
                linha = linha.trim();
                // Ignora linhas vazias e comentários
                if (!linha.isEmpty() && !linha.startsWith("#")) {
                    domains.add(linha);
                    contador++;
                }
            }
        } catch (Exception e) {
            System.err.println("❌ Erro ao ler arquivo: " + e.getMessage());
        }

        return domains;
    }
}
