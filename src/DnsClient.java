import java.net.*;

/**
 * Cliente DNS sobre UDP (porta 53) — construção e envio manual de pacotes binários.
 */
public class DnsClient {

    /** Último tempo de resposta registrado (ms) — disponível após cada sendQuery(). */
    public static long lastResponseTimeMs = -1;

    /**
     * Envia uma query DNS via UDP e retorna os bytes da resposta.
     *
     * @param query     bytes da query DNS
     * @param dnsServer IP do servidor DNS
     * @return bytes brutos da resposta
     * @throws Exception em caso de timeout ou erro de rede
     */
    public static byte[] sendQuery(byte[] query, String dnsServer) throws Exception {
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(2000);

        InetAddress address = InetAddress.getByName(dnsServer);
        DatagramPacket packet = new DatagramPacket(query, query.length, address, 53);

        long start = System.currentTimeMillis();
        socket.send(packet);

        byte[] buffer = new byte[1024];
        DatagramPacket response = new DatagramPacket(buffer, buffer.length);
        socket.receive(response);
        long end = System.currentTimeMillis();

        lastResponseTimeMs = end - start;
        socket.close();

        // Retorna apenas os bytes efetivamente recebidos
        byte[] data = new byte[response.getLength()];
        System.arraycopy(buffer, 0, data, 0, response.getLength());
        return data;
    }

    /**
     * Envia query DNS e retorna um DnsResult já preenchido com IPs e tempo.
     */
    public static DnsResult query(String domain, String serverIp, String label) {
        DnsResult result = new DnsResult(serverIp, label, domain, false);
        try {
            byte[] queryBytes = DnsQueryBuilder.buildQuery(domain);
            byte[] responseBytes = sendQuery(queryBytes, serverIp);
            result.responseTimeMs = lastResponseTimeMs;
            result.rcode = DnsParser.getRcode(responseBytes);
            result.ips = DnsParser.parseAllIPs(responseBytes);
        } catch (java.net.SocketTimeoutException e) {
            result.timeout = true;
            result.errorMsg = "TIMEOUT";
        } catch (Exception e) {
            result.timeout = true;
            result.errorMsg = e.getMessage();
        }
        return result;
    }
}
