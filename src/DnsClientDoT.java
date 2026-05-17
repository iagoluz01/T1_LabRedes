import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.util.Collections;
import java.util.List;

/**
 * Cliente DNS over TLS (DoT) conforme RFC 7858.
 * Usa TCP + TLS na porta 853.
 * As mensagens DNS são prefixadas com 2 bytes indicando o tamanho.
 */
public class DnsClientDoT {

    private static final int DOT_PORT = 853;
    private static final int TIMEOUT_MS = 5000;

    /**
     * Envia uma query DNS via DoT e retorna um DnsResult com IPs e tempo.
     *
     * @param query     bytes da query DNS (sem prefixo de tamanho)
     * @param serverIp  IP do servidor (para conexão)
     * @param hostname  hostname do servidor (para SNI / validação TLS)
     * @param label     rótulo legível do servidor
     * @param domain    domínio consultado
     */
    public static DnsResult sendQuery(byte[] query, String serverIp, String hostname,
                                      String label, String domain) {
        DnsResult result = new DnsResult(serverIp, label + " (DoT)", domain, true);

        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

            long start = System.currentTimeMillis();

            // Conecta pelo IP mas usa hostname para SNI
            InetAddress addr = InetAddress.getByName(serverIp);
            SSLSocket socket = (SSLSocket) factory.createSocket(addr, DOT_PORT);
            socket.setSoTimeout(TIMEOUT_MS);

            // Configura SNI explicitamente
            SSLParameters params = socket.getSSLParameters();
            params.setServerNames(Collections.singletonList(new SNIHostName(hostname)));
            socket.setSSLParameters(params);

            socket.startHandshake();

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            // Prefixo de 2 bytes com tamanho da mensagem (RFC 7858)
            out.writeShort(query.length);
            out.write(query);
            out.flush();

            DataInputStream in = new DataInputStream(socket.getInputStream());
            // Lê os 2 bytes do tamanho da resposta
            int responseLen = in.readUnsignedShort();
            byte[] responseData = new byte[responseLen];
            in.readFully(responseData);

            long end = System.currentTimeMillis();
            result.responseTimeMs = end - start;
            socket.close();

            // Parseia resposta
            result.rcode = DnsParser.getRcode(responseData);
            result.ips = DnsParser.parseAllIPs(responseData);

        } catch (SocketTimeoutException e) {
            result.timeout = true;
            result.errorMsg = "TIMEOUT";
        } catch (Exception e) {
            result.timeout = true;
            result.errorMsg = e.getMessage();
        }

        return result;
    }
}
