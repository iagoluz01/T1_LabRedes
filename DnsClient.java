import java.net.*;

public class DnsClient {

    public static byte[] sendQuery(byte[] query, String dnsServer) throws Exception {
        // Cria socket UDP
        DatagramSocket socket = new DatagramSocket();

        // Define timeout → evita travar se servidor não responder
        socket.setSoTimeout(2000);

        // Resolve o IP do servidor DNS (ex: 8.8.8.8)
        InetAddress address = InetAddress.getByName(dnsServer);

        // Monta pacote UDP para envio
        DatagramPacket packet = new DatagramPacket(query, query.length, address, 53);

        // Marca tempo antes de enviar (para medir latência)
        long start = System.currentTimeMillis();

        socket.send(packet); // envia query

        // Buffer para resposta (DNS padrão cabe em 512 bytes)
        byte[] buffer = new byte[512];
        DatagramPacket response = new DatagramPacket(buffer, buffer.length);

        // Aguarda resposta
        socket.receive(response);

        long end = System.currentTimeMillis();

        System.out.println("Tempo de resposta: " + (end - start) + " ms");

        socket.close();

        // Retorna os dados recebidos
        return response.getData();
    }
}