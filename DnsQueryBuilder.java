import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Random;

public class DnsQueryBuilder {

    public static byte[] buildQuery(String domain) throws Exception {
        // Buffer para montar o pacote binário em memória
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // ID aleatório da requisição (usado para casar resposta com requisição)
        Random rand = new Random();
        short id = (short) rand.nextInt(0xFFFF);

        // ===== HEADER DNS (12 bytes) =====

        dos.writeShort(id);       // ID (2 bytes)

        // FLAGS:
        // 0x0100 = query padrão + recursion desired (RD = 1)
        dos.writeShort(0x0100);

        dos.writeShort(1);        // QDCOUNT → número de perguntas (1)
        dos.writeShort(0);        // ANCOUNT → respostas (0 na query)
        dos.writeShort(0);        // NSCOUNT → authority (0)
        dos.writeShort(0);        // ARCOUNT → additional (0)

        // ===== QUESTION SECTION =====

        writeDomain(dos, domain); // Nome do domínio no formato DNS

        dos.writeShort(1); // QTYPE = 1 → tipo A (IPv4)
        dos.writeShort(1); // QCLASS = 1 → IN (Internet)

        // Retorna o pacote completo em formato binário
        return baos.toByteArray();
    }

    private static void writeDomain(DataOutputStream dos, String domain) throws Exception {
        // DNS NÃO usa string "www.google.com" direto.
        // Ele usa blocos com tamanho + conteúdo:
        // 3www6google3com0

        String[] labels = domain.split("\\.");

        for (String label : labels) {
            dos.writeByte(label.length()); // tamanho do label
            dos.writeBytes(label);         // conteúdo do label
        }

        dos.writeByte(0); // byte 0 indica fim do domínio
    }
}