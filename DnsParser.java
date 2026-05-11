public class DnsParser {

    public static int getRcode(byte[] response) {
        // FLAGS ficam nos bytes 2 e 3 do header

        int flags = ((response[2] & 0xFF) << 8) | (response[3] & 0xFF);

        // RCODE são os últimos 4 bits
        return flags & 0x000F;
    }

    public static int skipQuestion(byte[] data, int index) {
        // Pula o nome do domínio (formato com labels)
        while (data[index] != 0) {
            index += (data[index] & 0xFF) + 1;
        }

        index++; // pula o byte 0 final

        index += 4; // pula QTYPE (2 bytes) + QCLASS (2 bytes)

        return index;
    }

    public static String parseFirstIP(byte[] data) {
        // ANCOUNT = número de respostas
        int answerCount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);

        if (answerCount == 0) return null;

        int index = 12; // início após header

        // Pula seção de pergunta
        index = skipQuestion(data, index);

        // NAME → geralmente ponteiro (2 bytes)
        index += 2;

        // TYPE
        int type = ((data[index] & 0xFF) << 8) | (data[index + 1] & 0xFF);
        index += 2;

        index += 2; // CLASS
        index += 4; // TTL

        // Tamanho dos dados
        int rdlength = ((data[index] & 0xFF) << 8) | (data[index + 1] & 0xFF);
        index += 2;

        // Se for registro tipo A (IPv4)
        if (type == 1 && rdlength == 4) {
            return (data[index] & 0xFF) + "." +
                   (data[index+1] & 0xFF) + "." +
                   (data[index+2] & 0xFF) + "." +
                   (data[index+3] & 0xFF);
        }

        return null;
    }
}