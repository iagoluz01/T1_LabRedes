import java.util.ArrayList;
import java.util.List;

/**
 * Interpreta respostas DNS binárias (RFC 1035).
 * Suporta compressão de nomes (ponteiros 0xC0xx).
 */
public class DnsParser {

    // -------------------------------------------------------------------------
    // Campos do Header (offsets fixos)
    // -------------------------------------------------------------------------

    /** Extrai o RCODE dos bytes 2–3 do header DNS. */
    public static int getRcode(byte[] data) {
        int flags = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        return flags & 0x000F;
    }

    /** Retorna o número de perguntas (QDCOUNT). */
    public static int getQdcount(byte[] data) {
        return ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
    }

    /** Retorna o número de respostas (ANCOUNT). */
    public static int getAncount(byte[] data) {
        return ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
    }

    // -------------------------------------------------------------------------
    // Navegação no buffer
    // -------------------------------------------------------------------------

    /**
     * Avança o índice além de um nome DNS (labels ou ponteiro de compressão).
     * Retorna o índice do próximo byte após o nome.
     */
    public static int skipName(byte[] data, int index) {
        while (index < data.length) {
            int len = data[index] & 0xFF;
            if (len == 0) {
                return index + 1;          // fim de nome
            } else if ((len & 0xC0) == 0xC0) {
                return index + 2;          // ponteiro de 2 bytes — nome termina aqui
            } else {
                index += len + 1;          // label: pula comprimento + conteúdo
            }
        }
        return index;
    }

    /**
     * Lê e monta um nome DNS como string (ex: "www.google.com").
     * Suporta ponteiros de compressão de forma recursiva.
     */
    public static String readName(byte[] data, int index) {
        StringBuilder sb = new StringBuilder();
        boolean firstLabel = true;
        int safetyLimit = 0;

        while (index < data.length && safetyLimit++ < 128) {
            int len = data[index] & 0xFF;

            if (len == 0) break;

            if ((len & 0xC0) == 0xC0) {
                // Ponteiro: 2 bytes, bits superiores = 11
                int ptr = ((len & 0x3F) << 8) | (data[index + 1] & 0xFF);
                if (!firstLabel) sb.append('.');
                sb.append(readName(data, ptr));
                return sb.toString();
            } else {
                if (!firstLabel) sb.append('.');
                firstLabel = false;
                index++;
                sb.append(new String(data, index, len));
                index += len;
            }
        }
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Parsing de registros de resposta
    // -------------------------------------------------------------------------

    /**
     * Retorna todos os endereços IPv4 (registros tipo A) presentes na seção de respostas.
     */
    public static List<String> parseAllIPs(byte[] data) {
        List<String> ips = new ArrayList<>();

        int answerCount = getAncount(data);
        if (answerCount == 0) return ips;

        int index = 12; // início após header de 12 bytes

        // Pula seção de perguntas
        int qdcount = getQdcount(data);
        for (int i = 0; i < qdcount; i++) {
            index = skipName(data, index);
            index += 4; // QTYPE (2) + QCLASS (2)
        }

        // Itera sobre os registros de resposta
        for (int i = 0; i < answerCount && index + 10 < data.length; i++) {
            index = skipName(data, index); // NAME (pode ser ponteiro)

            int type  = ((data[index]     & 0xFF) << 8) | (data[index + 1] & 0xFF);
            index += 2; // TYPE
            index += 2; // CLASS
            index += 4; // TTL

            int rdlen = ((data[index] & 0xFF) << 8) | (data[index + 1] & 0xFF);
            index += 2; // RDLENGTH

            if (type == 1 && rdlen == 4 && index + 4 <= data.length) {
                // Registro A — IPv4
                String ip = (data[index]     & 0xFF) + "." +
                            (data[index + 1] & 0xFF) + "." +
                            (data[index + 2] & 0xFF) + "." +
                            (data[index + 3] & 0xFF);
                ips.add(ip);
            }
            // Pula RDATA (CNAME, MX, AAAA, etc. são ignorados)
            index += rdlen;
        }

        return ips;
    }

    /** Compatibilidade retroativa: retorna apenas o primeiro IP. */
    public static String parseFirstIP(byte[] data) {
        List<String> ips = parseAllIPs(data);
        return ips.isEmpty() ? null : ips.get(0);
    }

    /** Compatibilidade retroativa. */
    public static int skipQuestion(byte[] data, int index) {
        return skipName(data, index);
    }
}