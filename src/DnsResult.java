import java.util.ArrayList;
import java.util.List;

/**
 * Encapsula o resultado de uma consulta DNS.
 */
public class DnsResult {

    public final String serverIp;
    public final String serverLabel;
    public final String domain;
    public final boolean isDoT;

    public int rcode = -1;
    public List<String> ips = new ArrayList<>();
    public long responseTimeMs = -1;
    public boolean timeout = false;
    public String errorMsg = null;
    public String blockReason = null;

    public DnsResult(String serverIp, String serverLabel, String domain, boolean isDoT) {
        this.serverIp = serverIp;
        this.serverLabel = serverLabel;
        this.domain = domain;
        this.isDoT = isDoT;
    }

    public String getRcodeName() {
        switch (rcode) {
            case 0:  return "NOERROR";
            case 1:  return "FORMERR";
            case 2:  return "SERVFAIL";
            case 3:  return "NXDOMAIN";
            case 4:  return "NOTIMP";
            case 5:  return "REFUSED";
            default: return (rcode >= 0 ? "RCODE(" + rcode + ")" : "N/A");
        }
    }

    public String getFirstIp() {
        return ips.isEmpty() ? "-" : ips.get(0);
    }
}

