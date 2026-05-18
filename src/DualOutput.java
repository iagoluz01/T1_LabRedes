import java.io.*;

public class DualOutput extends OutputStream {
    private PrintStream console;
    private PrintWriter file;

    public DualOutput(PrintStream console, String filename) throws IOException {
        this.console = console;
        this.file = new PrintWriter(new FileWriter(filename, true), true);
    }

    @Override
    public void write(int b) throws IOException {
        console.write(b);
        file.write(b);
        file.flush();
    }

    @Override
    public void write(byte[] b) throws IOException {
        console.write(b);
        file.write(new String(b));
        file.flush();
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        console.write(b, off, len);
        file.write(new String(b, off, len));
        file.flush();
    }

    @Override
    public void flush() throws IOException {
        console.flush();
        file.flush();
    }

    @Override
    public void close() throws IOException {
        if (file != null) {
            file.close();
            file = null;
        }
    }
}
