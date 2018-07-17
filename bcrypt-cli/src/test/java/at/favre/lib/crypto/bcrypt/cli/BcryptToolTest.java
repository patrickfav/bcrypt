package at.favre.lib.crypto.bcrypt.cli;

import org.apache.tools.ant.types.Commandline;
import org.junit.Before;
import org.junit.Test;

import java.io.PrintStream;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class BcryptToolTest {
    private PrintStream out;
    private PrintStream err;

    @Before
    public void setup() {
        out = mock(PrintStream.class);
        err = mock(PrintStream.class);
    }

    @Test
    public void testExecuteHash() {
        BcryptTool.execute(CLIParser.parse(Commandline.translateCommandline("\"mySecretPw\" -b 8 8e270d6129fd45f30a9b3fe44b4a8d9a")), out, err);
        verify(out).println("$2a$08$hgaLWQl7PdKIkx9iQyoLkeuIqizWtPErpyC7aDBasi2Pav97wwW9G");
        verify(err, never()).println(any(String.class));
    }

    @Test
    public void testExecuteCheck() {
        BcryptTool.execute(CLIParser.parse(Commandline.translateCommandline("\"mySecretPw\" -check '$2a$08$hgaLWQl7PdKIkx9iQyoLkeuIqizWtPErpyC7aDBasi2Pav97wwW9G'")), out, err);
        verify(out).println(any(String.class));
        verify(err, never()).println(any(String.class));
    }
}
