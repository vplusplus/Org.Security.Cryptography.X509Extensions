using EasyConsole;

namespace X509.EnduranceTest.Shared
{
    public class TestProgram : Program
    {
        public TestProgram():base("Org.Security.Cryptography.X509Extensions Endurance Tests", true)
        {
            AddPage(new MainMenuPage(this));
            AddPage(new EncryptionDecryptionMenuPage(this));
            AddPage(new SignAndVerifyMenuPage(this));
            SetPage<MainMenuPage>();
        }
    }
}