using EasyConsole;
namespace X509.EnduranceTest.Shared
{
    internal class MainMenuPage : MenuPage
    {
        public MainMenuPage(TestProgram program) : base("Main Page", program,
                  new Option("Encryption/Decryption", (token) => program.NavigateTo<EncryptionDecryptionMenuPage>(token)),
                  new Option("Sign&Verify", (token) => program.NavigateTo<SignAndVerifyMenuPage>(token)))
        {
        }
    }
}