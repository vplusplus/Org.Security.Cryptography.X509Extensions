using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EasyConsole;
using Org.Security.Cryptography;
using UnitTests;

namespace X509.EnduranceTest.Shared
{
    internal class SignAndVerifyMenuPage : MenuPage
    {
        public SignAndVerifyMenuPage(TestProgram program) : base("SignAndVerify", program)
        {
            this.Menu.AddSync("Validate Sign/Verify ONCE.", () => ValidateSignAndVerifyOnce());
            
            this.Menu.AddSync("X509Certificate2.CreateSignature - Random 256 bytes, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.Run( .25, 100000));
            this.Menu.AddSync("X509Certificate2.CreateSignature - Random 1 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.Run(1, 100000));
            this.Menu.AddSync("X509Certificate2.CreateSignature - Random 8 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.Run(8, 100000));

            this.Menu.AddSync("X509Certificate2.VerifySignature - Random 256 bytes, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunVerify(.25, 100000));
            this.Menu.AddSync("X509Certificate2.VerifySignature - Random 1 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunVerify(1, 100000));
            this.Menu.AddSync("X509Certificate2.VerifySignature - Random 8 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunVerify(8, 100000));
        }

        private void ValidateSignAndVerifyOnce()
        {
            const string TestData = "Hello world";
            var payload = Encoding.UTF8.GetBytes(TestData);
            using var hashAlgorithm = HashAlgorithm.Create("SHA256");
            var hash = hashAlgorithm.ComputeHash(payload);
            var signature = MyConfig.SigningCertificate.CreateSignature(hash);
            X509Certificate2 verifyCertificate = MyConfig.VerifyCertificate;
            // Act
            var good = verifyCertificate.VerifySignature(hash, signature);
            ConsoleWriter.WriteSuccess("Successfully signed and verified");
        }

        public async override Task Display(CancellationToken cancellationToken)
        {
            await base.Display(cancellationToken);
            Input.ReadString("Press any key to continue");
            await this.Program.NavigateTo<SignAndVerifyMenuPage>(cancellationToken);
        }
    }
}