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
            this.Menu.AddSync("Validate Sign/Verify ONCE using MD5. (Fail in .Net Framework)", () => ValidateSignAndVerifyOnce("MD5"));

            this.Menu.AddSync("Validate Sign/Verify ONCE using SHA1.", () => ValidateSignAndVerifyOnce("SHA1"));
            this.Menu.AddSync("Validate Sign/Verify ONCE using SHA256.", () => ValidateSignAndVerifyOnce("SHA256"));
            
            this.Menu.AddSync("X509Certificate2.CreateSignature - SHA256, Random 256 bytes, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunSign("SHA256", .25, 100000));
            this.Menu.AddSync("X509Certificate2.CreateSignature - SHA256, Random 1 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunSign("SHA256", 1, 100000));
            this.Menu.AddSync("X509Certificate2.CreateSignature - SHA256, Random 8 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunSign("SHA256", 8, 100000));
            this.Menu.AddSync("X509Certificate2.CreateSignature - SHA512, Random 8 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunSign("SHA512", 8, 100000));

            this.Menu.AddSync("X509Certificate2.VerifySignature - SHA256, Random 256 bytes, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunVerify("SHA256", .25, 100000));
            this.Menu.AddSync("X509Certificate2.VerifySignature - SHA256, Random 1 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunVerify("SHA256", 1, 100000));
            this.Menu.AddSync("X509Certificate2.VerifySignature - SHA256, Random 8 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunVerify("SHA256", 8, 100000));
            this.Menu.AddSync("X509Certificate2.VerifySignature - SHA512, Random 8 KB, 100,000 times", () => X509Certificate2_SignAndVerifyEnduranceTests.RunVerify("SHA512", 8, 100000));
        }
        private void ValidateSignAndVerifyOnce(string hashName)
        {
            const string TestData = "Hello world";
            var payload = Encoding.UTF8.GetBytes(TestData);
            using var hashAlgorithm = HashAlgorithm.Create(hashName);
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