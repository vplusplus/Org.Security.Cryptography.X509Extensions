using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Org.Security.Cryptography
{
    public class X509CertificateBasedDecryptor
    {

        #region public
        public void DecryptStream(
            Stream inputStream,
            Stream outputStream,
            Func<string, X509Certificate2> certificateSelector,
            string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName)
        {
            var certificateForKeyEncryption = GetCertificateFromStreamAfterValidations(inputStream, outputStream, dataEncryptionAlgorithmName, certificateSelector);
            certificateForKeyEncryption.DecryptStreamWithTimestampValidation(inputStream, outputStream, false, dataEncryptionAlgorithmName);
        }

        public string DecryptBase64EncodedString(
            string valueToDecode,
            Func<string, X509Certificate2> certificateSelector)
        {
            var inputData = Convert.FromBase64String(valueToDecode);
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                this.DecryptStream(input, output, certificateSelector);
                output.Flush();
                var outputArray = output.ToArray();
                return Encoding.UTF8.GetString(outputArray);
            }
        }
        public void DecryptStreamWithTimestampValidation(
           Stream inputStream,
           Stream outputStream,
           Func<string, X509Certificate2> certificateSelector,
           string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName
           )
        {
            this.DecryptStreamWithTimestampValidation(
                inputStream,
                outputStream,
                certificateSelector,
                TimeSpan.FromMinutes(1),
                dataEncryptionAlgorithmName);
        }
        public void DecryptStreamWithTimestampValidation(
           Stream inputStream,
           Stream outputStream,
           Func<string, X509Certificate2> certificateSelector,
           TimeSpan lifeSpanOfInput,
           string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName
           )
        {
            X509Certificate2 certificateForKeyEncryption = GetCertificateFromStreamAfterValidations(inputStream, outputStream, dataEncryptionAlgorithmName, certificateSelector);

            certificateForKeyEncryption.DecryptStreamWithTimestampValidation(inputStream, outputStream, lifeSpanOfInput, dataEncryptionAlgorithmName);
        }

        public string DecryptBase64EncodedStringWithTimestampValidation(
            string valueToDecode,
            Func<string, X509Certificate2> certificateSelector)
        {
            return this.DecryptBase64EncodedStringWithTimestampValidation(valueToDecode, certificateSelector, Defaults.EncyptedPayloadTimeSpan);
        }
        public string DecryptBase64EncodedStringWithTimestampValidation(
            string valueToDecode,
            Func<string, X509Certificate2> certificateSelector,
            TimeSpan lifeSpanOfInput,
           string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName)
        {
            var inputData = Convert.FromBase64String(valueToDecode);
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                this.DecryptStreamWithTimestampValidation(input, output, certificateSelector, lifeSpanOfInput, dataEncryptionAlgorithmName);
                output.Flush();
                var outputArray = output.ToArray();
                return Encoding.UTF8.GetString(outputArray);
            }
        }
        #endregion

        #region Private helpers
        private static X509Certificate2 GetCertificateFromStreamAfterValidations(Stream inputStream, Stream outputStream, string dataEncryptionAlgorithmName, Func<string, X509Certificate2> certificateSelector)
        {
            if (null == certificateSelector) throw new ArgumentNullException(nameof(certificateSelector));
            var thumprintArray = inputStream.ReadLengthAndBytes(maxBytes: 2048);
            var certificateThumbprint = Encoding.UTF8.GetString(thumprintArray);
            var certificateForKeyEncryption = certificateSelector(certificateThumbprint);
            Validator.ValidateParametersAndThrowException(certificateForKeyEncryption, inputStream, outputStream, dataEncryptionAlgorithmName);
            return certificateForKeyEncryption;
        }
        #endregion
    }

}