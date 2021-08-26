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
            ValidateDecryptParamsAndThrowException(inputStream, outputStream, dataEncryptionAlgorithmName, certificateSelector);
            var certificateForKeyEncryption = GetCertificateFromStream(inputStream, certificateSelector);
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
            ValidateDecryptParamsAndThrowException(inputStream, outputStream, dataEncryptionAlgorithmName, certificateSelector);

            X509Certificate2 certificateForKeyEncryption = GetCertificateFromStream(inputStream, certificateSelector);

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
                this.DecryptStreamWithTimestampValidation(input, output, certificateSelector,lifeSpanOfInput,dataEncryptionAlgorithmName);
                output.Flush();
                var outputArray = output.ToArray();
                return Encoding.UTF8.GetString(outputArray);
            }
        }
        #endregion

        #region Private helpers
        private static X509Certificate2 GetCertificateFromStream(Stream inputStream, Func<string, X509Certificate2> certificateSelector)
        {
            var thumprintArray = inputStream.ReadLengthAndBytes(maxBytes: 2048);
            var certificateThumbprint = Encoding.UTF8.GetString(thumprintArray);
            var certificateForKeyEncryption = certificateSelector(certificateThumbprint);
            if (null == certificateForKeyEncryption) throw new ArgumentNullException("The certificate cannot be null");
            return certificateForKeyEncryption;
        }
        private static void ValidateDecryptParamsAndThrowException(Stream inputStream, Stream outputStream, string dataEncryptionAlgorithmName, Func<string, X509Certificate2> certificateSelector)
        {
            if (null == certificateSelector) throw new ArgumentNullException(nameof(certificateSelector));
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == dataEncryptionAlgorithmName) throw new ArgumentNullException(nameof(dataEncryptionAlgorithmName));
        }
        #endregion
    }
}