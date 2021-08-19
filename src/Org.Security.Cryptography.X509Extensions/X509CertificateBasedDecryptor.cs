using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Org.Security.Cryptography
{
    public class X509CertificateBasedDecryptor
    {
        #region Defaults
        const string DEF_DataEncryptionAlgorithmName = "Aes";
        const int DEF_KeySize = 256;
        const int DEF_BlockSize = 128;
        #endregion

        #region public
        public void DecryptStream(
            Stream inputStream,
            Stream outputStream,
            Func<string, X509Certificate2> certificateSelector,
            string dataEncryptionAlgorithmName = DEF_DataEncryptionAlgorithmName)
        {
            ValidateDecryptParamsAndThrowException( inputStream, outputStream, dataEncryptionAlgorithmName);

            var thumprintArray = inputStream.ReadLengthAndBytes(maxBytes: 2048);
            var certificateThumbprint = Encoding.UTF8.GetString(thumprintArray);
            var certificateForKeyEncryption = certificateSelector(certificateThumbprint);
            if (null == certificateForKeyEncryption) throw new ArgumentNullException("The certificate cannot be null");
            certificateForKeyEncryption.DecryptStream(inputStream, outputStream, dataEncryptionAlgorithmName);
        }
        public string DecryptBase64EncodedString(
            string valueToDecode,
            Func<string, X509Certificate2> certificateSelector)
        {
            var inputData = Convert.FromBase64String(valueToDecode);
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                this.DecryptStream( input, output,certificateSelector);
                output.Flush();
                var outputArray = output.ToArray();
                return Encoding.UTF8.GetString(outputArray);
            }
        }
        #endregion
        private static void ValidateDecryptParamsAndThrowException(Stream inputStream, Stream outputStream, string dataEncryptionAlgorithmName)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == dataEncryptionAlgorithmName) throw new ArgumentNullException(nameof(dataEncryptionAlgorithmName));
        }
    }
}