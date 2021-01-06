using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertStart
{
    class Program
    {
        static void Main(string[] args)
        {
            var rsaKey = RSA.Create(2048);
            string subject = "CN=myauthority.ru";
            var certReq = new CertificateRequest(subject, rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));
            var expirate = DateTimeOffset.Now.AddYears(5);
            var caCert = certReq.CreateSelfSigned(DateTimeOffset.Now, expirate);
            var clientKey = RSA.Create(2048);
            subject = "CN=10.10.10.*";
            var clientReq = new CertificateRequest(subject, clientKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            clientReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            clientReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
            clientReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(clientReq.PublicKey, false));
            byte[] serialNumber = BitConverter.GetBytes(DateTime.Now.ToBinary());
            var clientCert = clientReq.Create(caCert, DateTimeOffset.Now, expirate, serialNumber);
            var exportCert = new X509Certificate2(clientCert.Export(X509ContentType.Cert),
                    (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet).CopyWithPrivateKey(clientKey);
            File.WriteAllBytes("client.pfx", exportCert.Export(X509ContentType.Pfx));
            File.WriteAllBytes("client.p12", exportCert.Export(X509ContentType.Pkcs12));
            var fromFileCert = new X509Certificate2(File.ReadAllBytes("client.pfx"));
            Debug.Assert(fromFileCert.HasPrivateKey);
        }
    }
}
