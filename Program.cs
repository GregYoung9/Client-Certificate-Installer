using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

Console.Write("Enter certificate path and name or [Enter] key to accept the default path [C:\\Certs\\UniversalPublishers.pfx]: ");
string? inputPath = Console.ReadLine();
string certPath = string.IsNullOrWhiteSpace(inputPath) ? @"C:\Certs\UniversalPublishers.pfx" : inputPath;

if (!File.Exists(certPath))
{
    Console.WriteLine($"Certificate file not found: {certPath}");
    return;
}

X509Certificate2? cert = null;
while (cert == null)
{
    Console.Write("Enter certificate password (or type 'exit' to quit): ");
    string? certPassword = Console.ReadLine();

    if (certPassword == null || certPassword.Equals("exit", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine("Exiting.");
        return;
    }

    try
    {
        cert = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.PersistKeySet);
    }
    catch (System.Security.Cryptography.CryptographicException ex)
    {
        if (ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase) ||
            ex.Message.Contains("network password", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Incorrect password. Please try again.");
        }
        else
        {
            Console.WriteLine("Error loading certificate: " + ex.Message);
            return;
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine("Error loading certificate: " + ex.Message);
        return;
    }
}

using (var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
{
    try
    {
        store.Open(OpenFlags.ReadWrite);

        bool alreadyInstalled = false;
        foreach (var existingCert in store.Certificates)
        {
            if (string.Equals(existingCert.Thumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                alreadyInstalled = true;
                break;
            }
        }

        if (alreadyInstalled)
        {
            Console.WriteLine("Certificate is already installed in Trusted Root Certification Authorities (Local Machine).");
        }
        else
        {
            store.Add(cert);
            Console.WriteLine("Certificate installed successfully to Trusted Root Certification Authorities (Local Machine).");
        }
    }
    catch (System.Security.Cryptography.CryptographicException ex) when (ex.Message.Contains("Access is denied", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine("Error: Access is denied. Please run this application as an administrator to install certificates to the Local Machine store.");
        Console.WriteLine("Press Enter to exit...");
        Console.ReadLine();
    }
    catch (Exception ex)
    {
        Console.WriteLine("An error occurred while accessing the certificate store: " + ex.Message);
    }
}
