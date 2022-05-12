# PGP (Pretty Good Privacy) ile Dosya/Veri Şifreleme ve Çözme

İnternet Güvenlik Protokolleri proje ödevi kapsamında, PGP (Pretty Good Privacy) protokolü ile şifreleme ve şifre çözmeye yönelik bir C# Windows Form uygulaması geliştirildi.

## Projeye Genel Bakış

**ÖNEMLİ:** Proje Visual Studio 2019'da yazılmıştır. Windows Form Application projesidir.

Proje ayağa kaldırıldığında ilk açılacak ana sayfa aşağıdaki gibidir:

![Project Demo 1](https://i.hizliresim.com/jvpzy1a.jpg)

Sol kısımda "RC5 Hakkında" ve "Sifrele ve Coz" isimli iki adet menü bulunmaktadır. Bu menü seçimleri ile farklı ekranlar karşımıza çıkmaktadır.

"RC5 Hakkında" menüsünün içeriğinde RC5 şifreleme algoritmasıyla ilgili kısa bir bilgilendirme metni bulunmaktadır. Algoritmanın ayrıntıları proje raporunda anlatılmıştır.

![Project Demo 2](https://i.hizliresim.com/3s2t29p.jpg)

"Sifrele ve Coz" menüsünün içeriğinde ise bir metnin şifrelemesini ve şifre çözümlemesinin yapıldığı bir ekran karşımıza çıkmaktadır. "Şifre" butonuna tıklandığında, plain text RC5 algoritmasının prosedürlerine uygun olarak şifrelenmektedir ve Cipher Text isimli Rich Text Box'ta gösterilmektedir. "Çöz" butonuna tıklandığında ise Cipher Text isimli Rich Text Box'taki şifrelenmiş metnin çözümünü yapmaktadır. Ve çözümünü de Decrypted isimli Rich Text Box'ta göstermektedir.

![Project Demo 3](https://i.hizliresim.com/iqpezpm.jpg)

![Project Demo 4](https://i.hizliresim.com/qe51w1j.jpg)

Şifrelemek istediğimiz metni (plain text) kendimiz yazabildiğimiz gibi "Txt Dosyası Seç" butonu ile de .txt uzantılı bir dosya seçerek de aynı işlemleri gerçekleştirebiliriz.

![Project Demo 5](https://i.hizliresim.com/o9wogrq.jpg)

![Project Demo 6](https://i.hizliresim.com/n6amrc4.jpg)

![Project Demo 7](https://i.hizliresim.com/8nt8zsy.jpg)

![Project Demo 8](https://i.hizliresim.com/j0wce31.jpg)

![Project Demo 9](https://i.hizliresim.com/jj4tuk5.jpg)

![Project Demo 10](https://i.hizliresim.com/1j6nfde.jpg)

![Project Demo 11](https://i.hizliresim.com/j2qcye0.jpg)

## Algorithm.cs

PGP protokolü prosedürlerini içeren dosya.



```csharp
using PgpCore;
using System;
using Utils.Filesystem;

namespace Algorithms
{
    public interface IPgp
    {
        string GenerateKeyPair(string email, string sifre);
        void LoadInput(string dosyaAdi);
        void LoadKeys(string dosyaAdi);
        void UpdatePublicKey(string publicKeyYol);
        void UpdatePrivateKey(string privateKeyYol);
        void UpdatePlaintext(string plaintextYol);
        void UpdateCiphertext(string ciphertextYol);
        string Encrypt(string sifre);
        string Decrypt(string sifre);
        void Unload();
    }

    public class Pgp : IPgp
    {
        private readonly PGP _pgp = new PGP();
        private readonly IKey _key = new Key();
        private readonly IFileManager _file = new FileManager();
        private string _fileName;
        private string _plaintextFilePath;
        private readonly string _plaintextFilePathBase = "C:\\TEMP\\App.Pgp\\girdiler";
        private string _signedFilePath;
        private readonly string _signedFilePathBase = "C:\\TEMP\\App.Pgp\\sonuclar";

        public Pgp()
        {
            _file.InitializePgp();
        }

        public string GenerateKeyPair(string email, string sifre)
        {
            _key.Email = email;
            _key.Password = sifre;

            try
            {
                _pgp.GenerateKey(
                    @_key.PublicKeyPath,
                    @_key.PrivateKeyPath,
                    _key.Email,
                    _key.Password);
                return string.Empty;
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }

        public void LoadInput(string dosyaAdi)
        {
            _fileName = dosyaAdi;

            _plaintextFilePath = _plaintextFilePathBase + "\\" + _fileName + ".txt";
            _file.Register(_plaintextFilePath);
        }

        public void LoadKeys(string dosyaAdi)
        {
            _fileName = dosyaAdi;

            _key.PublicKeyPath = "C:\\TEMP\\App.Pgp\\anahtarlar\\" + dosyaAdi + "_PUBKEY.asc";
            _key.PrivateKeyPath = "C:\\TEMP\\App.Pgp\\anahtarlar\\" + dosyaAdi + "_PRVKEY.asc";

            _file.Register(_key.PublicKeyPath);
            _file.Register(_key.PrivateKeyPath);
        }

        public void UpdatePublicKey(string publicKeyYol)
        {
            _key.PublicKeyPath = publicKeyYol;
        }

        public void UpdatePrivateKey(string privateKeyYol)
        {
            _key.PrivateKeyPath = privateKeyYol;
        }

        public void UpdatePlaintext(string plaintextYol)
        {
            _plaintextFilePath = plaintextYol;
        }

        public void UpdateCiphertext(string ciphertextYol)
        {
            _signedFilePath = ciphertextYol;
        }

        public string Encrypt(string sifre)
        {
            try
            {
                _signedFilePath = _signedFilePathBase + "\\" + 
                    _fileName + "_SIGNED.pgp";
                _file.Register(_signedFilePath);

                _pgp.EncryptFileAndSign(
                   @_plaintextFilePath,
                   @_signedFilePath,
                   @_key.PublicKeyPath,
                   @_key.PrivateKeyPath,
                   sifre,
                   true,
                   true);
                return string.Empty;
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }

        public string Decrypt(string sifre)
        {
            string unsignedFilePath = _signedFilePathBase + "\\" + _fileName + "_UNSIGNED.txt";
            _file.Register(unsignedFilePath);

            try
            {
                _pgp.DecryptFileAndVerify(
                @_signedFilePath,
                @unsignedFilePath,
                @_key.PublicKeyPath,
                @_key.PrivateKeyPath,
                sifre);
                return string.Empty;
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }

        public void Unload()
        {
            _file.PgpEraseFootprint();
        }
    }
}


```
## License
[MIT](https://choosealicense.com/licenses/mit/)
