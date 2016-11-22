using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Util.Soap
{
    public class SoapMessage
    {       
        public XmlElement Header { get; set; }

        public XmlElement Body { get; set; }

        public X509Certificate2 Certificate { get; set; }

        public XmlDocument GetXml(bool signed = false)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;

            XmlElement soapEnvelopeXml = doc.CreateElement("s", "Envelope", "http://schemas.xmlsoap.org/soap/envelope/");
            soapEnvelopeXml.SetAttribute("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

            XmlElement soapHeaderXml = doc.CreateElement("s", "Header", "http://schemas.xmlsoap.org/soap/envelope/");
            if (Header != null)
            {
                var imported = doc.ImportNode(Header, true);
                soapHeaderXml.AppendChild(imported);
            }
            soapEnvelopeXml.AppendChild(soapHeaderXml);

            XmlElement soapBodyXml = doc.CreateElement("s", "Body", "http://schemas.xmlsoap.org/soap/envelope/");
            soapBodyXml.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_1");

            if (Body == null)
            {
                throw new Exception("Se necesita el cuerpo del mensaje");
            }
            else
            {
                XmlNode imported = doc.ImportNode(Body, true);
                soapBodyXml.AppendChild(imported);                
            }

            soapEnvelopeXml.AppendChild(soapBodyXml);
            doc.AppendChild(soapEnvelopeXml);

            if (signed)
            {
                SoapSigner signer = new SoapSigner();

                XmlDocument tempDoc = new XmlDocument();
                tempDoc.PreserveWhitespace = true;
                tempDoc.LoadXml(doc.OuterXml);

                return signer.SignMessage(tempDoc, Certificate);
            }

            return doc;
        }

        public void ReadXml(XmlDocument document)
        {
            XmlNamespaceManager ns = new XmlNamespaceManager(document.NameTable);
            ns.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");

            this.Header = document.DocumentElement.SelectSingleNode(@"//s:Header", ns) as XmlElement;
            this.Body = document.DocumentElement.SelectSingleNode(@"//s:Body", ns) as XmlElement;

            if (this.Body == null)
            {
                throw new Exception("No se ha encontrado el cuerpo del mensaje");
            }
        }
    }
}
