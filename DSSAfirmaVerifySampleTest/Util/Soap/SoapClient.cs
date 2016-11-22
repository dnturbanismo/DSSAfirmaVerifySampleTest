using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Xml;

namespace Util.Soap
{
    public class SoapClient
    {
        public static SoapMessage SendMessage(Uri destination, SoapMessage message, bool signed = false)
        {
            try
            {
                XmlDocument reqDocument = message.GetXml(signed);
                
                HttpWebRequest httpRequest = (HttpWebRequest)WebRequest.Create(destination);
                httpRequest.Method = "POST";
                httpRequest.ContentType = "text/xml; charset=utf-8";
                httpRequest.Headers.Add(string.Format("SOAPAction: \"{0}\"", ""));

                byte[] bytes = Encoding.UTF8.GetBytes(reqDocument.OuterXml);

                httpRequest.ContentLength = bytes.Length;
                httpRequest.ProtocolVersion = HttpVersion.Version11;

                using (Stream requestStream = httpRequest.GetRequestStream())
                {
                    requestStream.Write(bytes, 0, bytes.Length);
                }

                using (HttpWebResponse response = (HttpWebResponse)httpRequest.GetResponse())
                {
                    Stream responseStream = response.GetResponseStream();
                    StreamReader responseStreamReader = new StreamReader(responseStream);
                    var value = responseStreamReader.ReadToEnd();

                    XmlDocument responseDoc = new XmlDocument();
                    responseDoc.PreserveWhitespace = true;
                    responseDoc.LoadXml(value);

                    SoapMessage respMessage = new SoapMessage();
                    respMessage.ReadXml(responseDoc);

                    return respMessage;
                }
            }
            catch (Exception ex)
            {
                // TODO: loggear excepción
                throw ex;
            }
        }
    }
}