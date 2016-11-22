// --------------------------------------------------------------------------------------------------------------------
// DSSAfirmaVerify.cs
//
// Demostración de uso de los servicios de firma digital de @firma
// Copyright (C) 2016 Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/. 
//
// E-Mail: informatica@gemuc.es
// 
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using DSSAfirmaVerifySampleTest.Schemas;
using Util.Soap;
using System.Configuration;

namespace DSSAfirmaVerifySampleTest.AFirmaServices
{
    public enum SignatureFormat
    {
        XAdES,
        PAdES
    }

    public class DSSAfirmaVerify
    {
        private string _identificador;
        private X509Certificate2 _certificado;
        private Uri _uriAfirma;

        public DSSAfirmaVerify(string identificadorAplicacion,
            X509Certificate2 certificadoFirma)
        {
            _identificador = identificadorAplicacion;
            _certificado = certificadoFirma;
            _uriAfirma = new Uri(ConfigurationManager.AppSettings["DSSAfirmaVerifyURL"]);
        }

        private XmlElement GetXmlElement<T>(T source)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                XmlSerializer serializer = new XmlSerializer(typeof(T));
                serializer.Serialize(ms, source);                
                
                ms.Seek(0, SeekOrigin.Begin);

                XmlDocument doc = new XmlDocument();
                doc.Load(ms);

                return doc.DocumentElement;
            }
        }

        private T DeserializeXml<T>(string xml)
        {
            using (MemoryStream ms = new MemoryStream(UTF8Encoding.UTF8.GetBytes(xml)))
            {
                XmlSerializer serializer = new XmlSerializer(typeof(T));
                T result = (T)serializer.Deserialize(ms);

                return result;
            }
        }

        /// <summary>
        /// Construye la petición de verificación
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="updatedSignatureType"></param>
        /// <returns></returns>
        private VerifyRequest BuildRequest(object signature, string updatedSignatureType = null)
        {
            VerifyRequest vr = new VerifyRequest();

            ClaimedIdentity identity = new ClaimedIdentity();
            identity.Name = new NameIdentifierType() { Value = _identificador };

            IgnoreGracePeriod igp = new IgnoreGracePeriod();

            vr.OptionalInputs = new AnyType();

            if (!string.IsNullOrEmpty(updatedSignatureType))
            {
                ReturnUpdatedSignature returnUpdated = new ReturnUpdatedSignature();
                returnUpdated.Type = updatedSignatureType;

                vr.OptionalInputs.Any = new XmlElement[] { GetXmlElement<ClaimedIdentity>(identity),
                GetXmlElement<ReturnUpdatedSignature>(returnUpdated),
                GetXmlElement<IgnoreGracePeriod>(igp)};
            }
            else
            {
                vr.OptionalInputs.Any = new XmlElement[] { GetXmlElement<ClaimedIdentity>(identity),
                GetXmlElement<IgnoreGracePeriod>(igp)};
            }

            DocumentType doc = new DocumentType();
            doc.ID = "ID_DOCUMENTO";
            doc.Item = signature;
            vr.InputDocuments = new InputDocuments();
            vr.InputDocuments.Items = new object[] { doc };
            vr.SignatureObject = new SignatureObject();
            vr.SignatureObject.Item = new SignaturePtr() { WhichDocument = "ID_DOCUMENTO" };

            return vr;
        }

        /// <summary>
        /// Envia la petición al servidor
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="updatedSignatureType"></param>
        /// <returns></returns>
        private VerifyResponse SendRequest(object signature, string updatedSignatureType = null)
        {
            try
            {
                VerifyRequest request = BuildRequest(signature, updatedSignatureType);
                
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.LoadXml("<verify xmlns=\"urn:oasis:names:tc:dss:1.0:core:schema\"><dssXML xmlns=\"\"></dssXML></verify>");

                XmlNode dssXml = xmlDoc.SelectSingleNode("//dssXML");
                dssXml.InnerText = GetXmlElement<VerifyRequest>(request).OuterXml;

                SoapMessage soapMessage = new SoapMessage();
                soapMessage.Body = xmlDoc.DocumentElement;
                soapMessage.Certificate = _certificado;

                var resp = SoapClient.SendMessage(_uriAfirma, soapMessage, true);

                VerifyResponse respuesta = DeserializeXml<VerifyResponse>(resp.Body.InnerText);

                return respuesta;
            }
            catch (Exception ex)
            {
                throw new Exception("Ha ocurrido un error enviando la petición", ex);
            }
        }

        private object GetSignatureObject(byte[] signature, SignatureFormat signatureFormat)
        {
            if (signatureFormat == SignatureFormat.PAdES)
            {
                Base64Data b64Data = new Base64Data();
                b64Data.MimeType = "application/pdf";
                b64Data.Value = signature;

                return b64Data;
            }
            else
            {
                return signature;
            }
        }

        /// <summary>
        /// Método para realizar la ampliación de firmas
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="signatureFormat"></param>
        /// <param name="returnUpdatedSignatureType"></param>
        /// <returns></returns>
        public byte[] UpgradeSignature(byte[] signature, SignatureFormat signatureFormat, string returnUpdatedSignatureType)
        {
            object signatureObject = GetSignatureObject(signature, signatureFormat);

            VerifyResponse response = SendRequest(signatureObject, returnUpdatedSignatureType);

            if (response.Result.ResultMajor == "urn:oasis:names:tc:dss:1.0:resultmajor:Success")
            {
                XmlElement updatedSignatureXmlElement = response.OptionalOutputs.Any.Single(e => e.LocalName == "UpdatedSignature");
                UpdatedSignatureType updatedSignatureType = DeserializeXml<UpdatedSignatureType>(updatedSignatureXmlElement.OuterXml);

                if (updatedSignatureType.SignatureObject.Item.GetType() == typeof(SignaturePtr))
                {
                    SignaturePtr signaturePtr = updatedSignatureType.SignatureObject.Item as SignaturePtr;

                    DocumentWithSignature docWithSignature = null;
                    IEnumerable<XmlElement> documentWithSignatureXmlElements = response.OptionalOutputs.Any.Where(e => e.LocalName == "DocumentWithSignature");
                    foreach (var item in documentWithSignatureXmlElements)
                    {
                        docWithSignature = DeserializeXml<DocumentWithSignature>(item.OuterXml);

                        if (docWithSignature.Document.ID == signaturePtr.WhichDocument)
                        {
                            break;
                        }
                    }

                    if (docWithSignature == null)
                    {
                        throw new Exception("No se ha encontrado el documento de firma");
                    }
                    else
                    {
                        return docWithSignature.Document.Item as byte[];
                    }
                }
                else if (updatedSignatureType.SignatureObject.Item.GetType() == typeof(Base64Signature))
                {
                    Base64Signature b64Signature = updatedSignatureType.SignatureObject.Item as Base64Signature;

                    return b64Signature.Value;
                }
                else
                {
                    throw new Exception("Tipo de resultado no soportado");
                }
            }
            else
            {
                throw new Exception(response.Result.ResultMessage.Value);
            }
        }

        /// <summary>
        /// Método para la verificación de firmas
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="signatureFormat"></param>
        public void VerifySignature(byte[] signature, SignatureFormat signatureFormat)
        {
            object signatureObject = GetSignatureObject(signature, signatureFormat);

            VerifyResponse response = SendRequest(signatureObject);

            if (response.Result.ResultMajor != "urn:afirma:dss:1.0:profile:XSS:resultmajor:ValidSignature")
            {
                throw new Exception(response.Result.ResultMessage.Value);
            }
        }
    }
}
