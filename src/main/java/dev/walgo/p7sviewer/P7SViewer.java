package dev.walgo.p7sviewer;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.CollectionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class P7SViewer {

  private static final Logger LOG = LoggerFactory.getLogger(P7SViewer.class);

  private final CMSSignedData signature;

  public P7SViewer(InputStream stream) throws CMSException {
    signature = new CMSSignedData(stream);
  }

  public void viewCerts() throws Exception {
    CollectionStore<X509CertificateHolder> certs = (CollectionStore<X509CertificateHolder>) signature.getCertificates();
    LOG.info("Certificates:");
    for (X509CertificateHolder cert : certs) {
      LOG.info("  SN: [{}]", cert.getSerialNumber().toString());
      LOG.info("    Issuer: [{}]", cert.getIssuer().toString());
      LOG.info("    Not Before: [{}]", cert.getNotBefore().toString());
      LOG.info("    Not After: [{}]", cert.getNotAfter().toString());
      LOG.info("    SignatureAlgorithm: [{}]", cert.getSignatureAlgorithm().toASN1Primitive().toString());
      LOG.info("    Subject: [{}]", cert.getSubject().toString());
      LOG.info("    Version number: [{}]", cert.getVersionNumber());
      CertificateInfoParser parser = new CertificateInfoParser(cert);
      CertificateInfo info = parser.getCertificateInfo();
      LOG.info("    info: [{}]", info);

//      LOG.info("    Extensions:");
//      Extensions extensions = cert.getExtensions();
//      Extension directoryAttrsExtension = extensions.getExtension(Extension.subjectDirectoryAttributes);
//      if (directoryAttrsExtension != null) {
//        processPrimitive(directoryAttrsExtension.toASN1Primitive(), "      ");

//      for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
//        Extension extension = extensions.getExtension(oid);
//        ASN1Primitive primitive = extension.toASN1Primitive();
//        if (primitive instanceof DERSequence sequence) {
//          Iterator<ASN1Encodable> sequenceIterator = sequence.iterator();
//          iterateValues(sequenceIterator, "     ");
//        } else {
//          LOG.info("      [{}] => [{}]", oid, primitive.toString());
////        LOG.info("      [{}]", ASN1Dump.dumpAsString(primitive, true));
//        }
//      }
    }
  }

  @SuppressWarnings("unchecked")
  public void viewSigners() throws Exception {
    Collection<SignerInformation> signers = signature.getSignerInfos().getSigners();
    LOG.info("Signers:");
    for (SignerInformation signer : signers) {
      LOG.info("  DigestAlgOID: [{}]", signer.getDigestAlgOID());
      LOG.info("  ContentType Id: [{}]", signer.getContentType().getId());
      LOG.info("  DigestAlgorithmID: [{}]", signer.getDigestAlgorithmID().getAlgorithm().getId());
      LOG.info("  EncryptionAlgOID: [{}]", signer.getEncryptionAlgOID());
      LOG.info("  SID issuer: [{}]", signer.getSID().getIssuer().toString());
      LOG.info("  SID SN: [{}]", signer.getSID().getSerialNumber().toString());
      LOG.info("  Signed attributes:");
      Hashtable<Object, Object> attrs = signer.getSignedAttributes().toHashtable();
      showSignerAttributes(attrs);
      LOG.info("  Unsigned attributes:");
      attrs = signer.getUnsignedAttributes().toHashtable();
      showSignerAttributes(attrs);
    }
  }

  private void showSignerAttributes(Hashtable<Object, Object> attrs) throws Exception {
    for (Map.Entry<Object, Object> attr : attrs.entrySet()) {
      Attribute attrValue = (Attribute) attr.getValue();
      ASN1ObjectIdentifier id = ASN1ObjectIdentifier.fromContents(attrValue.getEncoded());
      LOG.info("    [{}] ({})", attr.getKey().toString(), id.toString());
      ASN1Set values = attrValue.getAttrValues();
      Iterator<ASN1Encodable> iterator = values.iterator();
      iterateValues(iterator, "      ");
    }
  }

  private void processPrimitive(ASN1Primitive asn1, String indent) throws Exception {
    if (asn1 instanceof DLSequence sequence) {
      Iterator<ASN1Encodable> sequenceIterator = sequence.iterator();
      iterateValues(sequenceIterator, indent + "  ");
    } else if (asn1 instanceof DLTaggedObject object) {
      if (object.getBaseObject()instanceof DLSequence sequence) {
        Iterator<ASN1Encodable> sequenceIterator = sequence.iterator();
        iterateValues(sequenceIterator, indent + "  ");
      } else {
        byte[] encoded = object.getLoadedObject().getEncoded();
        String logValue = toLogValue(encoded, object.getLoadedObject());
        LOG.info("      [{}] => [{}]", object.getBaseObject().toString(), logValue);
      }
    } else if (asn1 instanceof ASN1GeneralizedTime time) {
      LOG.info(indent + " [{}]", time.getDate().toString());
    } else if (asn1 instanceof ASN1Set set) {
      Iterator<ASN1Encodable> setIterator = set.iterator();
      iterateValues(setIterator, "  " + indent);
    } else if (asn1 instanceof ASN1ObjectIdentifier identifier) {
      LOG.info(indent + "[{}]", identifier.getId());
    } else if (asn1 instanceof DEROctetString derOctetString) {
      ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(derOctetString.getOctets()));
      ASN1Primitive primitive;
      while ((primitive = stream.readObject()) != null) {
        processPrimitive(primitive, "  " + indent);
      }
    } else if (asn1 instanceof DERSequence sequence) {
      Iterator<ASN1Encodable> sequenceIterator = sequence.iterator();
      iterateValues(sequenceIterator, "  " + indent);
    } else {
      byte[] encoded = asn1.toASN1Primitive().getEncoded();
      String logValue = toLogValue(encoded, asn1.toASN1Primitive());
      LOG.info(indent + "[{}]", logValue);
    }
  }

  private void iterateValues(Iterator<ASN1Encodable> iterator, String indent) throws Exception {
    while (iterator.hasNext()) {
      ASN1Encodable asn1 = iterator.next();
      processPrimitive(asn1.toASN1Primitive(), indent);
    }
  }

  private String toLogValue(byte[] encoded, ASN1Primitive asn) {
    String encodedStr = new String(encoded);
    String logValue = StringUtils.isAlphanumericSpace(encodedStr) ? encodedStr : asn.toString();
    return logValue;
  }

}
