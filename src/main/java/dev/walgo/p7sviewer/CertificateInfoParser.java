package dev.walgo.p7sviewer;

import java.util.Vector;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.cert.X509CertificateHolder;

public class CertificateInfoParser {

  private X509CertificateHolder cert;

  public CertificateInfoParser(X509CertificateHolder holder) {
    this.cert = holder;
  }

  @SuppressWarnings("unchecked")
  public CertificateInfo getCertificateInfo() {
    CertificateInfo info = new CertificateInfo();
    Extensions extensions = cert.getExtensions();
    Extension directoryAttrsExtension = extensions.getExtension(Extension.subjectDirectoryAttributes);
    if (directoryAttrsExtension != null) {
      Vector<Attribute> attrs = SubjectDirectoryAttributes.getInstance(directoryAttrsExtension.getParsedValue())
          .getAttributes();
      parseAttributes(attrs, info);
    }
    info.keyUsage = KeyUsage.fromExtensions(extensions);
    return info;
  }

  private void parseAttributes(Vector<Attribute> attrs, CertificateInfo info) {
    final int n = attrs.size();
    for (int i = 0; i < n; i++) {
      Attribute attr = attrs.get(i);
      ASN1ObjectIdentifier attrType = attr.getAttrType();
      ASN1Encodable attrVal = attr.getAttributeValues()[0];
      switch (attrType.getId()) {
        case "1.2.804.2.1.1.1.11.1.4.2.1":
          info.edrpou = ASN1PrintableString.getInstance(attrVal).getString();
          break;
        case "1.2.804.2.1.1.1.11.1.4.1.1":
          info.rnokpp = ASN1PrintableString.getInstance(attrVal).getString();
          break;
      }
    }
  }

}
