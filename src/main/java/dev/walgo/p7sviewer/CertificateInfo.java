package dev.walgo.p7sviewer;

import org.bouncycastle.asn1.x509.KeyUsage;

public class CertificateInfo {

  public String edrpou;
  public String rnokpp;
  public KeyUsage keyUsage;

  private void fillKeyUsage(int flag, String name, StringBuilder builder) {
    if (keyUsage.hasUsages(flag)) {
      if (!builder.isEmpty()) {
        builder.append("|");
      }
      builder.append(name);
    }
  }

  @Override
  public String toString() {
    StringBuilder ku = new StringBuilder();
    fillKeyUsage(KeyUsage.digitalSignature, "digitalSignature", ku);
    fillKeyUsage(KeyUsage.nonRepudiation, "nonRepudiation", ku);
    fillKeyUsage(KeyUsage.keyEncipherment, "keyEncipherment", ku);
    fillKeyUsage(KeyUsage.dataEncipherment, "dataEncipherment", ku);
    fillKeyUsage(KeyUsage.keyAgreement, "keyAgreement", ku);
    fillKeyUsage(KeyUsage.keyCertSign, "keyCertSign", ku);
    fillKeyUsage(KeyUsage.cRLSign, "cRLSign", ku);
    fillKeyUsage(KeyUsage.encipherOnly, "encipherOnly", ku);
    fillKeyUsage(KeyUsage.decipherOnly, "decipherOnly", ku);

    return "edrpou=" + edrpou + ", rnokpp=" + rnokpp + ", keyUsage=" + ku.toString();
  }

}
