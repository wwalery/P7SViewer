package dev.walgo.p7sviewer;

import java.io.File;
import java.io.FileInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Main class
public class Main {

  private static final Logger LOG = LoggerFactory.getLogger(Main.class);

  private Main() {
    // do nothing
  }

  // main method
  @SuppressWarnings("unchecked")
  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      LOG.error("Usage: P7SViewer file.p7s");
      System.exit(1);
    }
    File file = new File(args[0]);
    if (!file.exists()) {
      LOG.error("File [{}] doesn't exists", args[0]);
      System.exit(1);
    }

    try (FileInputStream stream = new FileInputStream(file)) {
      P7SViewer viewer = new P7SViewer(stream);
      viewer.viewCerts();
    }
//   Store cs = signature.getCertificates();
//   SignerInformationStore signers = signature.getSignerInfos();
//   Collection c = signers.getSigners();
//   Iterator it = c.iterator();
//
//   //the following array will contain the content of xml document
//   byte[] data = null;
//
//   while (it.hasNext()) {
//        SignerInformation signer = (SignerInformation) it.next();
//        Collection certCollection = cs.getMatches(signer.getSID());
//        Iterator certIt = certCollection.iterator();
//        X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
//
//        CMSProcessable sc = signature.getSignedContent();
//        data = (byte[]) sc.getContent();
//    }signers)
//   Store cs = signature.getCertificates();
//   SignerInformationStore signers = signature.getSignerInfos();
//   Collection c = signers.getSigners();
//   Iterator it = c.iterator();
//
//   //the following array will contain the content of xml document
//   byte[] data = null;
//
//   while (it.hasNext()) {
//        SignerInformation signer = (SignerInformation) it.next();
//        Collection certCollection = cs.getMatches(signer.getSID());
//        Iterator certIt = certCollection.iterator();
//        X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
//
//        CMSProcessable sc = signature.getSignedContent();
//        data = (byte[]) sc.getContent();
//    }
//   Store cs = signature.getCertificates();
//   SignerInformationStore signers = signature.getSignerInfos();
//   Collection c = signers.getSigners();
//   Iterator it = c.iterator();
//
//   //the following array will contain the content of xml document
//   byte[] data = null;
//
//   while (it.hasNext()) {
//        SignerInformation signer = (SignerInformation) it.next();
//        Collection certCollection = cs.getMatches(signer.getSID());
//        Iterator certIt = certCollection.iterator();
//        X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
//
//        CMSProcessable sc = signature.getSignedContent();
//        data = (byte[]) sc.getContent();
//    }signers)
//   Store cs = signature.getCertificates();
//   SignerInformationStore signers = signature.getSignerInfos();
//   Collection c = signers.getSigners();
//   Iterator it = c.iterator();
//
//   //the following array will contain the content of xml document
//   byte[] data = null;
//
//   while (it.hasNext()) {
//        SignerInformation signer = (SignerInformation) it.next();
//        Collection certCollection = cs.getMatches(signer.getSID());
//        Iterator certIt = certCollection.iterator();
//        X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
//
//        CMSProcessable sc = signature.getSignedContent();
//        data = (byte[]) sc.getContent();
//    }
  }

}
