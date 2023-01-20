package dev.walgo.p7sviewer;

import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class P7SViewerTest {
  
  public P7SViewerTest() {
  }

  /**
   * Test of view method, of class P7SViewer.
   */
  @Test
  @Disabled
  public void testViewSigners() throws Exception {
    InputStream stream = getClass().getClassLoader().getResourceAsStream("test.p7s");
    P7SViewer instance = new P7SViewer(stream);
    instance.viewSigners();
  }

  @Test
  public void testViewCerts() throws Exception {
    InputStream stream = getClass().getClassLoader().getResourceAsStream("test.p7s");
    P7SViewer instance = new P7SViewer(stream);
    instance.viewCerts();
  }
  
}
