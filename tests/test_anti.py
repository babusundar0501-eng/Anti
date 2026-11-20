import tempfile, unittest
from pathlib import Path
import anti

class ScannerTests(unittest.TestCase):
    def test_entropy(self): self.assertEqual(anti.entropy(b"AAAA"),0.0)
    def test_eicar(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"test.txt";p.write_bytes(anti.EICAR)
            r=anti.inspect_file(p);self.assertEqual(r["status"],"threat");self.assertEqual(r["severity"],"critical")
    def test_pe_disguised_as_pdf(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"invoice.pdf";p.write_bytes(b"MZ"+b"\0"*100)
            self.assertEqual(anti.inspect_file(p)["status"],"threat")
    def test_plain_text(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"notes.txt";p.write_text("Harmless test text")
            self.assertEqual(anti.inspect_file(p)["status"],"clean")
if __name__=="__main__":unittest.main()
