import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("bundle", Path(__file__).with_name("verify-bundle.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseTests(unittest.TestCase):
    def fixture(self, directory, change=None):
        files = {name: b"fixture" for name in ["lambda.zip", "public/index.html", "public/app.js", "public/generated/app.js", "public/generated/sbom-worker.js", "infra/vulnscope.yml", "infra/vulnscope-artifacts.yml"]}
        manifest = {"schemaVersion": 1, "sourceDigest": "a" * 40, "sourceRef": "refs/tags/v0.3.1", "dirty": False, "files": {key: hashlib.sha256(value).hexdigest() for key, value in files.items()}}
        if change == "tamper":
            files["public/app.js"] = b"tampered"
        if change == "extra":
            files["public/unverified.js"] = b"extra"
        if change == "missing":
            del files["infra/vulnscope.yml"]
        if change == "dirty":
            manifest["dirty"] = True
        archive = Path(directory) / "bundle.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name, data in {**files, "release.json": json.dumps(manifest).encode()}.items():
                member = tarfile.TarInfo("release/" + name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
            if change in ["traversal", "symlink", "appledouble", "noncanonical"]:
                member = tarfile.TarInfo({"traversal": "release/../outside", "symlink": "release/link", "appledouble": "._release", "noncanonical": "release/./extra"}[change])
                if change == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "../../outside"
                output.addfile(member)
        return archive

    def test_valid_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            module.verify_bundle(self.fixture(directory), Path(directory) / "out", "a" * 40, "refs/tags/v0.3.1")
            self.assertTrue((Path(directory) / "out/release/public/app.js").exists())

    def test_invalid_bundles(self):
        for change in ["tamper", "extra", "missing", "traversal", "symlink", "wrong-ref", "wrong-commit", "dirty", "appledouble", "noncanonical"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    module.verify_bundle(self.fixture(directory, change), Path(directory) / "out", ("b" if change == "wrong-commit" else "a") * 40, "refs/tags/wrong" if change == "wrong-ref" else "refs/tags/v0.3.1")
                self.assertFalse((Path(directory) / "out").exists())


if __name__ == "__main__":
    unittest.main()
