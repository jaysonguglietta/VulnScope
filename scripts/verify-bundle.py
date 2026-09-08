"""Validate all archive members and hashes before extracting a release bundle."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile


def verify_bundle(archive, destination, digest, ref, allow_dirty=False):
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("Extraction destination must be empty")
    with tarfile.open(archive, "r:gz") as bundle:
        members = []
        names = set()
        total = 0
        for member in bundle:
            name = member.name.rstrip("/")
            parts = PurePosixPath(name).parts
            if not parts or parts[0] != "release" or str(PurePosixPath(name)) != name or name.startswith("/") or ".." in parts or "\\" in name or ":" in name or name in names:
                raise ValueError("Unsafe or duplicate archive path")
            if not (member.isfile() or member.isdir()) or member.size < 0:
                raise ValueError("Links and special archive members are forbidden")
            names.add(name)
            total += member.size
            if len(names) > 2000 or total > 256 * 1024 * 1024:
                raise ValueError("Release bundle exceeds extraction limits")
            members.append(member)
        manifest_member = bundle.getmember("release/release.json")
        if manifest_member.size > 1024 * 1024:
            raise ValueError("Release manifest too large")
        manifest = json.load(bundle.extractfile(manifest_member))
        if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1 or manifest.get("sourceDigest") != digest or manifest.get("sourceRef") != ref:
            raise ValueError("Release source identity mismatch")
        if not isinstance(manifest.get("dirty"), bool) or (manifest["dirty"] and not allow_dirty):
            raise ValueError("Dirty source is not an approved release")
        expected = manifest.get("files")
        if not isinstance(expected, dict):
            raise ValueError("Invalid release manifest")
        actual = set()
        for member in members:
            if not member.isfile() or member.name == "release/release.json":
                continue
            relative = str(PurePosixPath(member.name).relative_to("release"))
            actual.add(relative)
            hasher = hashlib.sha256()
            with bundle.extractfile(member) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    hasher.update(block)
            if expected.get(relative) != hasher.hexdigest():
                raise ValueError("Release file digest mismatch: " + relative)
        if actual != set(expected):
            raise ValueError("Manifest file set mismatch")
        required = {"lambda.zip", "public/index.html", "public/app.js", "public/generated/app.js", "public/generated/sbom-worker.js", "infra/vulnscope.yml", "infra/vulnscope-artifacts.yml"}
        if not required.issubset(actual):
            raise ValueError("Release is missing required deployment files")
        # All names/types/digests were validated; never use archive permission bits.
        destination.mkdir(parents=True, exist_ok=True)
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, target.open("xb") as output:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        output.write(block)


if __name__ == "__main__":
    try:
        verify_bundle(*sys.argv[1:5], allow_dirty="--allow-dirty" in sys.argv[5:])
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        sys.exit("Release rejected: " + str(error))
