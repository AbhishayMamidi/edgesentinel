"""Package release distributions and compute SHA-256 checksums."""

from pathlib import Path
import hashlib
import os
import tarfile
import zipfile


def make_release():
    root = Path(__file__).resolve().parent.parent
    dist_dir = root / "dist"
    dist_dir.mkdir(exist_ok=True)

    archive_base = "edgesentinel-0.1.0-rc1"
    tar_path = dist_dir / f"{archive_base}.tar.gz"
    zip_path = dist_dir / f"{archive_base}.zip"

    exclude_names = {
        ".git", "__pycache__", ".pytest_cache", ".venv",
        "build", "dist", "data", "logs", ".eggs", "edgesentinel.egg-info"
    }

    def should_exclude(rel_path: str) -> bool:
        parts = rel_path.replace("\\", "/").split("/")
        for p in parts:
            if p in exclude_names or p.endswith(".pyc") or p.endswith(".db"):
                return True
        return False

    # 1. Create .tar.gz
    with tarfile.open(tar_path, "w:gz") as tar:
        for file_path in root.rglob("*"):
            rel = file_path.relative_to(root)
            rel_str = str(rel)
            if should_exclude(rel_str):
                continue
            tar.add(file_path, arcname=f"{archive_base}/{rel_str}")

    print(f"[+] Created {tar_path.name} ({tar_path.stat().st_size:,} bytes)")

    # 2. Create .zip
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_f:
        for file_path in root.rglob("*"):
            rel = file_path.relative_to(root)
            rel_str = str(rel)
            if should_exclude(rel_str):
                continue
            zip_f.write(file_path, arcname=f"{archive_base}/{rel_str}")

    print(f"[+] Created {zip_path.name} ({zip_path.stat().st_size:,} bytes)")

    # 3. Compute SHA256 checksums for all release artifacts
    checksum_lines = []
    for item in sorted(dist_dir.iterdir()):
        if item.name == "SHA256SUMS.txt" or item.is_dir():
            continue
        sha = hashlib.sha256(item.read_bytes()).hexdigest()
        checksum_lines.append(f"{sha}  {item.name}")

    sha_file = dist_dir / "SHA256SUMS.txt"
    sha_file.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    print("\nRelease Checksums (SHA-256):")
    for line in checksum_lines:
        print(f"  {line}")


if __name__ == "__main__":
    make_release()
