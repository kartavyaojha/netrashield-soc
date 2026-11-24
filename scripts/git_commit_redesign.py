import os
from pathlib import Path
from dulwich import porcelain
from dulwich.repo import Repo

root = Path(r"c:\Users\OKart\Desktop\project")
repo = Repo(str(root))

ignored_prefixes = [
    ".git",
    ".venv",
    "frontend/node_modules",
    "node_modules",
    "frontend/dist",
    "__pycache__",
    ".pytest_cache"
]

files_to_add = []
for p in root.rglob("*"):
    if p.is_file():
        rel = p.relative_to(root).as_posix()
        if any(rel == ig or rel.startswith(ig + "/") for ig in ignored_prefixes):
            continue
        files_to_add.append(rel)

print(f"[*] Staging {len(files_to_add)} files...")
porcelain.add(str(root), paths=files_to_add)

msg = b"Rebuild frontend with Bonanza Studios dark editorial design system"
author = b"Kartavya <kartavya@netrashield.local>"
commit_id = porcelain.commit(str(root), message=msg, author=author, committer=author)
commit_hex = commit_id.decode("ascii") if isinstance(commit_id, bytes) else str(commit_id)

print(f"[+] Committed successfully!")
print(f"    Commit ID: {commit_hex}")
print(f"    Message: {msg.decode()}")
