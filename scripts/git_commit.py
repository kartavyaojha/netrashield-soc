import os
import sys
from pathlib import Path
from dulwich import porcelain
from dulwich.repo import Repo

root = Path(r"c:\Users\OKart\Desktop\project")

# 1. git init
git_dir = root / ".git"
if not git_dir.exists():
    print("[*] Initializing git repository...")
    repo = porcelain.init(str(root))
else:
    print("[*] Git repository already initialized.")
    repo = Repo(str(root))

# 2. Collect files respecting .gitignore
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
        # check if ignored
        if any(rel == ig or rel.startswith(ig + "/") for ig in ignored_prefixes):
            continue
        files_to_add.append(rel)

print(f"[*] Staging {len(files_to_add)} files...")
porcelain.add(str(root), paths=files_to_add)

# 3. git commit
msg = b"Working NetraShield SOC backup before UI redesign"
author = b"Kartavya <kartavya@netrashield.local>"
commit_id = porcelain.commit(str(root), message=msg, author=author, committer=author)
commit_hex = commit_id.decode("ascii") if isinstance(commit_id, bytes) else str(commit_id)

print(f"[+] Committed successfully!")
print(f"    Commit ID: {commit_hex}")
print(f"    Message: {msg.decode()}")

# 4. Print commit info
repo = Repo(str(root))
head = repo.head()
print(f"    HEAD ref: {head}")
