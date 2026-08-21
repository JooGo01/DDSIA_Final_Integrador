"""Descarga el corpus OWASP desde los repositorios oficiales.

Uso:
    python scripts/fetch_corpus.py [destino]

Los documentos no se versionan en este repositorio: se descargan de la fuente
original para que el corpus sea siempre el publicado por OWASP.
"""

import sys
from pathlib import Path

import httpx

GITHUB_API = "https://api.github.com/repos"
TIMEOUT = 60.0

# (subcarpeta destino, repo, ruta dentro del repo, prefijos de archivo a bajar)
CORPUS = [
    ("web", "OWASP/Top10", "2025/docs/en", ("A0", "A1")),
    ("api", "OWASP/API-Security", "editions/2023/en", ("0xa",)),
]


def list_markdown_files(client: httpx.Client, repo: str, path: str, prefixes: tuple[str, ...]):
    """Lista los .md de una carpeta del repo que empiecen con alguno de los prefijos."""
    response = client.get(f"{GITHUB_API}/{repo}/contents/{path}")
    response.raise_for_status()
    for entry in response.json():
        name = entry.get("name", "")
        if name.endswith(".md") and name.startswith(prefixes):
            yield name, entry["download_url"]


def download_corpus(destination: Path) -> int:
    """Baja todos los documentos configurados. Devuelve la cantidad de archivos escritos."""
    written = 0
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "owasp-rag-assistant"}

    with httpx.Client(timeout=TIMEOUT, headers=headers, follow_redirects=True) as client:
        for folder, repo, path, prefixes in CORPUS:
            target = destination / folder
            target.mkdir(parents=True, exist_ok=True)
            print(f"\n{repo}/{path} -> {target}")

            for name, url in list_markdown_files(client, repo, path, prefixes):
                content = client.get(url).text
                (target / name).write_text(content, encoding="utf-8")
                print(f"  {name} ({len(content):,} caracteres)")
                written += 1

    return written


def main() -> int:
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "data/corpus")
    try:
        total = download_corpus(destination)
    except httpx.HTTPError as exc:
        print(f"\nError al descargar: {exc}", file=sys.stderr)
        return 1

    print(f"\nListo: {total} documentos en {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
