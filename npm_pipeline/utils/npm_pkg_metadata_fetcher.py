import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib
import uuid

import markdown
import requests
from bs4 import BeautifulSoup
from loguru import logger
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from npm_pipeline.classes.npm_pkg_metadata import NpmPkgMetadata

PACKAGE_PAGE_URL = "https://www.npmjs.com/package/{package}"
METADATE_FETCH_COMMAND = "npm view {package} --json"
DOWNLOADS_COUNT_COMMAND = "curl https://api.npmjs.org/downloads/point/last-week/{package}"
ECOSYSTEMS_PACKAGE_URL = (
    "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages/{package}"
)


def fetch_npm_pkg_metadata(package_name: str, tar_temp_path: str) -> NpmPkgMetadata | None:
    """Fetch npm package metadata."""
    command = METADATE_FETCH_COMMAND.format(package=package_name)
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        stdout_in_error = result.stdout
        stdout_in_error_json_data = json.loads(stdout_in_error)
        if "errors" in stdout_in_error_json_data:
            error_code = stdout_in_error_json_data["errors"].get("code", None)
            if error_code == "E404":
                logger.info(
                    f"Package '{package_name}' does not exist in npm registry (404 Not Found)"
                )
            else:
                summary = stdout_in_error_json_data["errors"].get("summary", None)
                if summary:
                    logger.error(
                        f"Failed to fetch npm package metadata for {package_name}: {summary}"
                    )
        else:
            logger.error(
                f"Failed to fetch npm package metadata for {package_name}: {result.stderr}"
            )
        return None

    git_repo_metadata = {
        "repo_url": None,
        "stars": None,
        "commits_number": None,
        "forks": None,
        "contributors_number": None,
    }

    metadata = json.loads(result.stdout)
    package_name: str = metadata.get("name", None)
    versions: list[str] = metadata.get("versions", None)
    time: dict = metadata.get("time", None)
    maintainers: list = metadata.get("maintainers", None)
    contributors: list = metadata.get("contributors", None)
    description: list = metadata.get("description", None)
    repository: dict = metadata.get("repository", None)
    keywords: list = metadata.get("keywords", None)
    tarball: str = metadata.get("dist")["tarball"]
    readme_text, declaration_files = extract_tarball_artifacts(tarball, tar_temp_path)
    weekly_download_count = get_weekly_download_number(package_name)
    dependents_count = get_npm_dependents_count(package_name)

    if repository:
        # npm may return repository as dict or string depending on package
        if isinstance(repository, dict):
            repo_type = repository.get("type", None)
            url = repository.get("url", None)
        else:
            repo_type = "git"
            url = str(repository)

        if repo_type == "git" and url is not None:
            normalized_url = normalize_repo_url(url)
            if normalized_url:
                git_repo_metadata["repo_url"] = normalized_url
                stars, commits_number, forks, contributors_number = fetch_github_repo_metadata(
                    normalized_url
                )
                git_repo_metadata["stars"] = stars
                git_repo_metadata["commits_number"] = commits_number
                git_repo_metadata["forks"] = forks
                git_repo_metadata["contributors_number"] = contributors_number
            else:
                logger.warning(f"Unrecognized repository url, skip github fetch: {url}")

    npm_metadata = NpmPkgMetadata(
        package_name=package_name,
        package_version_list=versions,
        package_description=description,
        package_maintainers=maintainers,
        package_contributors=contributors,
        package_keywords=keywords,
        package_repository=git_repo_metadata,
        package_changelog=time,
        package_weekly_downloads=weekly_download_count,
        package_readme_text=readme_text,
        package_dependents_count=dependents_count,
        package_declaration_files=declaration_files,
    )

    return npm_metadata


def extract_tarball_artifacts(tarball: str, temp_dir: str) -> tuple[str | None, dict[str, str]]:
    """Download the (latest-version) tarball once and extract documentary evidence.

    Returns ``(readme_text, declaration_files)`` where ``declaration_files`` maps
    each tarball-relative ``.d.ts`` path (with the leading ``package/`` stripped)
    to its text. Declaration files referenced by ``package.json``
    (``types`` / ``typings`` / ``exports.types``) are inserted first so that
    downstream method-level extraction searches the public entry points before
    re-exporting barrel files. Both outputs degrade to empty/``None`` on error.
    """
    os.makedirs(temp_dir, exist_ok=True)
    random_temp_dir = os.path.join(temp_dir, uuid.uuid4().hex)
    os.makedirs(random_temp_dir, exist_ok=True)
    file_name = tarball.split("/")[-1]  # the name of the file
    tar_file_path = os.path.join(random_temp_dir, file_name)

    readme_text: str | None = None
    declaration_files: dict[str, str] = {}

    try:
        urllib.request.urlretrieve(tarball, tar_file_path)

        with tarfile.open(tar_file_path, mode="r:gz") as tf:
            members_by_rel: dict[str, tarfile.TarInfo] = {}
            readme_member: tarfile.TarInfo | None = None
            pkg_json_member: tarfile.TarInfo | None = None

            for member in tf.getmembers():
                if not member.isfile():
                    continue
                name = member.name.replace("\\", "/")
                rel = _strip_package_prefix(name)
                members_by_rel[rel] = member
                name_lower = name.lower()
                if readme_member is None and name_lower.startswith("package/readme"):
                    readme_member = member
                if pkg_json_member is None and name_lower == "package/package.json":
                    pkg_json_member = member

            # README -> plain text
            if readme_member is not None:
                extracted = tf.extractfile(readme_member)
                if extracted is not None:
                    readme_content = extracted.read().decode("utf-8", errors="ignore")
                    readme_text = markdown_to_plain_text(readme_content)

            # Declaration entry paths declared in package.json
            entry_paths: list[str] = []
            if pkg_json_member is not None:
                pj = tf.extractfile(pkg_json_member)
                if pj is not None:
                    try:
                        pkg_json = json.loads(pj.read().decode("utf-8", errors="ignore"))
                        entry_paths = _collect_declaration_entry_paths(pkg_json)
                    except Exception as e:
                        logger.warning(f"Failed to parse package.json from tarball: {e}")

            # Build the search order: declared entry .d.ts first, then any other.
            candidate_rels: list[str] = []
            seen: set[str] = set()
            for rel in entry_paths:
                if rel in members_by_rel and rel not in seen:
                    candidate_rels.append(rel)
                    seen.add(rel)
            for rel in members_by_rel:
                if rel.endswith(".d.ts") and rel not in seen:
                    candidate_rels.append(rel)
                    seen.add(rel)

            for rel in candidate_rels:
                member = members_by_rel[rel]
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                text = extracted.read().decode("utf-8", errors="ignore")
                declaration_files[rel] = text

        return readme_text, declaration_files
    except Exception as e:
        logger.error(f"Failed to extract artifacts from tarball: {e}")
        return readme_text, declaration_files
    finally:
        # remove the temporary download
        try:
            if os.path.exists(random_temp_dir):
                shutil.rmtree(random_temp_dir)
        except Exception:
            pass


def _strip_package_prefix(name: str) -> str:
    """Strip the npm tarball ``package/`` root prefix from a member path."""
    name = name.replace("\\", "/")
    if name.startswith("package/"):
        return name[len("package/") :]
    return name


def _normalize_decl_path(path: str | None) -> str | None:
    """Normalize a package.json types path to a tarball-relative ``.d.ts`` path."""
    if not path or not isinstance(path, str):
        return None
    path = path.strip()
    while path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    if not path or not path.endswith(".d.ts"):
        return None
    return path


def _collect_declaration_entry_paths(pkg_json: dict) -> list[str]:
    """Collect declaration-file paths from ``types``/``typings``/``exports.types``."""
    paths: list[str] = []
    seen: set[str] = set()

    def add(value: str | None) -> None:
        normalized = _normalize_decl_path(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            paths.append(normalized)

    add(pkg_json.get("types"))
    add(pkg_json.get("typings"))

    # The `exports` map can nest "types" conditions arbitrarily deep.
    def walk(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "types" and isinstance(value, str):
                    add(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(pkg_json.get("exports"))
    return paths


def markdown_to_plain_text(markdown_content: str) -> str:
    try:
        html = markdown.markdown(markdown_content)
        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text()
        text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)

        return text

    except Exception as e:
        logger.warning(f"Failed to convert markdown to plain text: {e}")
        return markdown_content


_GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0",
}

_github_session = requests.Session()
_retry_strategy = Retry(
    total=3,
    backoff_factor=1,  # 1s, 2s, 4s
    status_forcelist=[500, 502, 503, 504],
    raise_on_status=False,
)
_github_session.mount("https://", HTTPAdapter(max_retries=_retry_strategy))
_github_session.headers.update(_GITHUB_API_HEADERS)


def _extract_owner_repo(repo_link: str) -> str | None:
    match = re.search(r"github\.com/([^/]+/[^/]+)", repo_link)
    if not match:
        return None
    return match.group(1).rstrip("/")


def _get_paginated_count(api_url: str) -> str | None:
    """Get total item count from a paginated GitHub API endpoint (per_page=1 trick)."""
    resp = _github_session.get(api_url)
    if resp.status_code != 200:
        return None
    link_header = resp.headers.get("Link", "")
    match = re.search(r'[&?]page=(\d+)>;\s*rel="last"', link_header)
    if match:
        return match.group(1)
    return str(len(resp.json()))


def fetch_github_repo_metadata(repo_link: str):
    try:
        owner_repo = _extract_owner_repo(repo_link)
        if not owner_repo:
            logger.error(f"Failed to extract owner/repo from: {repo_link}")
            return None, None, None, None

        stars = None
        forks = None
        commits_number = None
        contributors_number = None

        # Stars & Forks from repo endpoint (single request)
        repo_resp = _github_session.get(
            f"https://api.github.com/repos/{owner_repo}",
        )
        if repo_resp.status_code != 200:
            logger.warning(f"Failed to get GitHub repo info: {repo_resp.status_code}")
        else:
            data = repo_resp.json()
            stars = str(data.get("stargazers_count", ""))
            forks = str(data.get("forks_count", ""))

        # Commits count via pagination
        try:
            commits_number = _get_paginated_count(
                f"https://api.github.com/repos/{owner_repo}/commits?per_page=1"
            )
        except Exception as e:
            logger.error(f"Failed to get commits count: {e}")

        # Contributors count via pagination
        try:
            contributors_number = _get_paginated_count(
                f"https://api.github.com/repos/{owner_repo}/contributors?per_page=1&anon=true"
            )
        except Exception as e:
            logger.error(f"Failed to get contributors count: {e}")

        for name, val in [
            ("stars", stars),
            ("forks", forks),
            ("commits", commits_number),
            ("contributors", contributors_number),
        ]:
            if not val:
                logger.error(f"Failed to get {name} from GitHub repository: {repo_link}")

        logger.info(
            f"Stars: {stars}, Commits: {commits_number}, Forks: {forks}, Contributors: {contributors_number}"
        )
        return stars, commits_number, forks, contributors_number
    except Exception as e:
        logger.error(f"Failed to get GitHub repository metadata: {e}")
        return None, None, None, None


def get_weekly_download_number(package_name: str):
    command = DOWNLOADS_COUNT_COMMAND.format(package=package_name)
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"Failed to get weekly download number: {result.stderr}")
            return None
        data = json.loads(result.stdout)
        downloads = data.get("downloads", None)
        return downloads
    except Exception as e:
        logger.error(f"Failed to get weekly download number: {e}")
        return None


def get_npm_dependents_count(package_name: str) -> int | None:
    """Fetch how many other packages depend on this npm package, i.e. the Dependents count.

    Data source: the public ecosyste.ms API.
      GET /registries/npmjs.org/packages/<package> returns
      `dependent_packages_count`, which represents how many other packages
      depend on it.

    Returns:
        Dependent count (int); returns None when the package does not exist or the request fails.
    """
    url = ECOSYSTEMS_PACKAGE_URL.format(package=package_name)
    try:
        response = requests.get(url, timeout=20)
    except requests.RequestException as exc:
        logger.error(f"Failed to get dependents count for {package_name}: {exc}")
        return None

    if response.status_code != 200:
        logger.warning(
            f"Failed to get dependents count (status={response.status_code}): {package_name}"
        )
        return None

    try:
        data = response.json()
    except ValueError:
        logger.warning(f"Dependents count response is not valid JSON: {package_name}")
        return None

    return data.get("dependent_packages_count")


def normalize_repo_url(raw_url: str | None) -> str | None:
    """
    Normalize npm 'repository.url' to a fetchable URL (prefer https GitHub web URL).

    Common npm formats:
    - git+https://github.com/owner/repo.git
    - git://github.com/owner/repo.git
    - ssh://git@github.com/owner/repo.git
    - git@github.com:owner/repo.git
    - github:owner/repo
    """
    if not raw_url:
        return None
    s = str(raw_url).strip()
    if not s:
        return None

    # remove whitespace tails
    s = s.split()[0]

    # strip git+ prefix (may appear multiple times)
    while s.startswith("git+"):
        s = s[4:]

    # drop query/fragment
    s = s.split("#", 1)[0].split("?", 1)[0]

    # github shorthand: github:owner/repo
    m = re.match(r"^github:([^/]+/[^/]+)$", s, flags=re.IGNORECASE)
    if m:
        s = f"https://github.com/{m.group(1)}"

    # scp-like ssh: git@github.com:owner/repo(.git)
    m = re.match(r"^(?:ssh://)?git@github\.com[:/](.+)$", s, flags=re.IGNORECASE)
    if m:
        s = f"https://github.com/{m.group(1)}"

    # git:// -> https:// (GitHub web)
    if s.lower().startswith("git://"):
        s = "https://" + s[6:]

    # ssh://github.com/owner/repo(.git) -> https://github.com/owner/repo
    if s.lower().startswith("ssh://"):
        s = "https://" + s[6:]

    # trim trailing .git and trailing slash
    if s.lower().endswith(".git"):
        s = s[:-4]
    s = s.rstrip("/")

    # only return URLs we can fetch via requests
    if s.lower().startswith(("http://", "https://")):
        return s
    return None


if __name__ == "__main__":
    # fetch_npm_pkg_metadata("@nestjs/axios")
    stars, commits_number, forks, contributors_number = fetch_github_repo_metadata(
        "https://github.com/axios/axios"
    )
    logger.info(stars)
    logger.info(commits_number)
    logger.info(forks)
    logger.info(contributors_number)
    # readme = extract_readme_from_tarball(
    #     "https://registry.npmjs.org/@nestjs/axios/-/axios-4.0.1.tgz",
    #     "/home/huangyh/profMalPlus/workspace/test_package/static/pkd_download",
    # )
    # logger.info(readme)
    # get_weekly_download_number("axios")
