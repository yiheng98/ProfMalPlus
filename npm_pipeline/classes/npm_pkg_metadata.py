from datetime import datetime, timedelta, timezone

from loguru import logger

from llm import (
    llm_interpret_api_behavior,
    llm_interpret_module_overall_functionality,
    llm_interpret_package_trust,
)
from npm_pipeline.utils.dts_parser import extract_method_evidence_from_files


class NpmPkgMetadata:
    def __init__(
        self,
        package_name: str,
        package_version_list: list[str],
        package_description: str | None,
        package_maintainers: list[str] | None,
        package_contributors: list[str] | None,
        package_keywords: list[str] | None,
        package_repository: dict[str, str] | None,
        package_changelog: dict[str, str] | None,
        package_weekly_downloads: int | None,
        package_readme_text: str | None,
        package_dependents_count: int | None = None,
        package_declaration_files: dict[str, str] | None = None,
    ):
        self.package_name = package_name
        self.package_version_list = package_version_list
        self.package_description = package_description
        self.package_keywords = package_keywords
        self.package_repository = package_repository
        self.package_changelog = package_changelog
        self.package_weekly_downloads = package_weekly_downloads
        self.package_readme_text = package_readme_text
        self.package_dependents_count = package_dependents_count
        # Interface-level evidence: tarball-relative `.d.ts` path -> file text,
        # with package.json-declared entry files ordered first.
        self.package_declaration_files = package_declaration_files

    def __str__(self) -> str:
        version_count = len(self.package_version_list) if self.package_version_list else 0
        if self.package_readme_text is None:
            readme_preview = None
        else:
            readme_preview = f"<{len(self.package_readme_text)} chars>"

        if self.package_declaration_files is None:
            declaration_files_preview = None
        else:
            declaration_files_preview = list(self.package_declaration_files.keys())

        lines = [
            "NpmPkgMetadata(",
            f"  package_name={self.package_name!r},",
            f"  package_description={self.package_description!r},",
            f"  package_version_count={version_count},",
            f"  package_keywords={self.package_keywords!r},",
            f"  package_repository={self.package_repository!r},",
            f"  package_weekly_downloads={self.package_weekly_downloads!r},",
            f"  package_dependents_count={self.package_dependents_count!r},",
            f"  package_readme_text={readme_preview},",
            f"  package_declaration_files={declaration_files_preview!r},",
            ")",
        ]
        return "\n".join(lines)

    def __repr__(self) -> str:
        return self.__str__()

    def has_recent_release(self, months: int = 12) -> bool:
        """
        has recent release in the last months
        """
        if not self.package_changelog:
            return False

        # Use timezone-aware UTC datetimes to avoid "naive vs aware" comparison errors.
        threshold_date = datetime.now(timezone.utc) - timedelta(days=months * 30)
        for version_key, release_time_str in self.package_changelog.items():
            if version_key in ["created", "modified"]:
                continue

            try:
                release_time = datetime.fromisoformat(release_time_str.replace("Z", "+00:00"))
                # Some timestamps may be timezone-naive; treat them as UTC.
                if release_time.tzinfo is None:
                    release_time = release_time.replace(tzinfo=timezone.utc)
                if release_time > threshold_date:
                    return True
            except Exception as e:
                logger.warning(f"Failed to parse release time for version {version_key}: {e}")
                continue

        return False

    def is_trustworthy(self) -> bool:
        """
        Determine whether the current NPM package is trustworthy.
        """
        # 1. weekly downloads > 10,000
        # 2. repository is not None
        # 3. version list >= 3
        # 4. readme exist
        # 5. new released in last year

        if (
            self.package_weekly_downloads
            and self.package_weekly_downloads > 10000
            and self.package_repository
            and self.package_version_list
            and len(self.package_version_list) >= 3
            and self.package_readme_text is not None
            and self.has_recent_release(months=12)
        ):
            logger.info(f"Package {self.package_name} is trustworthy by hard rules")
            return True

        # Being depended on by many other packages is a strong trust signal.
        if self.package_dependents_count and self.package_dependents_count > 10000:
            logger.info(
                f"Package {self.package_name} is trustworthy by dependents count "
                f"({self.package_dependents_count})"
            )
            return True

        if not self.package_readme_text or not self.package_repository:
            # no readme or no repository, return False
            return False

        # LLM
        input_data = {
            "package_readme_text": self.package_readme_text,
            "package_description": self.package_description,
            "package_weekly_downloads": self.package_weekly_downloads,
            "stars_number_of_repository": self.package_repository["stars"],
            "forks_number_of_repository": self.package_repository["forks"],
            "contributors_number_of_repository": self.package_repository["contributors_number"],
            "commits_number_of_repository": self.package_repository["commits_number"],
            "package_versions_count": len(self.package_version_list),
            "package_changelog": self.package_changelog,
            "package_dependents_count": self.package_dependents_count,
        }
        llm_result = llm_interpret_package_trust(input_data)
        logger.info(f"[LLM] Trust interpretation: {llm_result}")
        if llm_result and llm_result.get("trust_level") == "HIGH_TRUST":
            return True

        return False

    def get_module_behavior(self) -> str | None:
        """
        Use the package README, description, and keywords to generate an LLM-based module behavior description.
        """
        input_data = {
            "package_name": self.package_name,
            "package_description": self.package_description,
            "package_keywords": self.package_keywords,
            "package_readme_text": self.package_readme_text,
        }

        module_functionality = llm_interpret_module_overall_functionality(input_data)
        if (
            module_functionality
            and module_functionality.get("overall_functionality", "unknown") != "unknown"
        ):
            return module_functionality.get("overall_functionality")
        else:
            return None

    def _extract_declaration_evidence(self, method_name: str) -> str | None:
        """Parse the stored `.d.ts` files for *method_name*'s declaration block.

        Returns the enclosing declaration (signature + JSDoc) as interface-level
        evidence, or ``None`` when no declaration file documents the method.
        """
        if not self.package_declaration_files:
            return None
        try:
            return extract_method_evidence_from_files(self.package_declaration_files, method_name)
        except Exception as e:
            logger.warning(
                f"Failed to extract declaration evidence for {self.package_name}.{method_name}: {e}"
            )
            return None

    def get_api_behavior(self, method_name: str) -> str | None:
        """
        Use the package README, description, and keywords to generate an LLM-based API behavior description.
        """
        input_data = {
            "method_name": method_name,
            "package_name": self.package_name,
            "package_description": self.package_description,
            "package_keywords": self.package_keywords,
            "package_readme_text": self.package_readme_text,
            "declaration_evidence": self._extract_declaration_evidence(method_name),
        }

        api_behavior = llm_interpret_api_behavior(input_data)
        if api_behavior and api_behavior.get("api_behavior", "unknown") != "unknown":
            return api_behavior.get("api_behavior")
        else:
            return None
