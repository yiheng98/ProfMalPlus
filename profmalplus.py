import argparse
import os
import sys

from loguru import logger

from analyse import analyse


def str2bool(value):
    if isinstance(value, bool):
        return value
    if value.lower() in ("yes", "true", "t", "y", "1"):
        return True
    if value.lower() in ("no", "false", "f", "n", "0"):
        return False
    raise argparse.ArgumentTypeError(f"Boolean value expected, got: {value!r}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="profmalplus",
        description="profMalPlus: analyse npm packages for malicious behaviour.",
    )
    parser.add_argument(
        "--package_path",
        required=True,
        help="Path to the npm package source directory. "
        "The package name is derived from the last component of this path.",
    )
    parser.add_argument(
        "--workspace_path",
        default=None,
        help="Path to the workspace directory used to store analysis output. "
        "Defaults to a 'profMalPlus_workspace' directory created two levels "
        "above this script.",
    )
    parser.add_argument(
        "--dynamic_support",
        type=str2bool,
        nargs="?",
        const=True,
        default=True,
        help="Whether to enable dynamic analysis support (true/false). Enabled by default.",
    )
    parser.add_argument(
        "--verbose",
        type=str2bool,
        nargs="?",
        const=True,
        default=False,
        help="Whether to show detailed node-identification logs from the "
        "call-processing path (true/false). Disabled by default.",
    )
    return parser.parse_args(argv)


def default_workspace_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    return os.path.join(base_dir, "profMalPlus_workspace")


def main(argv=None):
    args = parse_args(argv)

    package_path = os.path.abspath(args.package_path)
    if args.workspace_path:
        workspace_path = os.path.abspath(args.workspace_path)
    else:
        workspace_path = default_workspace_path()

    if not os.path.isdir(package_path):
        logger.error(f"package_path does not exist or is not a directory: {package_path}")
        return 1

    package_name = os.path.basename(os.path.normpath(package_path))
    if not package_name:
        logger.error(f"could not derive package name from package_path: {package_path}")
        return 1

    os.makedirs(workspace_path, exist_ok=True)

    analyse(
        package_name,
        package_path,
        workspace_path,
        args.dynamic_support,
        args.verbose,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
