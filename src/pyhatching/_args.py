"""Arguments for the CLI."""

import argparse
import pathlib


MAIN_PARSER = argparse.ArgumentParser(
    description="A CLI for the Hatching Triage Sandbox."
)
MAIN_PARSER.add_argument(
    "--debug",
    help="Display debug output.",
    action="store_true",
)
MAIN_PARSER.add_argument(
    "--version",
    help="Display the version and exit.",
    action="store_true",
)
MAIN_PARSER.add_argument(
    "-t",
    "--token",
    help="Use this token instead of the HATCHING_TOKEN environment variable.",
)
SUBPARSER = MAIN_PARSER.add_subparsers(dest="command", title="Commands")

PROFILE_PARSER = SUBPARSER.add_parser(
    "profile",
    description="Work with sandbox profiles",
)
PROFILE_PARSER.add_argument(
    "action",
    choices=("get", "list"),
    help="Whether to get a specific profile or list them all."
)
PROFILE_PARSER.add_argument(
    "-p",
    "--profile",
    help="The profile name or ID to get.",
)

SEARCH_PARSER = SUBPARSER.add_parser(
    "search",
    description="Search Hatching Triage Sandbox",
)
SEARCH_PARSER.add_argument(
    "query",
    help="The query string - see https://tria.ge/docs/cloud-api/search/",
)

SAMPLES_PARSER = SUBPARSER.add_parser(
    "samples",
    description="Search for, submit, download, and get reporting on sandbox "
    "samples. Supports the following hashes: md5, sha1, sha2, ssdeep",
)
SAMPLES_SUBPARSER = SAMPLES_PARSER.add_subparsers(dest="action", title="Actions")
DOWNLOAD_SAMPLES_PARSER = SAMPLES_SUBPARSER.add_parser(
    "download",
    description="Download a given sample by uuid or hash.",
)
DOWNLOAD_SAMPLES_PARSER.add_argument(
    "-s",
    "--sample",
    help="The sample id or hash to download.",
)
DOWNLOAD_SAMPLES_PARSER.add_argument(
    "-p",
    "--path",
    help="The path to save the file(s). If a dir is given the hash is used "
    "as the filename to avoid accidental execution.",
    type=pathlib.Path,
)
INFO_SAMPLES_PARSER = SAMPLES_SUBPARSER.add_parser(
    "info",
    description="Download a given sample by uuid or hash.",
)
INFO_SAMPLES_PARSER.add_argument(
    "-s",
    "--sample",
    help="The sample id or hash to get info on.",
)
REPORT_SAMPLES_PARSER = SAMPLES_SUBPARSER.add_parser(
    "report",
    description="Get the overview report for a given sample by uuid or hash.",
)
REPORT_SAMPLES_PARSER.add_argument(
    "-s",
    "--sample",
    help="The sample id or hash to get a report on.",
)

YARA_PARSER = SUBPARSER.add_parser(
    "yara",
    description="Manipulate sandbox Yara rules.",
)
YARA_PARSER.add_argument(
    "action",
    choices=("get", "update", "create", "export"),
    help="Whether to get one rule, update/create a rule, or export all rules."
)
YARA_PARSER.add_argument(
    "-n",
    "--name",
    help="The name of the rule to get/create/update."
)
YARA_PARSER.add_argument(
    "-p",
    "--path",
    help="The rule to upload, or the download path (must be a dir for export).",
    type=pathlib.Path,
)
