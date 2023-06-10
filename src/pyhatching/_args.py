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
    "--token",
    help="Use this token instead of the HATCHING_TOKEN environment variable.",
)
SUBPARSER = MAIN_PARSER.add_subparsers(dest="command", title="Commands", required=True)

PROFILE_PARSER = SUBPARSER.add_parser(
    "profile",
    description="Work with sandbox profiles",
)
PROFILE_SUBPARSER = PROFILE_PARSER.add_subparsers(
    dest="action", title="Actions", required=True
)
GET_PROFILE_PARSER = PROFILE_SUBPARSER.add_parser(
    "get",
    description="Download a given sample by uuid or hash.",
)
GET_PROFILE_PARSER.add_argument(
    "-p",
    "--profile",
    help="The sandbox profile name or ID to get.",
)
LIST_PROFILE_PARSER = PROFILE_SUBPARSER.add_parser(
    "list",
    description="List all sandbox profiles.",
)
CREATE_PROFILE_PARSER = PROFILE_SUBPARSER.add_parser(
    "create",
    description="Create a new sandbox profile.",
)
CREATE_PROFILE_PARSER.add_argument(
    "-n",
    "--name",
    help="The name to give the new profile.",
)
CREATE_PROFILE_PARSER.add_argument(
    "--tags",
    help="The tags for the new profile.",
    nargs="+",
    default=[],
)
CREATE_PROFILE_PARSER.add_argument(
    "--timeout",
    help="The new profile's timeout.",
    type=int,
)
CREATE_PROFILE_PARSER.add_argument(
    "--network",
    help="The new profile's network config - see "
    "https://tria.ge/docs/cloud-api/profiles/ for options.",
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
SAMPLES_SUBPARSER = SAMPLES_PARSER.add_subparsers(
    dest="action", title="Actions", required=True
)
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
SUBMIT_SAMPLES_PARSER = SAMPLES_SUBPARSER.add_parser(
    "submit",
    description="Submit a file to the sandbox.",
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "-k",
    "--kind",
    help="The kind of sandbox submission.",
    choices=("file", "url", "fetch"),
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "-u",
    "--url",
    help="The URL to fetch or analyze.",
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "-t",
    "--target",
    help="The name to give the submitted file when executed in the sandbox. "
    "Uses filename on disk otherwise.",
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "-i",
    "--interactive",
    help="Run the sandbox in interactive mode - may mess with automation.",
    action="store_true",
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "-pw",
    "--password",
    help="The decryption password if the given sample is an encrypted zip.",
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "-p",
    "--profile",
    help="The name of the profile to use for analysis.",
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "-pi",
    "--pick",
    help="If the given sample is a zip, execute this child file within.",
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "--tags",
    help="The user tags to give this sample.",
    nargs="+",
    default=None,
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "--timeout",
    help="The sandbox timeout for this analysis.",
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "-n",
    "--network",
    help="The sandbox network config for this analysis.",
)
SUBMIT_SAMPLES_PARSER.add_argument(
    "-f",
    "--file",
    help="The path to a local file to upload.",
    default=None,
)

YARA_PARSER = SUBPARSER.add_parser(
    "yara",
    description="Manipulate sandbox Yara rules.",
)
YARA_PARSER.add_argument(
    "action",
    choices=("get", "update", "create", "export"),
    help="Whether to get one rule, update/create a rule, or export all rules.",
)
YARA_PARSER.add_argument(
    "-n", "--name", help="The name of the rule to get/create/update."
)
YARA_PARSER.add_argument(
    "-p",
    "--path",
    help="The rule to upload, or the download path (must be a dir for export).",
    type=pathlib.Path,
)
