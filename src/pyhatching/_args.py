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
    description="Search for, submit, download, and get reporting on sandbox samples.",
)
SAMPLES_PARSER.add_argument(
    "action",
    help="What to do with this sample.",
    choices=("download", "info", "report", "submit",)
)
SAMPLES_PARSER.add_argument(
    "-s",
    "--sample",
    help="The sample id or hash of the sample to work with.",
)
SAMPLES_PARSER.add_argument(
    "-p",
    "--path",
    help="The path of the sample to submit, the path to download the "
    "sample to, or the path to save the report to.",
    type=pathlib.Path,
)
