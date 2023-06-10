"""CLI"""

import asyncio
import json
import os

from ._args import MAIN_PARSER
from .client import new_client, PyHatchingClient
from .base import ErrorResponse


def check_and_print_err(obj):
    """Check if obj is an ErrorResponse and print it before returning True, else False."""
    if isinstance(obj, ErrorResponse):
        print(f"{obj.error.value}: {obj.message}")
        return True
    return False


async def do_profile(client: PyHatchingClient, args):
    """Handle the profile command."""

    if args.action == "list":
        profiles = await client.get_profiles()
        if check_and_print_err(profiles):
            return
        print(profiles)
    elif args.action == "get" and args.profile is None:
        print("Must specify a profile to get!")
        return
    else:
        profile = await client.get_profile(args.profile)
        if check_and_print_err(profile):
            return
        print(profile)


async def do_samples(client: PyHatchingClient, args):
    """Handle the samples command."""

    if args.action == "download":
        sample_bytes = await client.download_sample(args.sample)
        if sample_bytes:
            with open(args.path, "wb") as fd:
                fd.write(sample_bytes)
        else:
            print(f"No bytes found for {args.sample}")

    elif args.action == "info":
        sample_info = await client.get_sample(args.sample)
        if check_and_print_err(sample_info):
            return
        print(sample_info)

    elif args.action == "report":
        report = await client.overview(args.sample)
        if check_and_print_err(report):
            return
        with open(args.path, "w") as fd:
            fd.write(json.dumps(report, indent=2))

    else:
        raise NotImplementedError()
        success = await client.submit_sample(None ,args.path)


async def do_search(client: PyHatchingClient, args):
    """Handle the search command."""

    samples = await client.search(args.query)
    if check_and_print_err(samples):
        return
    print(samples)


async def do_yara(client: PyHatchingClient, args):
    """Handle the yara command."""

    if args.action == "get":
        rule = await client.get_rule(args.name)
        if check_and_print_err(rule):
            return
        with open(args.path, "w") as fd:
            fd.write(rule.rule)
            print(f"Wrote {rule.name} to {args.path}")
        if rule.warnings:
            print(f"Rule warnings!\n\n{rule.warnings}\n")
    if args.action == "update":
        raise NotImplementedError()
    if args.action == "create":
        raise NotImplementedError()
    if args.action == "export":
        raise NotImplementedError()

async def main():
    """Main function for the CLI."""

    args = MAIN_PARSER.parse_args()

    if not args.token:
        token = os.environ.get("HATCHING_TOKEN")
        if token:
            args.token = token
        else:
            print("No token in $HATCHING_TOKEN or passed with --token!")

    client = await new_client(api_key=args.token)

    match args.command:
        case "profile":
            do_profile(client, args)
        case "search":
            do_search(client, args)
        case "samples":
            do_samples(client, args)
        case "yara":
            do_yara(client, args)

    breakpoint()

if __name__ == "__main__":
    asyncio.run(main())
