"""CLI"""

import asyncio
import json

from ._args import MAIN_PARSER
from .client import new_client


async def do_profile(client, args):
    """Handle the profile command."""

    if args.action == "list":
        profiles = await client.get_profiles()
        print(profiles)
    elif args.action == "get" and args.profile is None:
        print("Must specify a profile to get!")
        return
    else:
        profile = await client.get_profile(args.profile)
        print(profile)


async def do_samples(client, args):
    """Handle the samples command."""

    if args.action == "download":
        sample_bytes = await client.download_sample(args.sample)
        with open(args.path, "wb") as fd:
            fd.write(sample_bytes)
    elif args.action == "info":
        sample_info = await client.get_sample(args.sample)
        print(sample_info)
    elif args.action == "report":
        report = await client.overview(args.sample)
        with open(args.path, "w") as fd:
            fd.write(json.dumps(report, indent=2))
    else:
        raise NotImplementedError()
        success = await client.submit_sample(None ,args.path)


async def do_search(client, args):
    """Handle the search command."""

    samples = await client.search(args.query)
    print(samples)


async def main():
    """Main function for the CLI."""

    args = MAIN_PARSER.parse_args()

    client = await new_client(api_key=args.token)

    match args.command:
        case "profile":
            do_profile(client, args)
        case "search":
            do_search(client, args)
        case "samples":
            do_samples(client, args)

    breakpoint()

if __name__ == "__main__":
    asyncio.run(main())
