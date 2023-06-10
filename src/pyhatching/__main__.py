"""CLI"""

import asyncio
import os

from . import _cmds, PyHatchingClient
from ._args import MAIN_PARSER
from .errors import PyHatchingError


async def async_main():
    """Main function for the CLI."""

    args = MAIN_PARSER.parse_args()

    if args.token is None:
        if (token := os.environ.get("HATCHING_TOKEN")):
            args.token = token
        else:
            print("No token in $HATCHING_TOKEN or passed with --token!")
            return

    if args.command is None:
        print("Must specify a command!")

    try:
        cmd = getattr(_cmds, f"do_{args.command}")
    except AttributeError as err:
        print(f"Unable to find command func for {args.command}: {err}")
        return

    async with PyHatchingClient(api_key=args.token) as client:
        try:
            await cmd(client, args)
        except PyHatchingError as err:
            print(f"{err.__class__.__name__} while executing {args.command}: {err}")


def main():
    """A synchronous main function that just passes ``async_main`` to ``asyncio.run``."""
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
