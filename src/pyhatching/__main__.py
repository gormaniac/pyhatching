"""CLI"""

import asyncio
import os

from . import _cmds, PyHatchingClient
from ._args import MAIN_PARSER
from .errors import PyHatchingError


async def main():
    """Main function for the CLI."""

    args = MAIN_PARSER.parse_args()

    if not args.token:
        if (token := os.environ.get("HATCHING_TOKEN")):
            args.token = token
        else:
            print("No token in $HATCHING_TOKEN or passed with --token!")
            return

    try:
        cmd = getattr(_cmds, f"do_{args.command}")
    except AttributeError as err:
        print(f"Unable to find command func for {args.command}: {err}")
        return

    async with PyHatchingClient(api_key=args.token) as client:
        try:
            cmd(client, args)
        except PyHatchingError as err:
            print(f"{str(type(err))} while executing {args.command}: {err}")


if __name__ == "__main__":
    asyncio.run(main())
