"""Commands for the main func to dispatch."""

import json
from pydantic import ValidationError

from . import PyHatchingClient
from .base import ErrorResponse, SubmissionRequest


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
    elif args.action == "get":
        profile = await client.get_profile(args.profile)
        if check_and_print_err(profile):
            return
        print(profile)
    elif args.action == "create":
        profile = await client.submit_profile(
            args.name,
            args.tags,
            args.timeout,
            args.network,
        )
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

    elif args.action == "submit":
        profile_args = {"profile": args.profile, "pick": args.pick}
        profile = {k: v for k, v in profile_args.items() if v is not None}

        defaults_args = {"network": args.network, "timeout": args.timeout}
        defaults = {k: v for k, v in defaults_args.items() if v is not None}

        try:
            submit_args = SubmissionRequest(
                kind=args.kind,
                url=args.url,
                target=args.target,
                interactive=args.interactive,
                password=args.password,
                profiles=[profile] if profile else None,
                user_tags=args.tags,
                defaults=defaults if defaults else None,
            )
        except ValidationError as err:
            print(f"Unable to validate sample submission args: {err}")
            return
        sample = await client.submit_sample(submit_args, args.file)
        if check_and_print_err(report):
            return
        print(sample)


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
        fpath = args.path if args.path else args.name
        with open(fpath, "w") as fd:
            fd.write(rule.rule)
            print(f"Wrote {rule.name} to {fpath}")
        if rule.warnings:
            print(f"Rule warnings!\n\n{rule.warnings}\n")
    if args.action in ("create", "update"):
        with open(args.path, "r") as fd:
            rule_str = fd.read()
        # TODO Print the response here
        if args.action == "create":
            ret = await client.submit_rule(args.name, rule_str)
        else:
            ret = await client.update_rule(args.name, rule_str)
        if check_and_print_err(ret):
            return
        if ret is None:
            print(f"Successfully {args.action}d {args.name}!")
        else:
            print(ret)
    if args.action == "export":
        rules = await client.get_rules()
        if check_and_print_err(rule):
            return
        for rule in rules.rules:
            with open(args.path + rule.name, "w") as fd:
                fd.write(rule.rule)
