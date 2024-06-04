import getopt
import logging
from logging.config import dictConfig
import os
import sys
from datetime import datetime

import coloredlogs  # pylint: disable=unused-import
import snyk
import snyk.errors

FORMAT = "[%(asctime)s] [pid(%(process)d):%(threadName)s] [%(levelname)s] [%(module)s.%(funcName)s:%(lineno)d] %(message)s"

LEVEL = "INFO"
if os.getenv("DEBUG"):
    LEVEL = "DEBUG"

logging_config = {
    "version": 1,
    "formatters": {
        "default": {
            "()": "coloredlogs.ColoredFormatter",
            "format": FORMAT,
        },
        "file": {
            "format": FORMAT,
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "default",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "snyk-bulk-delete.log",
            "mode": "a",
            "formatter": "file",
        },
    },
    "root": {"level": LEVEL, "handlers": ["console", "file"]},
}

dictConfig(logging_config)
logger = logging.getLogger(__name__)

helpString = """
This script will allow you to deactivate or delete projects in bulk based on a set of filters.
set your SNYK_TOKEN as an environment variable to use this script.

Usage: SNYK_TOKEN=your_token python snyk-bulk-delete.py [options]

--help: Returns this page

--force: By default this script will perform a dry run, add this flag to actually apply changes

--delete: By default this script will deactivate projects, add this flag to delete active projects instead

--delete-non-active-projects: By default this script will deactivate projects, add this flag to delete non-active projects instead
(if this flag is present only non-active projects will be deleted)

--origins: Defines origin of projects to delete (github, github-enterprise, github-cloud-app...)

--orgs: A set of orgs upon which to perform delete, be sure to use org slug instead of org display name (use ! for all orgs)

--sca-types: Defines types of projects to delete (deb, linux, dockerfile, rpm, apk, npm, sast ...)

--products: Defines which Snyk feature related projects to delete
             examples: sast container iac opensource

--product_excludes: Defines product/s types of projects to exclude from deletion

--delete-empty-orgs: This will delete all orgs that do not have any projects in them
    * Please replace spaces with dashes(-) when entering orgs
    * If entering multiple values use the following format: "value-1 value-2 value-3"

--after: Only delete projects that were created after a certain date time (in ISO 8601 format, i.e 2023-09-01T00:00:00.000Z)

--before : Only delete projects that were created before  a certain date time (in ISO 8601 format, i.e 2023-09-01T00:00:00.000Z)

--ignore-keys: An array of key's, if any of these key's are present in a project name then that project will not be targeted for deletion/deactivation
"""


if "--help" in sys.argv:
    print(helpString)
    sys.exit(2)


# get all user orgs and verify snyk API token
snyk_token = os.getenv("SNYK_TOKEN", "")
if not snyk_token:
    logger.error("💥 Please set your SNYK_TOKEN as an environment variable")
    print(helpString)
    sys.exit(1)


try:
    client = snyk.SnykClient(token=snyk_token)
    userOrgs = client.organizations.all() or []
    logger.info("Found organizations: %s", len(userOrgs))
except snyk.errors.SnykHTTPError as err:
    logger.error(
        "💥 Ran into an error while fetching account details, please check your API token: %s",
        vars(err),
    )
    print(helpString)
    sys.exit(1)


def is_date_between(curr_date_str, before_date_str, after_date_str):
    # Parse the current date string into a datetime object
    curr_date = datetime.strptime(curr_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    # Parse the before date string into a datetime object if it's not empty
    if before_date_str:
        before_date = datetime.strptime(before_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        before_date = None

    # Parse the after date string into a datetime object if it's not empty
    if after_date_str:
        after_date = datetime.strptime(after_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        after_date = None

    # Check if the current date is between the before and after dates
    if before_date and after_date:
        return (
            curr_date <= before_date  # pylint: disable=chained-comparison
            and curr_date >= after_date
        )
    if before_date:
        return curr_date <= before_date
    if after_date:
        return curr_date >= after_date

    # If both before and after dates are empty, return True
    return True


def convertProjectTypeToProduct(inputType: str) -> str:
    containerTypes = ["deb", "linux", "dockerfile", "rpm", "apk"]
    iacTypes = [
        "k8sconfig",
        "helmconfig",
        "terraformconfig",
        "armconfig",
        "cloudformationconfig",
    ]
    codeTypes = ["sast"]
    open_source_types = [
        "cocoapods",
        "composer",
        "cpp",
        "golangdep",
        "gomodules",
        "govendor",
        "gradle",
        "hex",
        "maven",
        "npm",
        "nuget",
        "paket",
        "pip",
        "pipenv",
        "poetry",
        "rubygems",
        "sbt",
        "swift",
        "yarn",
    ]

    if inputType in containerTypes:
        return "container"
    if inputType in iacTypes:
        return "iac"
    if inputType in codeTypes:
        return "sast"
    if inputType in open_source_types:
        return "opensource"

    logger.warning("Unknown project type: %s", inputType)
    return "unknown"


def main(argv):  # pylint: disable=too-many-statements
    inputOrgs = []
    products = []
    scaTypes = []
    origins = []
    product_excludes = []
    deleteorgs = False
    dryrun = True
    deactivate = True
    deleteNonActive = False
    beforeDate = ""
    afterDate = ""
    ignoreKeys = []

    # valid input arguments declared here
    try:
        opts, _ = getopt.getopt(
            argv,
            "hofd",
            [
                "help",
                "orgs=",
                "sca-types=",
                "products=",
                "product_excludes=",
                "origins=",
                "ignore-keys=",
                "before=",
                "after=",
                "force",
                "delete-empty-orgs",
                "delete",
                "delete-non-active-projects",
            ],
        )
    except getopt.GetoptError:
        logger.error("Error parsing input, please check your syntax: %s", argv)
        sys.exit(2)

    # process input
    logger.debug(opts)
    for opt, arg in opts:
        if opt == "--help":
            print(helpString)
            sys.exit(2)
        if opt == "--orgs":
            if arg == "!":
                inputOrgs = [org.slug for org in userOrgs]
            else:
                inputOrgs = arg.split()
        if opt == "--sca-types":
            scaTypes = [scaType.lower() for scaType in arg.split()]
        if opt == "--products":
            products = [product.lower() for product in arg.split()]
        if opt == "--product_excludes":
            product_excludes = [product.lower() for product in arg.split()]
        if opt == "--origins":
            origins = [origin.lower() for origin in arg.split()]
        if opt == "--delete-empty-orgs":
            deleteorgs = True
        if opt == "--force":
            dryrun = False
        if opt == "--delete":
            deactivate = False
        if opt == "--delete-non-active-projects":
            deactivate = False
            deleteNonActive = True
        if opt == "--before":
            beforeDate = arg
        if opt == "--after":
            afterDate = arg
        if opt == "--ignore-keys":
            ignoreKeys = [key.lower() for key in arg.split()]

    # error handling if no filters declared
    logger.debug(
        "Filters: sca-types: %s, products: %s, origins: %s, product_excludes: %s",
        scaTypes,
        products,
        origins,
        product_excludes,
    )

    filtersEmpty = (
        len(scaTypes) == 0
        and len(products) == 0
        and len(product_excludes) == 0
        and len(origins) == 0
    )
    if filtersEmpty and not deleteorgs:
        logger.debug("Empty params %s:", filtersEmpty)
        logger.error(
            "No settings entered, define one of: sca-types, products, product_excludes, origins"
        )
        print(helpString)
        sys.exit(2)

    # error handling if no orgs declared
    if len(inputOrgs) == 0:
        logger.error("No --orgs to process entered, exiting")
        print(helpString)

    # print dryrun message
    if dryrun:
        logger.info(
            "THIS IS A DRY RUN, NOTHING WILL BE DELETED! USE --FORCE TO APPLY ACTIONS"
        )
    if not dryrun:
        logger.error("FORCE FLAG DETECTED, ACTIONS WILL BE APPLIED")

    results = {
        "projects": {"deactivated": [], "deleted": [], "failed": [], "skipped": []},
        "orgs": {"deleted": [], "failed": []},
    }
    # delete functionality
    for currOrg in userOrgs:  # pylint: disable=too-many-nested-blocks

        # if curr org is in list of orgs to process
        if currOrg.slug not in inputOrgs:
            logger.debug("Skipping organization: %s not in %s", currOrg.slug, inputOrgs)
            continue

        logger.info("Collecting projects for organization: %s", currOrg.url)
        org_projects = currOrg.projects.all()
        logger.info("%s has %s projects", currOrg.url, len(org_projects))

        # cycle through all projects in current org and delete projects that match filter
        for count, currProject in enumerate(org_projects):
            logger.debug("[%s/%s] - %s", count + 1, len(org_projects), currOrg.url)

            # variables which determine whether project matches criteria to delete, if criteria is empty they will be defined as true
            scaTypeMatch = False
            originMatch = False
            productMatch = False
            dateMatch = False
            nameMatch = True
            isActive = currProject.isMonitored

            # dateMatch validation
            try:
                dateMatch = is_date_between(currProject.created, beforeDate, afterDate)
            except ValueError as exc:
                logger.error(
                    "Error processing before/after datetimes, please check your format %s",
                    exc,
                )
                sys.exit(2)

            # nameMatch validation
            for key in ignoreKeys:
                if key in currProject.name:
                    nameMatch = False

            # if scatypes are not declared or curr project type matches filter criteria then return true
            if len(scaTypes) != 0:
                if currProject.type in scaTypes:
                    scaTypeMatch = True
            else:
                scaTypeMatch = True

            # if origintypes are not declared or curr project origin matches filter criteria then return true
            if len(origins) != 0:
                if currProject.origin in origins:
                    originMatch = True
            else:
                originMatch = True

            # if producttypes are not declared or curr project product matches filter criteria then return true
            currProjectProductType = convertProjectTypeToProduct(currProject.type)

            if (currProjectProductType in products) or (
                currProjectProductType not in product_excludes
            ):
                productMatch = True

            # Guard clause to avoid complex conditions below
            if not (
                scaTypeMatch
                and originMatch
                and productMatch
                and dateMatch
                and nameMatch
                and not filtersEmpty
            ):
                logger.debug(
                    "Skipping unmatched project: %s, Type: %s, Origin: %s, Product: %s",
                    currProject.name,
                    currProject.type,
                    currProject.origin,
                    currProjectProductType,
                )
                results["projects"]["skipped"].append(currProject)
                continue

            remoteurl = currProject.remoteRepoUrl
            if not remoteurl or remoteurl is None:
                remoteurl = currProject.branch
            if not remoteurl or remoteurl is None:
                remoteurl = currProject.name

            currProjectDetails = f"Org: {currProject.organization.url}, URL: {remoteurl}, Name: {currProject.name} Origin: {currProject.origin}, Type: {currProject.type}, Feature: {currProjectProductType}"
            # delete active project if filters are met
            if isActive and not deleteNonActive:
                action = "Deactivating" if deactivate else "Deleting"
                logger.warning("%s project: %s", action, currProjectDetails)
                try:
                    if not deactivate:
                        if not dryrun:
                            currProject.delete()
                        results["projects"]["deleted"].append(currProject)
                    else:
                        if not dryrun:
                            currProject.deactivate()
                        results["projects"]["deactivated"].append(currProject)
                except Exception as e:
                    logger.error(
                        "Error %s project: %s -> %s", action, currProjectDetails, e
                    )
                    results["projects"]["failed"].append(currProject)

            # delete non-active project if filters are met
            if not isActive and deleteNonActive:
                logger.warning("Deleting inactive project: %s", currProjectDetails)
                try:
                    if not dryrun:
                        currProject.delete()
                        results["projects"]["deleted"].append(currProject)
                except Exception as e:
                    logger.error(
                        "Error deleting project: %s -> %s", currProjectDetails, e
                    )
                    results["projects"]["failed"].append(currProject)

        # if org is empty and --delete-empty-org flag is on
        if deleteorgs:
            logger.info("Delete empty org flag set, checking if empty: %s", currOrg.url)
            if not len(currOrg.projects.all()) == 0:
                logger.info("%s not empty, continuing...", currOrg.url)
                continue

            logger.warning("Deleting empty organization: %s", currOrg.url)
            try:
                if not dryrun:
                    client.delete(f"org/{currOrg.id}")
                results["orgs"]["deleted"].append(currOrg)
            except Exception as e:
                logger.error("Error processing organization: %s", e, exc_info=True)
                results["orgs"]["failed"].append(currOrg)

    for i_type in results:  # pylint: disable=consider-using-dict-items
        for action in results[i_type]:
            logger.info(
                "%s - %s: %s",
                i_type.capitalize(),
                action.capitalize(),
                len(results[i_type][action]),
            )

    if dryrun:
        logger.info("DRY RUN COMPLETE NOTHING DELETED")
    else:
        logger.error("ACTIONS APPLIED, PLEASE CHECK LOGS FOR ERRORS")


main(sys.argv[1:])
