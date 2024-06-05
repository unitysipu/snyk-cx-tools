import getopt
import logging
from logging.config import dictConfig
import os
import sys
from datetime import datetime

import coloredlogs  # pylint: disable=unused-import
import snyk
import snyk.errors

FORMAT = "[%(asctime)s] [%(levelname)s] [pid(%(process)d):%(threadName)s] [%(module)s.%(funcName)s:%(lineno)d] %(message)s"

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

# Delete flags

--delete: By default this script will deactivate projects, add this flag to delete active projects instead
--delete-inactive-projects: Add this flag to delete any found inactive projects
    * if this flag is present only inactive projects will be deleted
--delete-empty-orgs: This will delete all orgs that do not have any projects in them
    * Please replace spaces with dashes(-) when entering orgs
    * If entering multiple values use the following format: "value-1 value-2 value-3"

# Time filters:

--after: Only delete projects that were created after a certain date time (in ISO 8601 format, i.e 2023-09-01T00:00:00.000Z)
--before : Only delete projects that were created before  a certain date time (in ISO 8601 format, i.e 2023-09-01T00:00:00.000Z)

# Arrays of filters, repeat following argument for many: (i.e --orgs=org1 --orgs=org2)

--origins: Defines origin of projects to delete (github, github-enterprise, github-cloud-app...)
--orgs: Organization upon which to perform action, be sure to use org slug instead of org display name (use ! for all orgs)
--org-excludes: org to exclude from processing (and deletion)
--sca-types: Defines types of projects to delete
    * examples: deb, linux, dockerfile, rpm, apk, npm, sast
--products: Defines which Snyk feature related projects to delete
    * examples: sast container iac opensource

--product_excludes: Defines feature types of projects to exclude from deletion

--name-excludes: An array of names, if any of these names are present in a project name then that project will not be targeted for deletion/deactivation
"""


if "--help" in sys.argv:
    print(helpString)
    sys.exit(2)


# get all user orgs and verify snyk API token
snyk_token = os.getenv("SNYK_TOKEN", "")
if not snyk_token:
    logger.error("Please set your SNYK_TOKEN as an environment variable")
    print(helpString)
    sys.exit(1)


try:
    client = snyk.SnykClient(token=snyk_token)
    userOrgs = client.organizations.all() or []
    logger.info("Found organizations: %s", len(userOrgs))
except snyk.errors.SnykHTTPError as err:
    logger.error(
        "Ran into an error while fetching account details, please check your API token: %s",
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


def is_project_skipped(filters, project):
    project_type = convertProjectTypeToProduct(project.type)
    if project.readOnly:
        logger.info(
            "Skipping read-only (public) project: %s, Type: %s, Origin: %s, Product: %s",
            project.name,
            project.type,
            project.origin,
            project_type,
        )
        return True

    if project_type == "unknown":
        logger.error(
            "Not processing unknown project type: %s, Type: %s, Origin: %s, Product: %s",
            project.name,
            project.type,
            project.origin,
            project_type,
        )
        return True

    # nameMatch validation
    if project.name in filters["name-excludes"]:
        return True

    # if scatypes are not declared or curr project type matches filter criteria then return true
    if filters["sca-types"] and project.type not in filters["sca-types"]:
        return True

    # if origintypes are not declared or curr project origin matches filter criteria then return true
    if filters["origins"] and project.origin not in filters["origins"]:
        return True

    # skip excluded products
    if filters["product-excludes"] and project_type in filters["product-excludes"]:
        return True

    # skip products not in filter
    if filters["products"] and project_type not in filters["products"]:
        return True

    return False


def is_org_filtered(org, filters):
    if org.slug in filters["org-excludes"]:
        logger.warning(
            "Organization skipped, %s in excludes %s",
            org.slug,
            filters["orgs"],
        )
        return True
    if org.slug not in filters["orgs"]:
        logger.debug(
            "Organization skipped, %s not in %s",
            org.slug,
            filters["orgs"],
        )
        return True
    return False


def main(argv):  # pylint: disable=too-many-statements
    filters = {
        "name-excludes": set(),
        "org-excludes": set(),
        "orgs": set(),
        "origins": set(),
        "product-excludes": set(),
        "products": set(),
        "sca-types": set(),
    }
    deleteorgs = False
    dryrun = True
    deactivate = True
    deleteinActive = False
    before_date = ""
    after_date = ""

    # valid input arguments declared here
    try:
        opts, _ = getopt.getopt(
            argv,
            "hofd",
            [
                "after-date=",
                "before-date=",
                "delete",
                "delete-empty-orgs",
                "delete-inactive-projects",
                "force",
                "help",
                "name-excludes=",
                "org-excludes=",
                "orgs=",
                "origins=",
                "product-excludes=",
                "products=",
                "sca-types=",
            ],
        )
    except getopt.GetoptError:
        logger.error("Error parsing input, please check your syntax: %s", argv)
        sys.exit(2)

    # process input
    logger.debug("Passed options: %s", opts)
    for opt, arg in opts:
        if opt == "--help":
            print(helpString)
            sys.exit(2)
        if opt in "--orgs":
            if arg == "!":
                filters["orgs"] = set(org.slug for org in userOrgs)
            else:
                filters["orgs"].add(arg.lower())
        if opt in "--org-excludes":
            filters["org-excludes"].add(arg.lower())
        if opt in "--sca-types":
            filters["sca-types"].add(arg.lower())
        if opt in "--products":
            filters["products"].add(arg.lower())
        if opt in "--product-excludes":
            filters["product-excludes"].add(arg.lower())
        if opt in "--origins":
            filters["origins"].add(arg.lower())
        if opt in "--name-excludes":
            filters["name-excludes"].add(arg.lower())
        if opt == "--delete-empty-orgs":
            deleteorgs = True
        if opt == "--force":
            dryrun = False
        if opt == "--delete":
            deactivate = False
        if opt == "--delete-inactive-projects":
            deactivate = False
            deleteinActive = True
        if opt == "--before":
            before_date = arg
        if opt == "--after":
            after_date = arg

    logger.debug("Filters: %s", filters)

    if all(len(value) == 0 for value in filters.values()) and not deleteorgs:
        logger.error(
            "No filters defined entered, define one of: %s", list(filters.keys())
        )
        print(helpString)
        sys.exit(2)

    # error handling if no orgs declared
    if not filters["orgs"]:
        logger.error(
            "No --orgs to process entered, use '!' for all, or define slugs..."
        )
        print(helpString)

    # print dryrun message
    if dryrun:
        logger.info(
            "THIS IS A DRY RUN, NOTHING WILL BE DELETED! USE --FORCE TO APPLY ACTIONS"
        )
    if not dryrun:
        logger.info("FORCE FLAG DETECTED, ACTIONS WILL BE APPLIED")

    results = {
        "projects": {"deactivated": [], "deleted": [], "failed": [], "skipped": []},
        "orgs": {"deleted": [], "failed": []},
    }
    try:  # pylint: disable=too-many-nested-blocks
        for o_count, currOrg in enumerate(userOrgs):

            # if curr org is in list of orgs to process
            if is_org_filtered(currOrg, filters):
                continue

            logger.info(
                "[%s/%s] Processing projects for organization: %s",
                o_count + 1,
                len(userOrgs),
                currOrg.url,
            )
            org_projects = currOrg.projects.all()
            logger.info("%s has %s projects", currOrg.url, len(org_projects))

            # cycle through all projects in current org and delete projects that match filter
            for count, currProject in enumerate(org_projects):
                logger.debug(
                    "Org: [%s/%s] - Project: [%s/%s] - %s",
                    o_count + 1,
                    len(userOrgs),
                    count + 1,
                    len(org_projects),
                    currOrg.url,
                )

                remoteurl = currProject.remoteRepoUrl
                if not remoteurl or remoteurl is None:
                    remoteurl = currProject.branch
                if not remoteurl or remoteurl is None:
                    remoteurl = currProject.name

                currProjectProductType = convertProjectTypeToProduct(currProject.type)
                currProjectDetails = {
                    "feature": currProjectProductType,
                    "name": currProject.name,
                    "org": currProject.organization.url,
                    "origin": currProject.origin,
                    "type": currProject.type,
                    "url": remoteurl,
                }

                # dateMatch validation
                try:
                    if not is_date_between(
                        currProject.created,
                        before_date,
                        after_date,
                    ):
                        continue
                except ValueError as exc:
                    logger.error(
                        "Error processing before/after datetimes, please check your format %s",
                        exc,
                    )
                    sys.exit(2)

                if is_project_skipped(filters, currProject):
                    logger.debug("Skipping unmatched project: %s", currProjectDetails)
                    results["projects"]["skipped"].append(currProject)
                    continue

                # delete active project if filters are met
                if currProject.isMonitored and not deleteinActive:
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

                # delete inactive project if filters are met
                if not currProject.isMonitored:
                    logger.debug("Inactive project: %s", currProjectDetails)
                    if deleteinActive:
                        logger.warning(
                            "Deleting inactive project: %s", currProjectDetails
                        )
                        try:
                            if not dryrun:
                                currProject.delete()
                            results["projects"]["deleted"].append(currProject)
                        except Exception as e:
                            logger.error(
                                "Error deleting project: %s -> %s",
                                currProjectDetails,
                                e,
                            )
                            results["projects"]["failed"].append(currProject)

            # if org is empty and --delete-empty-org flag is on
            if deleteorgs:
                logger.info(
                    "Delete empty org flag set, checking if empty: %s", currOrg.url
                )
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

    except KeyboardInterrupt:
        logger.error("User interrupted, aborting")

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
        logger.info("ACTIONS APPLIED, PLEASE CHECK LOGS FOR ERRORS")


main(sys.argv[1:])
