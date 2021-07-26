# Requires GitPython: https://gitpython.readthedocs.io/en/stable/intro.html

import subprocess
import re
import sys
import argparse
import os

from git import Repo, TagReference
from enum import Enum


def replace_src_versions(src_lines, new_major, new_minor, new_patch, new_rc, with_rc, comment, src_repo, src_path):
    header_file_path = src_path + "/pEpEngine.h"

    if not src_lines:
        exit("Information: Not writing version/RC info to " + header_file_path)

    filedata = None
    # If successful, then bump the RC
    with open(header_file_path, 'r') as file:
        filedata = file.read()

    file.close()

    cmd = ["grep", "-E", "#define PEP_ENGINE_VERSION[ \t]+\"[0-9]+.[0-9]+.[0-9]+\"", header_file_path]
    result = subprocess.run(cmd, capture_output=True)
    grep_output = result.stdout.decode("utf-8")

    major_str = str(new_major)
    minor_str = str(new_minor)
    patch_str = str(new_patch)
    rc_str = str(new_rc)

    # define PEP_ENGINE_VERSION "2.1.0"
    version_str = str(new_major) + "." + str(new_minor) + "." + str(new_patch)

    filedata = filedata.replace(grep_output, "#define PEP_ENGINE_VERSION \"" + version_str + "\"\n")
    filedata = filedata.replace(src_lines[0], "#define PEP_ENGINE_VERSION_MAJOR " + major_str)
    filedata = filedata.replace(src_lines[1], "#define PEP_ENGINE_VERSION_MINOR " + minor_str)
    filedata = filedata.replace(src_lines[2], "#define PEP_ENGINE_VERSION_PATCH " + patch_str)
    filedata = filedata.replace(src_lines[3], "#define PEP_ENGINE_VERSION_RC    " + rc_str)

    # Write the file out again
    with open(header_file_path, 'w') as file:
        file.write(filedata)
        file.close()

    print("About to run with this comment:")
    print(comment)
    if not comment:
        comment = "Default commit message: rewrote src to contain eventual release info for FUTURE Release_" + \
                  version_str
        if with_rc:
            comment += "-RC" + rc_str
    src_repo.git.commit('-am', comment)

    return version_str


def bool_prompt(prompt):
    reply = str(input(prompt)).lower().strip()
    if reply != "y":
        exit("Aborting at user request.")


class ReleaseType(Enum):
    UNKNOWN = 0
    RC = 1
    PATCH = 2

# Init some things to be used later
rel_type = ReleaseType.UNKNOWN
repo_path = None
bumped_comment = "Bumped header patch number for NEXT release"

# Parse args
parser = argparse.ArgumentParser(description='Automate the RC release process as sanely as possible.')
parser.add_argument('-r', '--repo', help="Repository root - [default: current working directory]")
parser.add_argument('REASON',
                    help="Tag annotation for showing reason for release - short description of what this release is")

args = parser.parse_args()
annotation = args.REASON

# Set up repo object
repo_path = args.repo

if not repo_path:
    repo_path = os.getenv('ENGINE_REPO_PATH')

    # API docs say the above is a string, but I'm getting a list from 3.9.6, so just in case...
    if not repo_path:
        repo_path = os.getcwd()

if not repo_path:
    exit("Can't get repository path.")

repo = Repo(repo_path)

if not repo or repo.bare:
    exit("No extant repository at " + repo_path)

# DO THE THING!

#
# 1. get current branch
#
branch = repo.active_branch
if not branch:
    exit("Can't get current branch.")

start_branch = branch.name
if not start_branch:
    exit("Can't get current branch name.")

#
# 2. Figure out what kind of a release we're doing
#

# These are the TARGET numbers
major = 0
minor = 0
patch = 0
rc = 0

if start_branch == 'master':
    rel_type = ReleaseType.RC
else:
    release_re = re.compile('^Release_([0-9])+[.]([0-9])+')
    release_match = release_re.match(start_branch)
    if not release_match:
        exit("Not in a release branch. Aborting. (Release branches are of the form 'Release_<major>.<minor>')")
    else:
        rel_type = ReleaseType.PATCH
        major = int(release_match.groups()[0])
        minor = int(release_match.groups()[1])

print("\nRELEASE SCRIPT: Preparing for release in branch '" + start_branch + "' in repository at '" + repo_path + "'")

#
# 3. See what the header files have to say about what version we're working with
#
src_major = 0
src_minor = 0
src_patch = 0
src_rc = 0

# Amateur hour. Biteme.
engine_header = repo_path + "/src/pEpEngine.h"
cmd = ["grep", "-E", "#define PEP_ENGINE_VERSION_[A-Z]+[ \t]+[0-9]+", engine_header]
result = subprocess.run(cmd, capture_output=True)
grep_output = result.stdout.decode("utf-8")
grep_lines = grep_output.splitlines();

version_re = re.compile('#define PEP_ENGINE_VERSION_([A-Z]+)[ \t]+([0-9]+)')

for line in grep_lines:
    m = version_re.search(line)
    if not m:
        exit("Can't find matching version information in header file to determine source version info.")
    key = m.group(1)
    value = int(m.group(2))

    if key == "MAJOR":
        src_major = value
    elif key == "MINOR":
        src_minor = value
    elif key == "PATCH":
        src_patch = value
    elif key == "RC":
        src_rc = value
    else:
        exit("Additional information has been added matching '#define PEP_ENGINE_VERSION_.*' - please fix this script.")

# This is tentative based on tag checks:
if rel_type == ReleaseType.RC:
    major = src_major
    minor = src_minor
    patch = 0       # Should be anyway, but...
    rc = src_rc     # we still have checks to run
elif rel_type == ReleaseType.PATCH:
    patch = src_patch
else:
    exit("Internal script error. Probably bad cleanup.")

# Unsolicited commentary: I hate that Python doesn't have a switch construct

new_tag = None

#
# 3. Get last release tag for this branch to check we aren't messing things up
#    Then tag and release
#
tag_maj = 0
tag_min = 0
tag_patch = 0
tag_rc = 0

compile_string = ''
if rel_type == ReleaseType.RC:
    major = src_major
    minor = src_minor
    patch = 0  # Should be anyway, but...

    compile_string = '^Release_' + str(src_major) + '[.]' + str(src_minor) + '[.]0-RC([0-9])+'
elif rel_type == ReleaseType.PATCH:
    compile_string = '^Release_' + str(major) + '[.]' + str(minor) + '[.]([0-9]+)$'
else:
    exit("Internal script error. Probably bad cleanup.")

tag_re = re.compile(compile_string)
tag_refs = TagReference.list_items(repo)
candidates = [int(m.group(1)) for tag in tag_refs for m in [tag_re.search(tag.name)] if m]

if candidates:
    candidates.sort(reverse=True)

    src_val = 0
    tag_val = candidates[0]

    if rel_type == ReleaseType.RC:
        src_val = src_rc
    elif rel_type == ReleaseType.PATCH:
        src_val = src_patch

    if src_val <= tag_val:
        # Somebody done messed up. Sorry, folks, we're not tagging today. (Do better here)
        exit("Mismatch between tag values and values in the source. Please release manually.")

new_tag = "Release_" + str(major) + "." + str(minor) + "." + str(patch)

if rel_type == ReleaseType.RC:
    new_tag += "-RC" + str(rc)

print("\nRELEASE SCRIPT: About to tag release " + new_tag + " on branch '" + start_branch + "'.")
print("RELEASE SCRIPT: This tag will be annotated as follows:")

print("RELEASE_SCRIPT:\nRELEASE_SCRIPT: \"" + annotation + "\"")
bool_prompt("RELEASE_SCRIPT:\nRELEASE SCRIPT: Continue? Y/[N]")

repo.git.tag(new_tag, '-a', '-m', annotation)

if rel_type == ReleaseType.PATCH:
    patch = patch + 1
else:
    rc = rc + 1

replace_src_versions(grep_lines, major, minor, patch, rc, rel_type == ReleaseType.RC, bumped_comment, repo,
                     repo_path + "/src")
