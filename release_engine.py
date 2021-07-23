# Requires GitPython: https://gitpython.readthedocs.io/en/stable/intro.html

import subprocess
import re
import sys
import operator
import argparse
import os
from time import sleep

import git.util
from git import Repo, TagReference, Git
from enum import Enum


def replace_src_versions(src_lines, new_major, new_minor, new_patch, new_rc, with_rc, comment, src_repo):
    if not src_lines:
        print("Information: Not writing version/RC info to src/pEpEngine.h")
        sys.exit()

    filedata = None
    # If successful, then bump the RC
    with open('src/pEpEngine.h', 'r') as file:
        filedata = file.read()

    file.close()

    cmd = ["grep", "-E", "#define PEP_ENGINE_VERSION[ \t]+\"[0-9]+.[0-9]+.[0-9]+\"", "src/pEpEngine.h"]
    result = subprocess.run(cmd, capture_output=True)
    grep_output = result.stdout.decode("utf-8")

    major_str = str(new_major)
    minor_str = str(new_minor)
    patch_str = str(new_patch)
    rc_str = str(new_rc)

    # define PEP_ENGINE_VERSION "2.1.0"
    version_str = str(new_major) + "." + str(new_minor) + "." + str(new_patch)

    filedata = filedata.replace(grep_output, "#define PEP_ENGINE_VERSION \"" + version_str + "\"\n")
    filedata = filedata.replace(src_lines[0], "#define PEP_ENGINE_VERSION_MAJOR " + str(new_major))
    filedata = filedata.replace(src_lines[1], "#define PEP_ENGINE_VERSION_MINOR " + str(new_minor))
    filedata = filedata.replace(src_lines[2], "#define PEP_ENGINE_VERSION_PATCH " + str(new_patch))
    filedata = filedata.replace(src_lines[3], "#define PEP_ENGINE_VERSION_RC    " + str(new_rc))

    # Write the file out again
    with open('src/pEpEngine.h', 'w') as file:
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
        exit(42)


class ReleaseType(Enum):
    UNKNOWN = 0
    RC = 1
    PATCH = 2
    MINOR = 3
    MAJOR = 4


# Init some things to be used later
rel_type = ReleaseType.UNKNOWN
repo_path = None
bumped_comment = "Bumped header patch number for NEXT release"

# Parse args
parser = argparse.ArgumentParser(description='Automate the RC release process as sanely as possible.')
parser.add_argument('-r', '--repo', help="Repository root - [default: current working directory]")
parser.add_argument('-a', '--note',
                    help="Tag annotation for release - short description of what this release is [default: none]")
parser.add_argument('-j', '--major', help="Branch off new major release", action='store_true')
parser.add_argument('-n', '--minor', help="Branch off new minor release", action='store_true')
parser.add_argument('-M', '--next_major', help="Only valid for major and minor releases: make next release in "
                                               "master source a major release", action='store_true')

args = parser.parse_args()
annotation = args.note

# Set up repo object
repo_path = args.repo

if not repo_path:
    repo_path = os.getenv('ENGINE_REPO_PATH')

    # API docs say the above is a string, but I'm getting a list from 3.9.6, so just in case...
    if not repo_path:
        repo_path = os.getcwd()

if not repo_path:
    exit(-1)

repo = Repo(repo_path)

if not repo or repo.bare:
    exit(-1)

# DO THE THING!

#
# 1. get current branch
#
branch = repo.active_branch
if not branch:
    exit(-1)

start_branch = branch.name
if not start_branch:
    exit(-1)

branch_release = args.major or args.minor

#
# 2. Figure out what kind of a release we're doing
#

# These are the TARGET numbers
major = 0
minor = 0
patch = 0
rc = 0

if start_branch == 'master':
    if args.major:
        rel_type = ReleaseType.MAJOR
    elif args.minor:
        rel_type = ReleaseType.MINOR
    else:
        rel_type = ReleaseType.RC
else:
    if branch_release:
        print("RELEASE SCRIPT: New major or minor release branching is only supported from the 'master' branch.")
        print("RELEASE SCRIPT: If you have a good reason for what you're doing, do it by hand.")
        exit(-1)
    release_re = re.compile('^Release_([0-9])+[.]([0-9])+')
    release_match = release_re.match(start_branch)
    if not release_match:
        exit(-1)
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

version_re = re.compile('PEP_ENGINE_VERSION_([A-Z]+)[ \t]+([0-9]+)')
for line in grep_lines:
    m = version_re.search(line)
    if not m:
        exit(-1)
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
        exit(-1)

# This is tentative based on tag checks:
if rel_type == ReleaseType.RC:
    major = src_major
    minor = src_minor
    patch = 0       # Should be anyway, but...
    rc = src_rc     # we still have checks to run
elif rel_type == ReleaseType.PATCH:
    patch = src_patch
elif branch_release:
    # Note: This will NOT keep people from doing something stupid with a remote.
    # There's a limited amount of time I want to put into this script to protect
    # people from themselves
    local_branches = repo.branches

    branch_check = 'Release_([0-9]+)[.]([0-9]+)$'
    branch_check_re = re.compile(branch_check)

    branch_matches = []

    branch_matches = [[int(m.group(1)), int(m.group(2))] for branch in local_branches for m in
                      [branch_check_re.match(branch.name)] if m]

    branch_matches = sorted(branch_matches, key=operator.itemgetter(0, 1))
    if not branch_matches:
        exit(-1)
    major_minor_pair = branch_matches[-1]

    manual_required = False;

    # Make sure we don't have an extant release branch! RCs are OK, others are not.
    if rel_type == ReleaseType.MAJOR:
        if major_minor_pair[0] >= src_major or src_minor != 0:
            manual_required = True
    elif rel_type == ReleaseType.MINOR:
        if major_minor_pair[0] > src_major or major_minor_pair[1] >= src_minor:
            manual_required = True
    if manual_required:
        print("RELEASE SCRIPT: The highest release branch version, according to tags, is 'Release_" +
              str(major_minor_pair[0]) + "." + str(major_minor_pair[1]) + "'.")
        print("RELEASE SCRIPT:      It is intended that master always has the next intended branch in the source")
        print("RELEASE SCRIPT:      constants in src/pEpEngine.h for tracking reasons. However, a branch greater or")
        print("RELEASE SCRIPT:      equal to the source release information (Release_" + str(src_major) + "."
              + str(src_minor) + ")")
        print("RELEASE SCRIPT:      has already been released. Aborting - fix this manually in pEpEngine.h first.")
        exit(-1)

    # This should only be 0 for releases (in the src). RC candidates should
    # always have a positive RC val > 1 in master in src awaiting the first RC release.
    major = src_major
    minor = src_minor
    rc = 0
    patch = 0

else:
    exit(-1)

# Unsolicited commentary: I hate that Python doesn't have a switch construct

new_tag = None

#
# 3. If this isn't a new branch, get last release tag for this branch to check we aren't messing things up
#    Then tag and release
#
if not branch_release:
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
        exit(-1)

    tag_re = re.compile(compile_string)
    tag_refs = TagReference.list_items(repo)
    candidates = [int(m.group(1)) for tag in tag_refs for m in [tag_re.search(tag.name)] if m]

    # FIXME

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
            exit(-1)

    new_tag = "Release_" + str(major) + "." + str(minor) + "." + str(patch)

    if rel_type == ReleaseType.RC:
        new_tag += "-RC" + str(rc)

    #
    #  We REALLY want to encourage annotation.
    #  While culturally, we try not to be about blame, this is really for accountability in the release
    #  process, something we have trouble with.
    #
    #  Delete it once I'm gone, if you want. I could make annotating mandatory, but of course sometimes
    #  people need to make quick releases, so I don't want to prevent that.
    #
    notify_addendum = ""
    if not annotation:
        notify_addendum = " (if you don't like this, please run script w/ -a option)"
    print("\nRELEASE SCRIPT: About to tag release " + new_tag + " on branch '" + start_branch + "'.")
    print("RELEASE SCRIPT: This tag will be annotated as follows" + notify_addendum + ":")

    if not annotation:
        g = Git(repo_path)
        username = g.config("user.name")
        if not username:
            username = g.config("user.email")
            if not username:
                username = "Anonymous BadGuy"  # We could go down to the system level, but that's
                                               # a bit much, no?

        annotation = username + " has cowardly failed to provide a release description!"

    print("RELEASE_SCRIPT: ***\t" + annotation)
    bool_prompt("\nRELEASE SCRIPT: Continue? Y/[N]")

    repo.git.tag(new_tag, '-a', '-m', annotation)

    if rel_type == ReleaseType.PATCH:
        patch = patch + 1
    else:
        rc = rc + 1

    replace_src_versions(grep_lines, major, minor, patch, rc, rel_type == ReleaseType.RC, bumped_comment, repo)

#
# 4. Otherwise, if this is a new branch, we need to branch off, write the source, and commit.
#
else:
    if branch_release:
        new_branch_name = "Release_" + str(src_major) + "." + str(src_minor)
        print("\nRELEASE SCRIPT: About to create release branch '" + new_branch_name + "'")
        bool_prompt("\nRELEASE SCRIPT: Continue? Y/[N]")

        repo.git.checkout('-b', new_branch_name)

        tmp_annotate = annotation
        if not tmp_annotate:
            tmp_annotate = '"Initial release for ' + new_branch_name + '"'

        repo.git.commit('--allow-empty', '-m', tmp_annotate)
        repo.git.tag(new_branch_name + ".0", '-a', '-m', tmp_annotate)
        replace_src_versions(grep_lines, major, minor, 1, 0, False, bumped_comment, repo)
        repo.git.checkout(start_branch)
        if args.next_major:
            major = major + 1
            minor = 0
        else:
            minor = minor + 1

        replace_src_versions(grep_lines, major, minor, 0, 1, True, bumped_comment + " (first RC in new cycle)", repo)
        exit(0)

