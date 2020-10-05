import subprocess
import re
import sys
import argparse

parser = argparse.ArgumentParser(description='Automate the patch release process as sanely as possible.')
parser.add_argument('-r','--rev',nargs=1, help="revision number or changeset to tag as next RC")
group = parser.add_mutually_exclusive_group(required=False)
group.add_argument('-v','--version',nargs=4, type=int, help="force this version - bypasses version inference. Format: major minor patch")
group.add_argument('p', '--patch', type=int, help="force this patch number on the inferred version")
args = parser.parse_args()

# Note: we could get this from the macros, but since folks seem to be actually upgrading 
# the release tag manually correctly and not the macro, let's just check both
cmd = ["hg", "log", "-r", ".", "--template", "\"{latesttag(r're:Release_[0-9]+\.[0-9]+\.[0-9]+-RC[0-9]+')}\""]
result = subprocess.run(cmd, capture_output=True)
release_string = result.stdout.decode("utf-8").replace('"','')
#print(release_string)

changeset = args.rev # can be None :)

major = -1
minor = -1
patch = -1

if args.version:
    major = args.version[0]
    minor = args.version[1]
    patch = args.version[2]
    #print(rc)
    if (major < 0) or (minor < 0) or (patch < 0):
        raise Exception("Version numbers must all be positive values.")
elif args.patch:
    patch = args.patch
    if (patch < 0):
        raise Exception("Patch numbers must all be positive values.")

#define PEP_ENGINE_VERSION_MAJOR 2
#define PEP_ENGINE_VERSION_MINOR 1
#define PEP_ENGINE_VERSION_PATCH 0
#define PEP_ENGINE_VERSION_RC    13

# Amateur hour. Biteme.
cmd = ["grep", "-E", "#define PEP_ENGINE_VERSION_[A-Z]+[ \t]+[0-9]+", "src/pEpEngine.h"]
result = subprocess.run(cmd, capture_output=True)
grep_output = result.stdout.decode("utf-8")
#print(grep_output)

if not args.version:
    src_nums = []
    src_nums = re.findall(r'([0-9]+)', grep_output)
        
    if not src_nums:
        raise Exception("Somehow, the source values for the engine versions were not found in src/pEpEngine.h. Aborting.")
    if len(src_nums) != 4:
        raise Exception("Somehow, we could not extract all version numbers from the header file src/pEpEngine.h. Aborting.")
            
    tag_nums = []
    if release_string.startswith("Release_"):
        tag_nums = re.findall(r'([0-9]+)', release_string)
    #    for num in tagnums:
    #        print (num)

    if not tag_nums or len(tag_nums) < 3:
        if not tag_nums:
            print("Wow... there is no extant release tag. What did you do, wipe the repository?")
        else:
            print("Somehow, there was an error with the numbering of the tag \"" + release_string + "\"")
        print("Do you want to continue? We'll make a tag from the source patch info. (Y/N)[enter]")
        a = input().lower()
        if not (a.startswith("y") or a.startswith("Y")):
            sys.exit()
            
    force = False

    if len(tag_nums) >= 3 and src_nums:
        major_tag = int(tag_nums[0])
        major_src = int(src_nums[0])
        minor_tag = int(tag_nums[1])
        minor_src = int(src_nums[1])
        patch_tag = int(tag_nums[2])
        patch_src = int(src_nums[2])

        print("Inferring current/next version info for automatic upgrade:")
        print("Tagged (should show current):                    " + str(major_tag) + "." + str(minor_tag) + "." + str(patch_tag)
        print("Source (should show *next* (i.e. this upgrade)): " + str(major_src) + "." + str(minor_src) + "." + str(patch_src)            
            
        if (major_tag == major_src):
            major = major_tag
            if (minor_tag == minor_src):
                minor = minor_tag


                if (patch_tag == patch_src):
                    patch = patch_tag
                    # Hoorah, we're just changing the RC number.
                    if (rc < 0):
                        if (rc_tag == (rc_src - 1)):
                            # Best case!
                            rc = rc_src
                        elif (rc_tag == rc_src):
                            print("Someone was naughty and didn't bump the RC number in the src, or you made a mistake you want to fix.")
                            print("Current tagged version is " + str(major) + "." + str(minor) + "." + str(patch) + " RC" + rc_tag + ".")
                            print("(I)ncrement,(F)orce same version,(A)bort? [enter]")
                            a = input().lower()
                            a = lower(a)
                            if (a.startswith(i)):
                                rc = rc_tag + 1
                            elif (a.startswith(f)):
                                rc = rc_tag
                                force = True 
                            else:
                                print("Aborting...")
                                sys.exit()
                        else:
                            print("RC numbers are messed up. The last tagged version is " + str(rc_tag) + ", while the last source version is " + str(rc_src) + ".")
                            print("Please enter the RC version you want to use, followed by enter:")
                            a = input().lower()
                            rc = int(a) # Will raise value error if not a number. User deserves it, frankly.
                    
                    #Ok, we now have a value. Good.
                    
        # This feels extremely suboptimal, but I'm tired and don't care            
        if (rc < 0):
            if (major < 0):
                if (major_src == major_tag + 1) and (minor_src == 0) and (patch_src == 0):
                    major = major_src
                    minor = 0
                    patch = 0
                else:
                    print("Tagged release major version and source versions are too different for automatic deduction. Please do this manually.")
                    sys.exit()
            elif (minor < 0):
                if (minor_src == minor_tag + 1) and (patch_src == 0):
                    minor = minor_src
                    patch = 0
                else:
                    print("Tagged release major version and source versions are too different for automatic deduction. Please do this manually.")
                    sys.exit()
            elif (patch_src == patch_tag + 1):
                patch = patch_src
            else:
                print("Tagged release major version and source versions are too different for automatic deduction. Please do this manually.")
                sys.exit()    
            # if we got this far, it was a version upgrade.

            if (rc_src > 0):
                print("We detected a version upgrade, but the source indicates the next RC is RC " + str(rc_src))
                print("(K)eep,(R)eset to 0,(A)bort? [enter]")
                a = input().lower()
                
                if a.startswith("k"):
                    rc = rc_src
                elif a.startswith("r"):
                    rc = 0
                else:
                    print("Aborting...")       
            else:
                rc = 0

# Ok, so now, after all that, we should have the right version numbers.

# If there's no changeset to tag, we take the latest local default
if not changeset:
    cmd = ["hg", "id", "-i", "-r", "default"]
    result = subprocess.run(cmd, capture_output=True)
    changeset = result.stdout.decode("utf-8").replace('"','').replace('\n','')
    if not changeset:
        raise Exception("Unable to determine latest default changeset. Aborting.")

        
rev_tag = "Release_" + str(major) + "." + str(minor) + "." + str(patch) + "-RC" + str(rc)

print("Preparing to tag changeset " + changeset + " with tag " + rev_tag + ".\n\nProceed? (Y/N) [enter]")
a = input().lower()
if not (a.startswith("y")):
    sys.exit()

cmd = ["hg", "tag", "-r", changeset, rev_tag]  
subprocess.run(cmd, check=True, capture_output=False)

if not grep_output:
    print("Information: Not writing version/RC info to src/pEpEngine.h")
    sys.exit()

# If successful, then bump the RC
with open('src/pEpEngine.h', 'r') as file :
  filedata = file.read()

grep_strs = grep_output.split("\n")

cmd = ["grep", "-E", "#define PEP_ENGINE_VERSION[ \t]+\"[0-9]+.[0-9]+.[0-9]+\"", "src/pEpEngine.h"]
result = subprocess.run(cmd, capture_output=True)
grep_output = result.stdout.decode("utf-8")

#define PEP_ENGINE_VERSION "2.1.0"
version_str = str(major) + "." + str(minor) + "." + str(patch)

filedata = filedata.replace(grep_output, "#define PEP_ENGINE_VERSION \"" + version_str + "\"\n")
filedata = filedata.replace(grep_strs[0], "#define PEP_ENGINE_VERSION_MAJOR " + str(major))
filedata = filedata.replace(grep_strs[1], "#define PEP_ENGINE_VERSION_MINOR " + str(minor))
filedata = filedata.replace(grep_strs[2], "#define PEP_ENGINE_VERSION_PATCH " + str(patch))
filedata = filedata.replace(grep_strs[3], "#define PEP_ENGINE_VERSION_RC    0"

# Write the file out again
with open('src/pEpEngine.h', 'w') as file:
    file.write(filedata)     

comment = "Automatically bumped patch in source for future release. Next patch after this one will be " + version_str + "-RC" + str(rc + 1) + " **if released**."
#print("about to run with this comment:")
print(comment) 
cmd = ["hg", "commit", "-m", comment]  
subprocess.run(cmd, capture_output=False)

print("New engine release: " + rev_tag + " Changeset: " + changeset)
                                     
