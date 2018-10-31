# this file is in the Public Domain

# Typical pure MacPorts environment

# Restrict to MacPorts
export PATH=/opt/local/bin:/opt/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/X11/bin

# Make sure the Apple python (which will be triggered by the makefile)
# has access to the Python libs installed for MacPorts
export PYTHONPATH=/opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/
