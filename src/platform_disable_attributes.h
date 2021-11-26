#ifndef PLATFORM_DISABLE_ATTRIBUTES_H
#define PLATFORM_DISABLE_ATTRIBUTES_H

/* Disable GNU-style attributes for functions, variables, types and label
   (https://gcc.gnu.org/onlinedocs/gcc/Function-Attributes.html ), turning them
   into noops.  This lets the code compile with compilers not supporting
   attributes, while keeping them enabled where they matter.

   This header is included by platform-specific code where needed: it is not
   for the user to directly see. */

/* Notice that this definition is extremely conservative: supporting exactly
   one argument would suffice. */
#define __attribute__(...) /* nothing */
#define attribute __attribute__


#endif // #ifndef PLATFORM_DISABLE_ATTRIBUTES_H
