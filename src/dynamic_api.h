#pragma once

#ifdef WIN32
#ifdef _EXPORT_PEP_ENGINE_DLL
#define DYNAMIC_API __declspec(dllexport)
#else
#define DYNAMIC_API __declspec(dllimport)
#endif
#else
#define DYNAMIC_API
#endif

