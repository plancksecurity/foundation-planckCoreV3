/**
 * @file    dynamic_api.h
 * @brief   defines for windows API export
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

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

