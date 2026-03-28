#include "stdafx.h"

#include "Engine/Core/Core.h"
#include "Engine/Core/ObjectsManager.h"
#include "Engine/Generation/MDK.h"
#include "Engine/Generation/SDK.h"
#include "Engine/Userdefined/FeatureFlags.h"
#include "Frontend/Windows/LogWindow.h"
#include "Memory/Memory.h"
#include "Settings/EngineSettings.h"

namespace
{
	struct Options
	{
		std::string processName;
		int pid = 0;
		std::string projectName = "Dump";
		int sdkFlags = FeatureFlags::SDK::STABLE;
		bool generateSdk = true;
		bool generateMdk = false;
		bool generateFNames = true;
		bool saveProject = false;
	};

	void printUsage(const char* argv0)
	{
		std::cout
			<< "Usage: " << argv0 << " [options]\n"
			<< "  --process <name>         Target process name (e.g. SevenDeadlySins_Origin-Win64-Shipping.exe)\n"
			<< "  --pid <pid>              Target process PID\n"
			<< "  --project <name>         Output directory name under the current working directory\n"
			<< "  --sdk <stable|experimental|off>\n"
			<< "  --mdk                    Generate MDK in addition to SDK\n"
			<< "  --no-fnames              Skip FNames.txt generation\n"
			<< "  --save-project           Save a .uedproj snapshot\n"
			<< "  --help                   Show this help\n";
	}

	bool parseArgs(int argc, char** argv, Options& options)
	{
		for (int i = 1; i < argc; ++i)
		{
			const std::string arg = argv[i];

			auto takeValue = [&](const char* opt) -> const char*
			{
				if (i + 1 >= argc)
				{
					std::cerr << "Missing value for " << opt << "\n";
					return nullptr;
				}
				return argv[++i];
			};

			if (arg == "--help")
			{
				printUsage(argv[0]);
				return false;
			}
			if (arg == "--process")
			{
				if (const char* value = takeValue("--process"))
					options.processName = value;
				else
					return false;
				continue;
			}
			if (arg == "--pid")
			{
				if (const char* value = takeValue("--pid"))
					options.pid = std::atoi(value);
				else
					return false;
				continue;
			}
			if (arg == "--project")
			{
				if (const char* value = takeValue("--project"))
					options.projectName = value;
				else
					return false;
				continue;
			}
			if (arg == "--sdk")
			{
				const char* value = takeValue("--sdk");
				if (!value)
					return false;

				const std::string mode = value;
				if (mode == "stable")
				{
					options.generateSdk = true;
					options.sdkFlags = FeatureFlags::SDK::STABLE;
				}
				else if (mode == "experimental")
				{
					options.generateSdk = true;
					options.sdkFlags = FeatureFlags::SDK::EXPERIMENTAL_INTERNAL;
				}
				else if (mode == "off")
				{
					options.generateSdk = false;
				}
				else
				{
					std::cerr << "Unknown SDK mode: " << mode << "\n";
					return false;
				}
				continue;
			}
			if (arg == "--mdk")
			{
				options.generateMdk = true;
				continue;
			}
			if (arg == "--no-fnames")
			{
				options.generateFNames = false;
				continue;
			}
			if (arg == "--save-project")
			{
				options.saveProject = true;
				continue;
			}

			std::cerr << "Unknown option: " << arg << "\n";
			return false;
		}

		if (options.pid <= 0 && options.processName.empty())
		{
			std::cerr << "Either --process or --pid is required.\n";
			return false;
		}

		return true;
	}

	bool runDumpPipeline()
	{
		EngineCore();
		if (!EngineCore::initSuccess())
		{
			windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_ERROR, "HEADLESS", "EngineCore initialization failed");
			return false;
		}

		ObjectsManager();
		if (ObjectsManager::CRITICAL_STOP_CALLED())
		{
			windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_ERROR, "HEADLESS", "ObjectsManager initialization failed: %s", ObjectsManager::getErrorMessage().c_str());
			return false;
		}

		int64_t finished = 0;
		int64_t total = 0;
		CopyStatus status = CS_idle;

		ObjectsManager::copyGObjectPtrs(finished, total, status);
		if (status != CS_success || ObjectsManager::CRITICAL_STOP_CALLED())
		{
			windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_ERROR, "HEADLESS", "copyGObjectPtrs failed: %s", ObjectsManager::getErrorMessage().c_str());
			return false;
		}

		ObjectsManager::copyUBigObjects(finished, total, status);
		if (status != CS_success || ObjectsManager::CRITICAL_STOP_CALLED())
		{
			windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_ERROR, "HEADLESS", "copyUBigObjects failed: %s", ObjectsManager::getErrorMessage().c_str());
			return false;
		}

		EngineCore::cacheFNames(finished, total, status);
		if (status != CS_success || ObjectsManager::CRITICAL_STOP_CALLED())
		{
			windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_ERROR, "HEADLESS", "cacheFNames failed: %s", windows::LogWindow::getLastLogMessage().c_str());
			return false;
		}

		EngineCore::generatePackages(finished, total, status);
		if (status != CS_success || ObjectsManager::CRITICAL_STOP_CALLED())
		{
			windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_ERROR, "HEADLESS", "generatePackages failed: %s", windows::LogWindow::getLastLogMessage().c_str());
			return false;
		}

		ObjectsManager::setSDKGenerationDone();
		EngineSettings::setLiveEditor(true);
		return true;
	}
}

int main(int argc, char** argv)
{
	Options options;
	if (!parseArgs(argc, argv, options))
	{
		const bool helpRequested = argc == 2 && std::string(argv[1]) == "--help";
		if (argc <= 1)
			printUsage(argv[0]);
		return (argc <= 1 || helpRequested) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	windows::LogWindow::setLogLevel(static_cast<int>(windows::LogWindow::logLevels::LOGLEVEL_ALL));
	EngineSettings::loadMacros();

	if (!EngineSettings::setProjectName(options.projectName))
	{
		windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_ERROR, "HEADLESS", "Failed to create project directory %s", options.projectName.c_str());
		return EXIT_FAILURE;
	}

	EngineSettings::setTargetApplicationName(options.processName.empty() ? std::to_string(options.pid) : options.processName);

	Memory();
	const auto loadResult = options.pid > 0 ? Memory::load(options.pid) : Memory::load(options.processName);
	if (loadResult != Memory::success)
	{
		windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_ERROR, "HEADLESS", "Failed to attach to target process");
		return EXIT_FAILURE;
	}

	if (!runDumpPipeline())
		return EXIT_FAILURE;

	int progressDone = 0;
	int totalProgress = 0;

	if (options.generateFNames)
	{
		if (!EngineCore::generateFNameFile(progressDone, totalProgress))
		{
			windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_WARNING, "HEADLESS", "FNames generation reported failure");
		}
	}

	if (options.generateSdk)
	{
		SDKGeneration::Generate(progressDone, totalProgress, options.sdkFlags);
	}

	if (options.generateMdk)
	{
		MDKGeneration::generate(progressDone, totalProgress);
	}

	if (options.saveProject)
	{
		EngineCore::saveToDisk(progressDone, totalProgress);
	}

	EngineCore::generateStructDefinitionsFile();
	windows::LogWindow::Log(windows::LogWindow::logLevels::LOGLEVEL_INFO, "HEADLESS", "Dump completed successfully at %s", EngineSettings::getWorkingDirectory().string().c_str());
	return EXIT_SUCCESS;
}
