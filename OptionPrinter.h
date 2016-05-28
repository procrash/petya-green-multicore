#pragma once

#include "CustomOptionDescription.h"
namespace rad
{
	class OptionPrinter {
	public:
		void addOption(const CustomOptionDescription& optionDesc);

		std::string usage();

		std::string positionalOptionDetails();
		std::string optionDetails();

	public:
		static void printStandardAppDesc(const std::string& appName, std::ostream& out,
										 boost::program_options::options_description desc,
										 boost::program_options::positional_options_description* positionalDesc=0);
		static void formatRequiredOptionError(boost::program_options::required_option& error);

	private:
		std::vector<CustomOptionDescription> options;
		std::vector<CustomOptionDescription> positionalOptions;

	};
}
