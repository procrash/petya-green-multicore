#pragma once

#include "boost/program_options.hpp"

#include <string>
namespace rad
{
	class CustomOptionDescription {
	public:
		CustomOptionDescription(boost::shared_ptr<boost::program_options::option_description> option);

		void checkIfPositional(const boost::program_options::positional_options_description& positionalDesc);

		std::string getOptionUsageString();

	public:
		std::string optionID;
		std::string optionDisplayName;
		std::string optionDescription;
		std::string optionFormatName;

		bool required;
		bool hasShort;
		bool hasArgument;
		bool isPositional;
	};
}
