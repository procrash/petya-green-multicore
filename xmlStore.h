#pragma once

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

struct petya_decryptor_settings
{
    std::string m_file;              // filename which contains encrypted harddisk sectors
    
    uint64_t start_keyNr;              // start key that was used
    uint64_t resume_keyNr;              // resume key nr
    uint64_t nrOfKeysToCalculate;    // nr of keys that shall be calculated by the job

    uint64_t gpu_blocks;             // nr of GPU blocks used for calculation
    uint64_t gpu_threads;            // nr of GPU threads used for calculation
	uint64_t gpu_keysCtxSwitch;      // nr of keys calculated on GPU before context is switched back to host

	uint64_t cpu_threads;            // nr of CPU threads used for calculation
    
	uint64_t calculatedKeyBlockSize = -1; // key Blocksize which shall be calculated by each single instance (CPU Thread or GPU Thread)
	    	    
    void load(const std::string &filename);
    void save(const std::string &filename);
};


// Loads debug_settings structure from the specified XML file
void petya_decryptor_settings::load(const std::string &filename)
{
    using boost::property_tree::ptree;
    ptree pt;

    read_xml(filename, pt);
    
    m_file = pt.get<std::string>("encryptedDiskSectorFilename");
    start_keyNr = pt.get<uint64_t>("startKeyNumber");
    resume_keyNr = pt.get<uint64_t>("resumeKeyNumber");    
    nrOfKeysToCalculate = pt.get<uint64_t>("nrOfKeysToCalculate");

    gpu_blocks = pt.get<uint64_t>("gpu_blocks");
    gpu_threads = pt.get<uint64_t>("gpu_threads");
	gpu_keysCtxSwitch = pt.get<uint64_t>("gpu_keysCtxSwitch");

	cpu_threads = pt.get<uint64_t>("cpu_threads");
    
	calculatedKeyBlockSize = pt.get<uint64_t>("calculatedKeyBlockSize");

}

// Saves the debug_settings structure to the specified XML file
void petya_decryptor_settings::save(const std::string &filename)
{
   using boost::property_tree::ptree;
   ptree pt;
   
   pt.put("encryptedDiskSectorFilename", m_file);
   pt.put("startKeyNumber", start_keyNr);   
   pt.put("resumeKeyNumber", resume_keyNr);
   pt.put("nrOfKeysToCalculate", nrOfKeysToCalculate);
   pt.put("gpu_blocks", gpu_blocks);
   pt.put("gpu_threads", gpu_threads);
   pt.put("gpu_keysCtxSwitch", gpu_keysCtxSwitch);
   pt.put("cpu_threads", cpu_threads);
   pt.put("calculatedKeyBlockSize", calculatedKeyBlockSize);

   write_xml(filename, pt);
}
