#pragma once


// wxWidgets "Hello world" Program
// For compilers that support precompilation, includes "wx/wx.h".
#include <wx/wx.h>
#include "wxImagePanel.h"
#include "petya.h"

enum
{
    ID_Hello = 1
};

enum
{
	 ButtonChooseDiskDump = wxID_HIGHEST + 1,
	 ButtonFindGPUParameters = wxID_HIGHEST +2, // declares an id which will be used to call our button
	 ButtonReadFile = wxID_HIGHEST +3,
	 ComboBoxSourceChoice = wxID_HIGHEST +4,
	 ButtonStartCalculation = wxID_HIGHEST +5
};


class MainAppFrame: public wxFrame
{
private:

    char nonce[NONCE_SIZE];
    char veribuf[VERIBUF_SIZE];

    uint64_t nrBlocks;
	uint64_t nrThreads;


	 wxBoxSizer *vbox = new wxBoxSizer(wxVERTICAL); // Main Sizer

	 wxImagePanel *imagePanel = NULL;
	 wxPanel *panel = NULL;
	 wxTextCtrl *tcGpuBlocks;
	 wxTextCtrl *tcGpuThreads;


	 wxComboBox *cbSourceChoice;

	 // Infected Harddisk
	 wxBoxSizer *hboxCreateInfectedDiskChoice;


	 // Disk Dump choice
	 wxBoxSizer *hboxDiskDump;
	 wxTextCtrl *tcFilename;

	 // Nonce Veribuf

	 wxBoxSizer* hboxNonce;
	 wxBoxSizer* hboxVeribuf;

	 wxTextCtrl *tcNonce;
	 wxTextCtrl *tcVerificationBuffer;

	 // GPU Parameters
	 wxBoxSizer *hboxGPUParameterBtn;
	 wxBoxSizer *hboxGPUParameterBlocks;
	 wxBoxSizer *hboxGPUParametersThreads;


public:
	MainAppFrame(const wxString& title, const wxPoint& pos, const wxSize& size);
private:
	void createBanner(wxBoxSizer* vbox);
	void createSourceChoice(wxBoxSizer* vbox);
	void createInfectedDiskChoice(wxBoxSizer * vbox);
	void createDiskDumpChoice(wxBoxSizer* vbox);
	void createNonceVeribufEnterTextChoice(wxBoxSizer* vbox);
	void createGpuParameterChoice(wxBoxSizer *vbox);


	void showHideInfectedDisk(bool isVisible);
	void showHideDiskDump(bool isVisible);
	void showHideNonce(bool isVisible);
	void showHideGpuParameters(bool isVisible);

	void showHideChoices(bool isVisible);

    void OnHello(wxCommandEvent& event);
    void OnExit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);
    void OnComboTabAction(wxKeyEvent& event);
    void OnSize(wxSizeEvent& event);
    void OnOpenDiskDumpFile(wxCommandEvent& WXUNUSED(event));
    void OnFindGPUParameters(wxCommandEvent& WXUNUSED(event));
    void OnComboBoxSourceChanged(wxCommandEvent& event);
    void OnStartCalculation(wxCommandEvent& WXUNUSED(event));
    wxDECLARE_EVENT_TABLE();
};

