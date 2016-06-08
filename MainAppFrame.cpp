/*
 * MainAppFrame.cpp
 *
 *  Created on: 03.06.2016
 *      Author: wolfgangmeyerle
 */

#include "MainAppFrame.h"
#include <iostream>
#include <wx/wx.h>
#include <wx/dc.h>
#include <wx/image.h>
#include "wxImagePanel.h"
#include <wx/wfstream.h>

#include <boost/lexical_cast.hpp>
#include "petya.h"
#include "keyCandidateDistributor.h"
#include <boost/thread.hpp>

// #include "gpu_code.cu"
using namespace std;


void MainAppFrame::createBanner(wxBoxSizer* vbox) {
    // Banner
    wxInitAllImageHandlers();
    wxBoxSizer *hboxBanner = new wxBoxSizer(wxHORIZONTAL);
    imagePanel = new wxImagePanel( this, wxT("Banner.png"), wxBITMAP_TYPE_PNG);
    imagePanel->SetMinSize(wxSize(this->GetSize().GetWidth(),714*this->GetSize().GetWidth()/1418));
    //imagePanel->SetClientSize(GetSize().GetWidth(),200);
    hboxBanner->Add(imagePanel, 1, wxEXPAND , 0);

    vbox->Add(hboxBanner, 0,  wxEXPAND | wxALL, 0);
}

void MainAppFrame::createSourceChoice(wxBoxSizer* vbox) {
    wxBoxSizer *hboxSourceChoice = new wxBoxSizer(wxHORIZONTAL);
    wxString lblIHave = wxT("I have");
    wxStaticText *stIHave = new wxStaticText(panel, wxID_ANY, lblIHave, wxPoint(0,0), wxDefaultSize, wxALIGN_RIGHT);
    hboxSourceChoice->Add(stIHave, 0, wxLEFT | wxTOP, 3);
    hboxSourceChoice->AddSpacer(10);

    wxArrayString arIHave;
    arIHave.Add(wxT("connected a Petya Mischa infected harddrive to this Computer (not implemented yet)"));
    arIHave.Add(wxT("a disk dump file of an infected harddisk (first 56 sectors are enough)"));
    arIHave.Add(wxT("a nonce and the verification number as hex bytes (not implemented yet)"));
    arIHave.Add(wxT("nothing, of above, I'd like to generate an USB Stick to generate the disk dump (not implemented yet)"));

    cbSourceChoice = new wxComboBox(panel, ComboBoxSourceChoice, _T(""), wxPoint(0,0), wxDefaultSize,
    		arIHave,  wxTE_PROCESS_TAB  |  wxCB_DROPDOWN | wxCB_READONLY);

    hboxSourceChoice->Add(cbSourceChoice, 1,  wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 0);

    vbox->Add(hboxSourceChoice, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
}

void MainAppFrame::createInfectedDiskChoice(wxBoxSizer * vbox) {
    // Infected Disk choice...

	wxStaticText *stChooseDrive;
	wxComboBox* cbChooseDrive;
	wxButton *btnChooseDrive;

    hboxCreateInfectedDiskChoice = new wxBoxSizer(wxHORIZONTAL);

    wxString  lblChooseDrive = wxT("Choose your infected Harddisk");
    stChooseDrive = new wxStaticText(panel, wxID_ANY, lblChooseDrive,
         wxPoint(0, 0), wxDefaultSize, wxALIGN_RIGHT);

    hboxCreateInfectedDiskChoice->Add(stChooseDrive, 0, wxLEFT | wxTOP, 3);

    hboxCreateInfectedDiskChoice->AddSpacer(10);

    wxArrayString strings;
    strings.Add(wxT("1"));
    strings.Add(wxT("2"));
    strings.Add(wxT("3"));
    strings.Add(wxT("4"));

    cbChooseDrive = new wxComboBox(panel, wxID_ANY, _T(""), wxPoint(0, 0), wxDefaultSize,
        strings,  wxTE_PROCESS_TAB  |  wxCB_DROPDOWN | wxCB_READONLY | wxCB_SORT);
    //box->GetEventHandler()->Connect(wxEVT_KEY_DOWN, wxKeyEventHandler(MainAppFrame::OnComboTabAction));


    // Choose Drive line...
    hboxCreateInfectedDiskChoice->Add(cbChooseDrive, 1,  wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 0);

    btnChooseDrive = new wxButton(panel, wxID_ANY, _T("Display Information"), wxPoint(0, 2), wxDefaultSize, 0, wxDefaultValidator, _T("btnDisplayInformation") );
    hboxCreateInfectedDiskChoice->Add(btnChooseDrive, 0, wxALIGN_RIGHT | wxTOP, 1);
    vbox->Add(hboxCreateInfectedDiskChoice, 0,  wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);

}

void MainAppFrame::createDiskDumpChoice(wxBoxSizer* vbox) {
    // Choose Disk Dump

    wxStaticText *stChooseDiskDump;
    wxButton *btnChooseFile;

    hboxDiskDump = new wxBoxSizer(wxHORIZONTAL);


    wxString  lblChooseDiskDump = wxT("Choose disk dump of harddisk");
    stChooseDiskDump = new wxStaticText(panel, wxID_ANY, lblChooseDiskDump,
    		wxPoint(0,0), wxSize(200,20), wxALIGN_RIGHT  );

    hboxDiskDump->Add(stChooseDiskDump, 0);

    hboxDiskDump->AddSpacer(10);

    tcFilename = new wxTextCtrl(panel, wxID_ANY, wxEmptyString, wxDefaultPosition,
    		wxDefaultSize, 0, wxDefaultValidator, wxTextCtrlNameStr );

    hboxDiskDump->Add(tcFilename, 1);


    hboxDiskDump->AddSpacer(10);

    btnChooseFile = new wxButton(panel, ButtonChooseDiskDump, _T("..."), wxPoint(0, 2), wxDefaultSize, 0, wxDefaultValidator, _T("btnChooseFile") );
    hboxDiskDump->Add(btnChooseFile, 0,  wxTOP| wxLEFT | wxRIGHT, 0);

    vbox->Add(hboxDiskDump, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
}

void MainAppFrame::createNonceVeribufEnterTextChoice(wxBoxSizer* vbox) {
    // Choose Nonce line...

	wxStaticText *stNonce;
	wxTextCtrl *tcNonce;
	wxStaticText *stVerificationBuffer;
	wxTextCtrl *tcVerificationBuffer;


    hboxNonce = new wxBoxSizer(wxHORIZONTAL);

    wxString lblNonce = wxT("Nonce");
    stNonce = new wxStaticText(panel, wxID_ANY, lblNonce, wxPoint(0,0), wxSize(200,20), wxALIGN_RIGHT  );
    hboxNonce->Add(stNonce, 0);

    hboxNonce->AddSpacer(10);


    tcNonce = new wxTextCtrl(panel, wxID_ANY, _T(""), wxDefaultPosition, wxSize(10,20), 0, wxDefaultValidator, wxTextCtrlNameStr );
    hboxNonce->Add(tcNonce, 1);

    vbox->Add(hboxNonce, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);


    // Verification Buffer line...
    hboxVeribuf = new wxBoxSizer(wxHORIZONTAL);
    wxString lblVerificationBuffer = wxT("Verification Buffer");
    stVerificationBuffer = new wxStaticText(panel, wxID_ANY, lblVerificationBuffer, wxPoint(0,0), wxSize(200,20), wxALIGN_RIGHT);
    hboxVeribuf->Add(stVerificationBuffer, 0);

    hboxVeribuf->AddSpacer(10);

    tcVerificationBuffer = new wxTextCtrl(panel, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0, wxDefaultValidator, wxTextCtrlNameStr );
    hboxVeribuf->Add(tcVerificationBuffer, 1);
    vbox->Add(hboxVeribuf, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);

}

void MainAppFrame::createGpuParameterChoice(wxBoxSizer *vbox) {
    // Find GPU Parameters...
    hboxGPUParameterBtn = new wxBoxSizer(wxHORIZONTAL);
    hboxGPUParameterBlocks = new wxBoxSizer(wxHORIZONTAL);
    hboxGPUParametersThreads = new wxBoxSizer(wxHORIZONTAL);

    wxStaticText *stEmpty3GPU = new wxStaticText(panel, wxID_ANY, _T(""), wxPoint(0,0),  wxSize(210,20), wxALIGN_RIGHT  );
    hboxGPUParameterBtn->Add(stEmpty3GPU, 0);

    wxButton *btnFindGPUParameters = new wxButton(panel, ButtonFindGPUParameters, _T("Find optimal GPU Parameters"), wxPoint(0, 2), wxSize(200,20), 0, wxDefaultValidator, _T("btnFindGPUParameters") );
    hboxGPUParameterBtn->Add(btnFindGPUParameters, wxEXPAND);
    vbox->Add(hboxGPUParameterBtn, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);


    // GPU Blocks line...
    wxString lblGPUBlocks = wxT("Nr of GPU Blocks");
    wxStaticText *stGPUBlocks = new wxStaticText(panel, wxID_ANY, lblGPUBlocks, wxPoint(0,0), wxSize(200,20), wxALIGN_RIGHT);
    hboxGPUParameterBlocks->Add(stGPUBlocks, 0);

    hboxGPUParameterBlocks->AddSpacer(10);

    tcGpuBlocks = new wxTextCtrl(panel, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0, wxDefaultValidator, wxTextCtrlNameStr );
    hboxGPUParameterBlocks->Add(tcGpuBlocks, 1);
    vbox->Add(hboxGPUParameterBlocks, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);


    // GPU Threads line...
    wxString lblGPUThreads = wxT("Nr of GPU Threads");
    wxStaticText *stGPUThreads = new wxStaticText(panel, wxID_ANY, lblGPUThreads, wxPoint(0,0), wxSize(200,20), wxALIGN_RIGHT);
    hboxGPUParametersThreads->Add(stGPUThreads, 0);

    hboxGPUParametersThreads->AddSpacer(10);


    tcGpuThreads = new wxTextCtrl(panel, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0, wxDefaultValidator, wxTextCtrlNameStr );
    hboxGPUParametersThreads->Add(tcGpuThreads, 1);

    vbox->Add(hboxGPUParametersThreads, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
}

MainAppFrame::MainAppFrame(const wxString& title, const wxPoint& pos, const wxSize& size)
        : wxFrame(NULL, wxID_ANY, title, pos, size)
{
	imagePanel = NULL;

    wxMenu *menuFile = new wxMenu;
    menuFile->Append(ID_Hello, "&Hello...\tCtrl-H",
                     "Help string shown in status bar for this menu item");
    menuFile->AppendSeparator();
    menuFile->Append(wxID_EXIT);
    wxMenu *menuHelp = new wxMenu;
    menuHelp->Append(wxID_ABOUT);
    wxMenuBar *menuBar = new wxMenuBar;
    menuBar->Append( menuFile, "&File" );
    menuBar->Append( menuHelp, "&Help" );


    this->SetBackgroundColour(wxColour(* wxBLACK));

    panel = new wxPanel(this, wxID_ANY);
    // panel->SetMinSize(wxSize(300,900));
    panel->SetBackgroundColour(wxColour(* wxWHITE));



    wxString lblEmpty = wxT(" ");


    createBanner(vbox);
    createSourceChoice(vbox);
    createInfectedDiskChoice(vbox);
    createDiskDumpChoice(vbox);
    createNonceVeribufEnterTextChoice(vbox);
    createGpuParameterChoice(vbox);


    // Add Empty row line
    vbox->AddSpacer(10);


    // Search Key...
    wxBoxSizer *hbox7 = new wxBoxSizer(wxHORIZONTAL);
    wxButton *btnStartKeySearch = new wxButton(panel, ButtonStartCalculation, _T("start key search"), wxPoint(0, 2), wxSize(200,20), 0, wxDefaultValidator, _T("btnStartKeySearch") );
    hbox7->Add(btnStartKeySearch, wxEXPAND);
    vbox->Add(hbox7, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);


    // panel->SetSizer(vbox);
    panel->SetSizerAndFit(vbox);

    wxCommandEvent evt = wxCommandEvent(wxEVT_NULL);
    this->OnComboBoxSourceChanged(evt);


    SetMenuBar( menuBar );
    CreateStatusBar();
    SetStatusText( "Choose your harddrive..." );
    Centre();

	this->Fit();
}

void MainAppFrame::OnSize(wxSizeEvent& event)
{
    //wxSize ssize = GetSize();
//	GetSize();
	cout << "Size changed " << GetSize().GetWidth()<< " " << GetSize().GetHeight() << endl;

	panel->SetMinSize(wxSize(GetSize().GetWidth(), GetSize().GetHeight()));
	panel->Fit();

	// imagePanel->OnSize(event);
	/*
	wxSize size = GetSize();
    int pictureSizeX = size.GetWidth();
    int pictureSizeY = size.GetWidth()*157/ 300;


    imagePanel = new wxImagePanel( frame, wxT("banner.png"), wxBITMAP_TYPE_PNG);
           sizer->Add(drawPane, 1, wxEXPAND);
	*/

}

void MainAppFrame::OnOpenDiskDumpFile(wxCommandEvent& WXUNUSED(event))
{
	/*
    if (...current content has not been saved...)
    {
        if (wxMessageBox(_("Current content has not been saved! Proceed?"), _("Please confirm"),
                         wxICON_QUESTION | wxYES_NO, this) == wxNO )
            return;
        //else: proceed asking to the user the new file to open
    }
	*/

    wxFileDialog
        openFileDialog(this, _("Open Harddisk dump file"), "", "",
                       "bin files (*.bin)|*.bin", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
    if (openFileDialog.ShowModal() == wxID_CANCEL)
        return;     // the user changed idea...

    // proceed loading the file chosen by the user;
    // this can be done with e.g. wxWidgets input streams:
    wxFileInputStream input_stream(openFileDialog.GetPath());
    if (!input_stream.IsOk())
    {
        wxLogError("Cannot open file '%s'.", openFileDialog.GetPath());
        return;
    }


    bool nonceSet = false;
    bool veribufSet = false;

//     cout << "Reading Data"<<endl;
    if (input_stream.CanRead())
    {
    	size_t bytesRead = 0;
    	uint64_t sectorNr = 0;
    	do {
			char buffer[SECTOR_SIZE];
			input_stream.Read(buffer, SECTOR_SIZE);
			bytesRead = input_stream.LastRead();

			if (sectorNr == ONION_SECTOR_NUM) {
				for (int i= 0; i< NONCE_SIZE;i++) {
					nonce[i] = buffer[NONCE_OFFSET+i];
				}


				std::stringstream stream;

				for (int i=0; i<NONCE_SIZE;i++) {
					stream << std::hex << (((int)nonce[i])&0xFF) << " ";
				}

				std::string nonceStr( stream.str() );
				//tcNonce->SetValue(wxString(nonceStr));
				nonceSet = true;

			}

			if (sectorNr == VERIBUF_SECTOR_NUM) {
				for (int i=0; i<VERIBUF_SIZE; i++) {
					veribuf[i] = buffer[i];
				}


				std::stringstream stream;

				for (int i=0; i<VERIBUF_SIZE;i++) {
					stream << std::hex << (((int)veribuf[i])&0xFF) << " ";
				}

				std::string veribufStr( stream.str() );
				//tcVerificationBuffer->SetValue(wxString(veribufStr));
				veribufSet = true;

			}

			sectorNr++;



    	} while (input_stream.CanRead() && bytesRead>0 && !(nonceSet && veribufSet));


    	if (nonceSet && veribufSet) {
    		tcFilename->SetValue(openFileDialog.GetPath());
    	}


    }
}

void MainAppFrame::OnFindGPUParameters(wxCommandEvent& WXUNUSED(event)) {
	uint64_t nrOfBlocks;
	uint64_t nrOfThreads;

	cout << "Finding GPU Parameters" << endl;
	queryDeviceInfo(&nrOfBlocks, &nrOfThreads);


	tcGpuBlocks->SetValue(wxString(boost::lexical_cast<std::string>(nrOfBlocks)));
	tcGpuThreads->SetValue(wxString(boost::lexical_cast<std::string>(nrOfThreads)));

}


void MainAppFrame::showHideInfectedDisk(bool isVisible) {
	 // Infected Harddisk

	 hboxCreateInfectedDiskChoice->Show(isVisible);
}

void MainAppFrame::showHideDiskDump(bool isVisible) {
	 // Disk Dump choice
	 hboxDiskDump->Show(isVisible);
}

void MainAppFrame::showHideNonce(bool isVisible) {
	 // Nonce Veribuf
	 hboxNonce->Show(isVisible);
	 hboxVeribuf->Show(isVisible);
}

void MainAppFrame::showHideGpuParameters(bool isVisible) {
	 hboxGPUParameterBtn->Show(isVisible);
	 hboxGPUParameterBlocks->Show(isVisible);
	 hboxGPUParametersThreads->Show(isVisible);
}

void MainAppFrame::showHideChoices(bool isVisible) {
	showHideInfectedDisk(isVisible);
	showHideDiskDump(isVisible);
	showHideNonce(isVisible);
	showHideGpuParameters(isVisible);
}



void MainAppFrame::OnComboBoxSourceChanged(wxCommandEvent& event) {


	int selectedIdx = cbSourceChoice->GetSelection();
	switch (selectedIdx) {
		case wxNOT_FOUND: break;
		case 0: // Infected Harddisk drive
				showHideChoices(false);
			    showHideInfectedDisk(true);
			    break;
		case 1: // Disk dump
				showHideChoices(false);
				showHideDiskDump(true);
				break;

		case 2: // Nonce and Veribuf manually
				showHideChoices(false);
				showHideNonce(true);
				break;

		default: break;
	}


	vbox->Layout();
	panel->Fit();

	/*
    this->Fit();
	this->Layout();
	this->Refresh();
	*/
	//Layout();
}

void MainAppFrame::calculationThread(GPUMultiShotArguments args) {
	shutdownRequested = false;
	tryKeysGPUMultiShot(args);
}

void MainAppFrame::OnStartCalculation(wxCommandEvent& WXUNUSED(event)) {
	// Find GPU Parameters...
	queryDeviceInfo(&nrBlocks, &nrThreads);

	uint64_t ctxSwitchKeys = 10000;

	unsigned int nrKeys = nrThreads*nrBlocks;

	char *keys = (char *) malloc(nrKeys*sizeof(char)*KEY_SIZE);

	uint64_t startKey = 0;

	uint64_t totalKeyRange = 2 * 26 + 10;

	for (int i = 0; i < 7; i++) {
		totalKeyRange *= 2 * 26 + 10;
	}

	uint64_t nrOfKeysToCalculate = totalKeyRange;


	uint64_t currentKeyIndex = startKey;
	char *currentKey = keys;

	uint64_t blockSize = (nrOfKeysToCalculate / (uint64_t) nrKeys)+1;

	for (int i=0; i<nrKeys; i++) {
		calculate16ByteKeyFromIndex(currentKeyIndex, currentKey);
		currentKey+=KEY_SIZE;
		currentKeyIndex += blockSize;
	}


	GPUMultiShotArguments argument;
	argument.nrBlocks = nrBlocks;
	argument.nrThreads = nrThreads;
	memcpy(argument.nonce_hc, nonce, NONCE_SIZE);
	argument.verificationBuffer = veribuf;
	argument.keys = keys;
	argument.nrKeys = nrKeys;
	argument.keysBeforeContextSwitch = ctxSwitchKeys;
	argument.keysInTotalToCalculate = nrOfKeysToCalculate;
	argument.supressOutput = false;
	argument.shutdownRequested = &shutdownRequested;

	boost::thread(&MainAppFrame::calculationThread, this, argument);

	//  boost::thread(&MainAppFrame::calculationThread, argument);
}



void MainAppFrame::OnComboTabAction(wxKeyEvent& event)
{
   if (event.GetKeyCode() == WXK_TAB)
      Navigate(wxNavigationKeyEvent::IsForward);
   else
      event.Skip();
}

void MainAppFrame::OnExit(wxCommandEvent& event)
{
    Close( true );
}
void MainAppFrame::OnAbout(wxCommandEvent& event)
{
    wxMessageBox( "This is a wxWidgets' Hello world sample",
                  "About Hello World", wxOK | wxICON_INFORMATION );
}
void MainAppFrame::OnHello(wxCommandEvent& event)
{
    wxLogMessage("Hello world from wxWidgets!");
}

